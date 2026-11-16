package compiler

import (
	"fmt"
	"strings"

	"github.com/stevejboyle/hobby-ngfw/internal/config"
)

// TLS decryption in the data path.
//
// A new TCP connection that a decryption rule decrypts is handed to tlsd
// (nftables tproxy, in chain decrypt at prerouting). tlsd reads the
// client's TLS hello and then sends the connection's bytes, decrypted or
// not, through the cleartext loop: out of a network namespace, in on
// LoopClientIf, through the forward chain like routed traffic (the
// security rules, App Identification and the IPS all apply), out on
// LoopServerIf into a second namespace, where tlsd picks it up again and
// talks to the real server. The loop leg keeps the client's and server's
// addresses and ports; its own conntrack zone (LoopCTZone) keeps it apart
// from the client's original connection. tlsd marks the loop leg's DSCP
// with the client's ingress zone (ZoneDSCP), so rules can still match the
// zone it came from; its destination zone is the route to the server
// (fib daddr oifname).
const (
	LoopClientIf = "sjbd-c" // the loop's entry into the firewall (client half)
	LoopServerIf = "sjbd-s" // the loop's exit (server half)
	LoopCTZone   = 0xfff0

	// DecryptMark marks a connection handed to tlsd. Its low byte is the
	// decryption rule's position + 1, bits 8-13 the ingress zone's DSCP
	// code (ZoneDSCP). tlsd reads it from the accepted socket (the kernel
	// copies the SYN's mark: net.ipv4.tcp_fwmark_accept). Policy routing
	// (fwmark DecryptMark) delivers marked packets locally.
	DecryptMark      = 0x40000000
	DecryptRuleMask  = 0x000000ff
	DecryptZoneShift = 8
	DecryptZoneMask  = 0x00003f00

	// DecryptPort is where tlsd listens for handed-over connections.
	DecryptPort = 15080

	// DecryptReadySet holds 0.0.0.0/0 while tlsd is up and nothing while it
	// isn't, so connections are handed over only when tlsd can take them
	// (fail open). ngfwd fills it after each ruleset load and keeps it in
	// step with tlsd's health, without a commit.
	DecryptReadySet = "decrypt_ready"

	// MaxDecryptRules: the rule position + 1 fits the mark's low byte.
	MaxDecryptRules = 254
	// MaxDSCPZones: zone codes are DSCP values 1-63.
	MaxDSCPZones = 63
)

// ZoneDSCP is the DSCP code tlsd puts on loop traffic from a zone: its
// position in the config's zone list + 1 (0: unknown).
func ZoneDSCP(cfg *config.Config, zone string) int {
	for i, z := range cfg.Zones {
		if z.Name == zone {
			if i+1 > MaxDSCPZones {
				return 0
			}
			return i + 1
		}
	}
	return 0
}

// decryptOn: the ruleset carries decryption (some rule decrypts and
// decryption is on).
func (c *compiler) decryptOn() bool { return c.cfg.DecryptionActive() }

// loopZones returns the loop-traffic forms of a rule's zone matches: the
// ingress zones by DSCP on LoopClientIf, the egress zones by the route to
// the destination. ok is false when they can't match loop traffic (no
// zone codes).
func (c *compiler) loopZones(from, to []string) (in, out string, ok bool) {
	in = fmt.Sprintf("iifname %q", LoopClientIf)
	if !isAny(from) {
		var codes []string
		for _, z := range from {
			if code := ZoneDSCP(c.cfg, z); code > 0 && len(c.zoneIfaces[z]) > 0 {
				codes = appendUnique(codes, fmt.Sprintf("%d", code))
			}
		}
		if len(codes) == 0 {
			return "", "", false
		}
		in += " ip dscp " + set(codes)
	}
	out = fmt.Sprintf("oifname %q", LoopServerIf)
	if !isAny(to) {
		var ifs []string
		for _, z := range to {
			for _, i := range c.zoneIfaces[z] {
				ifs = appendUnique(ifs, fmt.Sprintf("%q", i))
			}
		}
		if len(ifs) == 0 {
			return "", "", false
		}
		out += " fib daddr oifname " + set(ifs)
	}
	return in, out, true
}

// decrypt writes the prerouting chains that hand connections to tlsd.
func (c *compiler) decrypt(b *strings.Builder) error {
	if !c.decryptOn() {
		return nil
	}
	if n := len(c.cfg.DecryptionRules); n > MaxDecryptRules {
		return fmt.Errorf("at most %d decryption rules (this config has %d)", MaxDecryptRules, n)
	}
	fmt.Fprintf(b, "\n\tset %s {\n\t\ttype ipv4_addr\n\t\tflags interval\n\t\tcomment \"tlsd is up\"\n\t}\n", DecryptReadySet)

	b.WriteString("\n\tchain decrypt_zone {\n")
	b.WriteString("\t\ttype filter hook prerouting priority raw; policy accept;\n")
	fmt.Fprintf(b, "\t\tiifname { %q, %q } ct zone set %d comment \"decryption loop\"\n", LoopClientIf, LoopServerIf, LoopCTZone)
	b.WriteString("\t}\n")

	b.WriteString("\n\tchain decrypt {\n")
	b.WriteString("\t\ttype filter hook prerouting priority mangle; policy accept;\n")
	// The loop first: its packets carry the client's addresses and ports,
	// so they would match tlsd's own client socket below.
	fmt.Fprintf(b, "\t\tiifname { %q, %q } accept\n", LoopClientIf, LoopServerIf)
	b.WriteString("\t\t# Packets of connections tlsd already holds go to its socket.\n")
	fmt.Fprintf(b, "\t\tmeta l4proto tcp socket transparent 1 meta mark set meta mark or 0x%x accept\n", DecryptMark)
	for i, r := range c.cfg.DecryptionRules {
		ins := c.decryptIngress(r.From)
		to, ok := c.zoneExpr("fib daddr oifname", r.To)
		if len(ins) == 0 || !ok {
			c.res.Warnings = append(c.res.Warnings, fmt.Sprintf("decryption rule %q skipped: a zone it uses has no interfaces", r.Name))
			fmt.Fprintf(b, "\t\t# decryption rule %q skipped: zone without interfaces\n", r.Name)
			continue
		}
		prof, _ := c.cfg.DecryptionProfile(r.ProfileOf())
		ports := set(c.decryptPorts(r.Service))
		comment := fmt.Sprintf("comment \"decrypt:%s\"", r.Name)
		for _, in := range ins {
			for _, src := range c.addrTerms(r.Source) {
				for _, dst := range c.addrTerms(r.Destination) {
					m := []string{fmt.Sprintf("iifname %q", in.name)}
					if to != "" {
						m = append(m, to)
					}
					if src != nil {
						m = append(m, src.expr("saddr"))
					}
					if dst != nil {
						m = append(m, dst.expr("daddr"))
					}
					match := strings.Join(m, " ")
					tcp := match + " tcp dport " + ports
					quic := match + " udp dport 443"
					if r.Action == config.NoDecryptAction {
						fmt.Fprintf(b, "\t\t%s accept %s\n", tcp, comment)
						fmt.Fprintf(b, "\t\t%s accept %s\n", quic, comment)
						continue
					}
					if !prof.AllowQUIC {
						fmt.Fprintf(b, "\t\t%s counter drop comment \"decrypt:%s quic\"\n", quic, r.Name)
					}
					mark := DecryptMark | in.zone<<DecryptZoneShift | (i + 1)
					fmt.Fprintf(b, "\t\t%s tcp flags & (syn | ack) == syn ip daddr @%s counter meta mark set 0x%x tproxy ip to :%d %s\n",
						tcp, DecryptReadySet, mark, DecryptPort, comment)
				}
			}
		}
	}
	b.WriteString("\t}\n")
	return nil
}

type decryptIn struct {
	name string
	zone int // DSCP code of its zone
}

// decryptIngress lists the interfaces of zones (any: every zoned interface)
// with their zone codes. Decryption covers default-VRF interfaces only
// (validation enforces it).
func (c *compiler) decryptIngress(zones []string) []decryptIn {
	var out []decryptIn
	for _, in := range c.cfg.Interfaces {
		if in.Zone == "" || c.inVRF[in.Name] {
			continue
		}
		if !isAny(zones) && !contains(zones, in.Zone) {
			continue
		}
		out = append(out, decryptIn{name: in.Name, zone: ZoneDSCP(c.cfg, in.Zone)})
	}
	return out
}

// decryptPorts are the TCP ports of a decryption rule's services (any: 443).
func (c *compiler) decryptPorts(names []string) []string {
	if isAny(names) {
		return []string{"443"}
	}
	var ports []string
	for _, t := range c.svcTerms(names) {
		if t != nil && t.proto == "tcp" {
			for _, p := range t.ports {
				ports = appendUnique(ports, p)
			}
		}
	}
	if len(ports) == 0 {
		return []string{"443"}
	}
	return ports
}
