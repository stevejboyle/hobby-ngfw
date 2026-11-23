package compiler

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/stevejboyle/sjb-os/internal/config"
)

// NAT in the data path.
//
// Published servers (port-forward and static entries) are translated in
// chain prerouting_nat. The kernel applies NAT at its own fixed point in
// prerouting (dstnat, -100; a NAT chain's priority only orders it among
// NAT chains), so chain decrypt's tproxy runs after it (DecryptPriority).
// Everything after translation, decryption, the security rules, App
// Identification and the IPS, sees the server's inside address and port,
// and rules name that address. iifname matches interfaces in a VRF too: at
// prerouting the packet is still on its own interface.
//
// Hairpin NAT (on unless an entry sets hairpin off): clients on SJB-OS's
// other zoned interfaces in the published interface's VRF (the server's:
// conntrack zones follow VRFs) reach the server by its public address too,
// with the same translation, so rules still name the server's inside
// address and judge the connection from the client's zone. Port forwards
// on the interface's own address match that address: the configured one,
// or the set IfAddrSet(iface) that ngfwd fills with the live address
// (DHCP, deployment settings). A client on the server's own network would
// get the server's replies straight from it, bypassing the firewall, so
// that one case is masqueraded to SJB-OS's address on that network
// (postrouting, ahead of every other source NAT).
//
// Source NAT runs in chain postrouting: hairpin first, then bidirectional
// static entries (a published server's own outbound traffic leaves from
// its public address), then the masquerade entries in list order.
const DNATPriority = "dstnat"

// IfAddrSet names the set holding an interface's live addresses.
func IfAddrSet(iface string) string { return "ifaddr_" + unsafe.ReplaceAllString(iface, "_") }

func (c *compiler) natChains(b *strings.Builder) {
	var dnat, hairSNAT, snat, masq []string
	for _, n := range c.cfg.NAT {
		switch {
		case n.Type == config.NATMasquerade:
			masq = append(masq, c.masquerade(n)...)
		case n.Published():
			d, s := c.published(n)
			dnat = append(dnat, d...)
			snat = append(snat, s...)
			if n.HairpinOn() {
				hd, hs := c.hairpin(n)
				dnat = append(dnat, hd...)
				for _, l := range hs {
					hairSNAT = appendUnique(hairSNAT, l)
				}
			}
		}
	}
	snat = append(hairSNAT, snat...)
	for _, iface := range sortedKeys(c.res.IfAddrSets) {
		fmt.Fprintf(b, "\n\tset %s {\n\t\ttype ipv4_addr\n\t\tcomment \"addresses of %s (hairpin NAT)\"\n\t}\n", c.res.IfAddrSets[iface], iface)
	}
	if len(dnat) > 0 {
		b.WriteString("\n\tchain prerouting_nat {\n")
		fmt.Fprintf(b, "\t\ttype nat hook prerouting priority %s; policy accept;\n", DNATPriority)
		for _, l := range dnat {
			b.WriteString("\t\t" + l + "\n")
		}
		b.WriteString("\t}\n")
	}
	if len(snat)+len(masq) > 0 {
		b.WriteString("\n\tchain postrouting {\n")
		b.WriteString("\t\ttype nat hook postrouting priority srcnat; policy accept;\n")
		for _, l := range append(snat, masq...) {
			b.WriteString("\t\t" + l + "\n")
		}
		b.WriteString("\t}\n")
	}
}

func (c *compiler) masquerade(n config.NATRule) []string {
	froms := c.ingress(n.From, true)
	to, ok2 := c.zoneExpr("oifname", n.To)
	if len(froms) == 0 || !ok2 {
		c.res.Warnings = append(c.res.Warnings,
			fmt.Sprintf("nat %q skipped: a zone it uses has no interfaces", n.Name))
		return []string{fmt.Sprintf("# nat %q skipped: zone without interfaces", n.Name)}
	}
	var lines []string
	for _, from := range froms {
		for _, src := range c.addrTerms(n.Source) {
			parts := []string{}
			for _, p := range []string{from, to} {
				if p != "" {
					parts = append(parts, p)
				}
			}
			if src != nil {
				parts = append(parts, src.expr("saddr"))
			}
			parts = append(parts, "counter masquerade", fmt.Sprintf("comment \"nat:%s\"", n.Name))
			lines = append(lines, strings.Join(parts, " "))
		}
	}
	return lines
}

// published compiles a port-forward or static entry: its prerouting
// (destination NAT) lines and, for bidirectional static NAT, its
// postrouting (source NAT) line.
func (c *compiler) published(n config.NATRule) (dnat, snat []string) {
	server, _ := c.cfg.HostAddress(n.Server)
	public, hasPublic := c.cfg.HostAddress(n.PublicAddress)
	comment := fmt.Sprintf("comment \"nat:%s\"", n.Name)
	parts := []string{fmt.Sprintf("iifname %q", n.Interface)}
	if hasPublic {
		parts = append(parts, "ip daddr "+public.String())
	} else {
		// The interface's own address, whatever it is (DHCP included):
		// any local address except the public addresses other entries
		// publish on this interface, which SJB-OS also holds.
		parts = append(parts, "fib daddr type local")
		if others := c.publicIPs(n.Interface); len(others) > 0 {
			parts = append(parts, "ip daddr != "+set(others))
		}
	}

	if n.Type == config.NATStatic {
		dnat = append(dnat, strings.Join(append(parts, "counter dnat ip to "+server.String(), comment), " "))
		if n.BidirectionalOn() {
			snat = append(snat, fmt.Sprintf("oifname %q ip saddr %s counter snat ip to %s %s", n.Interface, server, public, comment))
		}
		c.checkAllowed(n, server, "", 0)
		return dnat, snat
	}

	lo, hi, _ := config.PortRange(n.PublicPort)
	slo, _, _ := n.ServerPorts()
	parts = append(parts, fmt.Sprintf("%s dport %s", n.Protocol, portExpr(lo, hi)))
	to := server.String()
	if lo == hi {
		to += ":" + strconv.Itoa(slo)
	}
	dnat = append(dnat, strings.Join(append(parts, "counter dnat ip to "+to, comment), " "))
	c.checkAllowed(n, server, n.Protocol, slo)
	return dnat, nil
}

// hairpin compiles the extra lines that let SJB-OS's other interfaces
// reach a published server by its public address (see DNATPriority).
func (c *compiler) hairpin(n config.NATRule) (dnat, snat []string) {
	server, _ := c.cfg.HostAddress(n.Server)
	vrf := ""
	var ifaces []string
	for _, in := range c.cfg.Interfaces {
		if in.Name == n.Interface {
			vrf = in.VRFOf()
		}
	}
	srvIf, srvNet := "", netip.Prefix{}
	for _, in := range c.cfg.Interfaces {
		if in.Zone == "" || in.Name == c.cfg.System.MgmtInterface || in.Name == n.Interface || in.VRFOf() != vrf {
			continue
		}
		ifaces = append(ifaces, fmt.Sprintf("%q", in.Name))
		if p, err := netip.ParsePrefix(in.Address); err == nil && p.Masked().Contains(server) {
			srvIf, srvNet = in.Name, p.Masked()
		}
	}
	if len(ifaces) == 0 {
		return nil, nil
	}
	comment := fmt.Sprintf("comment \"nat:%s hairpin\"", n.Name)
	parts := []string{"iifname " + set(ifaces)}
	switch public, ok := c.cfg.HostAddress(n.PublicAddress); {
	case ok:
		parts = append(parts, "ip daddr "+public.String())
	case c.ifaceAddr(n.Interface).IsValid():
		parts = append(parts, "ip daddr "+c.ifaceAddr(n.Interface).String())
	default:
		name := IfAddrSet(n.Interface)
		c.res.IfAddrSets[n.Interface] = name
		parts = append(parts, "ip daddr @"+name)
	}
	to := server.String()
	if n.Type == config.NATPortForward {
		lo, hi, _ := config.PortRange(n.PublicPort)
		slo, _, _ := n.ServerPorts()
		parts = append(parts, fmt.Sprintf("%s dport %s", n.Protocol, portExpr(lo, hi)))
		if lo == hi {
			to += ":" + strconv.Itoa(slo)
		}
	}
	dnat = append(dnat, strings.Join(append(parts, "counter dnat ip to "+to, comment), " "))
	if srvIf != "" {
		// No ct status dnat: tlsd's server leg (a new connection in the
		// cleartext loop's zone, with the client's address) needs it too.
		// Nothing else is forwarded from a network back into it.
		snat = append(snat, fmt.Sprintf("oifname %q ip saddr %s ip daddr %s counter masquerade comment \"nat:hairpin %s\"", srvIf, srvNet, server, server))
	}
	return dnat, snat
}

// ifaceAddr is an interface's configured address (invalid if none).
func (c *compiler) ifaceAddr(iface string) netip.Addr {
	for _, in := range c.cfg.Interfaces {
		if in.Name == iface {
			if p, err := netip.ParsePrefix(in.Address); err == nil {
				return p.Addr()
			}
		}
	}
	return netip.Addr{}
}

// publicIPs lists the public addresses published entries put on iface.
func (c *compiler) publicIPs(iface string) []string {
	var out []string
	for _, n := range c.cfg.NAT {
		if n.Published() && n.Interface == iface {
			if ip, ok := c.cfg.HostAddress(n.PublicAddress); ok {
				out = appendUnique(out, ip.String())
			}
		}
	}
	return out
}

func portExpr(lo, hi int) string {
	if lo == hi {
		return strconv.Itoa(lo)
	}
	return fmt.Sprintf("%d-%d", lo, hi)
}

// checkAllowed warns when no allow rule lets published traffic reach the
// server: NAT only translates, the security rules still decide. Rules see
// the translated connection (the server's inside address and port, its
// zone). It errs towards silence: tag groups and unknown zones count as a
// possible match. proto "" (static NAT) accepts any service.
func (c *compiler) checkAllowed(n config.NATRule, server netip.Addr, proto string, port int) {
	from := ""
	for _, in := range c.cfg.Interfaces {
		if in.Name == n.Interface {
			from = in.Zone
		}
	}
	to := ""
	for _, in := range c.cfg.Interfaces {
		if p, err := netip.ParsePrefix(in.Address); err == nil && in.Zone != "" && p.Masked().Contains(server) {
			to = in.Zone
		}
	}
	for _, r := range c.cfg.Rules {
		if r.Action != "allow" {
			continue
		}
		if !isAny(r.From) && !contains(r.From, from) {
			continue
		}
		if to != "" && !isAny(r.To) && !contains(r.To, to) {
			continue
		}
		if !c.namesHost(r.Destination, server) || !c.servicePort(r.Service, proto, port) {
			continue
		}
		return
	}
	what := "any port"
	if proto != "" {
		what = fmt.Sprintf("%s port %d", proto, port)
	}
	where := ""
	if to != "" {
		where = fmt.Sprintf(" in zone %q", to)
	}
	c.res.Warnings = append(c.res.Warnings, fmt.Sprintf(
		"nat %q: no allow rule lets traffic from zone %q reach server %s (%s)%s on %s; NAT only translates, so add an allow rule naming the server's inside address",
		n.Name, from, n.Server, server, where, what))
}

// namesHost reports whether a rule's address list could match ip.
func (c *compiler) namesHost(names []string, ip netip.Addr) bool {
	if isAny(names) {
		return true
	}
	in := func(name string) bool {
		p, ok := c.addrs[name]
		if !ok {
			return false
		}
		pfx, err := netip.ParsePrefix(p)
		if err != nil {
			a, err := netip.ParseAddr(p)
			return err == nil && a == ip
		}
		return pfx.Contains(ip)
	}
	for _, n := range names {
		if in(n) {
			return true
		}
		if g, ok := c.groups[n]; ok {
			if g.Tag != "" {
				return true // registered at run time: may match
			}
			for _, m := range g.Static {
				if in(m) {
					return true
				}
			}
		}
	}
	return false
}

// servicePort reports whether a rule's service list could match proto/port
// (proto "": any service will do).
func (c *compiler) servicePort(names []string, proto string, port int) bool {
	if isAny(names) || proto == "" {
		return true
	}
	for _, n := range names {
		s, ok := c.services[n]
		if !ok || s.Protocol != proto {
			continue
		}
		for _, part := range strings.Split(s.Ports, ",") {
			if lo, hi, err := config.PortRange(part); err == nil && lo <= port && port <= hi {
				return true
			}
		}
	}
	return false
}
