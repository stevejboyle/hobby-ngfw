package config

import (
	"fmt"
	"net/netip"
	"strings"
)

// HostAddress returns the single IPv4 host an address object names
// ("10.0.0.5" or "10.0.0.5/32"); ok is false for prefixes, unknown names
// and anything else.
func (c *Config) HostAddress(name string) (netip.Addr, bool) {
	for _, a := range c.Addresses {
		if a.Name != name {
			continue
		}
		if ip, err := netip.ParseAddr(a.CIDR); err == nil {
			return ip, ip.Is4()
		}
		if p, err := netip.ParsePrefix(a.CIDR); err == nil && p.Bits() == 32 && p.Addr().Is4() {
			return p.Addr(), true
		}
		return netip.Addr{}, false
	}
	return netip.Addr{}, false
}

// PortRange parses a NAT port: "443" or "8000-8010".
func PortRange(s string) (lo, hi int, err error) {
	a, b, isRange := strings.Cut(strings.TrimSpace(s), "-")
	if lo, err = port(a); err != nil {
		return 0, 0, err
	}
	if !isRange {
		return lo, lo, nil
	}
	if hi, err = port(b); err != nil {
		return 0, 0, err
	}
	if lo > hi {
		return 0, 0, fmt.Errorf("port range %q is reversed", s)
	}
	return lo, hi, nil
}

// ServerPorts returns the port range a port-forward entry sends to on the
// server (the public port range when server_port is empty).
func (n NATRule) ServerPorts() (lo, hi int, err error) {
	if n.ServerPort == "" {
		return PortRange(n.PublicPort)
	}
	return PortRange(n.ServerPort)
}

func (v *validator) nat(c *Config, zones, addrs map[string]bool) {
	names := map[string]bool{}
	type pub struct {
		name   string
		lo, hi int
	}
	forwards := map[string][]pub{} // interface|public|protocol -> published ports
	statics := map[string]string{} // interface|public -> entry name
	snat := map[string]string{}    // server -> bidirectional static entry
	mgmtIPs := map[netip.Addr]bool{}
	for _, in := range c.Interfaces {
		if in.Name == c.System.MgmtInterface && in.Address != "" {
			if p, err := netip.ParsePrefix(in.Address); err == nil {
				mgmtIPs[p.Addr()] = true
			}
		}
	}

	for i, n := range c.NAT {
		p := fmt.Sprintf("nat[%d] %q", i, n.Name)
		v.checkName(p, n.Name)
		if names[n.Name] {
			v.add(p, "duplicate nat rule name")
		}
		names[n.Name] = true

		if n.Type == NATMasquerade {
			v.refs(p, "from", n.From, "zone", func(s string) bool { return zones[s] })
			v.refs(p, "to", n.To, "zone", func(s string) bool { return zones[s] })
			v.refs(p, "source", n.Source, "address or group", func(s string) bool { return addrs[s] })
			for _, f := range [][2]string{
				{"interface", n.Interface}, {"public_address", n.PublicAddress}, {"protocol", n.Protocol},
				{"public_port", n.PublicPort}, {"server", n.Server}, {"server_port", n.ServerPort}, {"bidirectional", n.Bidirectional},
			} {
				if f[1] != "" {
					v.add(p, "%s is for port-forward and static entries, not masquerade", f[0])
				}
			}
			continue
		}
		if !n.Published() {
			v.add(p, "type must be masquerade, port-forward or static, got %q", n.Type)
			continue
		}

		// Published server: port-forward or static.
		if len(n.From) > 0 || len(n.To) > 0 || len(n.Source) > 0 {
			v.add(p, "from, to and source are for masquerade; %s entries use interface", n.Type)
		}
		switch {
		case n.Interface == "":
			v.add(p, "interface required (where the published traffic arrives)")
		case n.Interface == c.System.MgmtInterface:
			v.add(p, "interface %q is the management interface", n.Interface)
		case !hasInterface(c, n.Interface):
			v.add(p, "unknown interface %q", n.Interface)
		case c.IsTrunk(n.Interface):
			v.add(p, "interface %q is a trunk (no zone): publish on one of its VLAN subinterfaces", n.Interface)
		}

		server, okServer := c.HostAddress(n.Server)
		switch {
		case n.Server == "":
			v.add(p, "server required (an address object naming one host)")
		case !okServer:
			v.add(p, "server %q must be an address object naming one host", n.Server)
		}
		if okServer && hasInterface(c, n.Interface) {
			if vrf, ok := serverVRF(c, server); ok && vrf != vrfOf(c, n.Interface) {
				v.add(p, "server %q is in vrf %q but interface %q is in vrf %q; a published server must be in the same VRF as the interface its traffic arrives on", n.Server, vrf, n.Interface, vrfOf(c, n.Interface))
			}
		}
		var public netip.Addr
		switch {
		case n.PublicAddress == "" && n.Type == NATStatic:
			v.add(p, "public_address required for static NAT")
		case n.PublicAddress != "":
			ip, ok := c.HostAddress(n.PublicAddress)
			if !ok {
				v.add(p, "public_address %q must be an address object naming one host", n.PublicAddress)
				break
			}
			public = ip
			if mgmtIPs[ip] {
				v.add(p, "public_address %q is the management address", n.PublicAddress)
			}
			if okServer && ip == server {
				v.add(p, "public_address and server are the same address")
			}
		}
		pubKey := n.Interface + "|" + n.PublicAddress

		if n.Type == NATStatic {
			if n.Protocol != "" || n.PublicPort != "" || n.ServerPort != "" {
				v.add(p, "static NAT translates every port; protocol, public_port and server_port are for port-forward")
			}
			switch n.Bidirectional {
			case "", "on", "off":
			default:
				v.add(p, "bidirectional must be on or off, got %q", n.Bidirectional)
			}
			if public.IsValid() {
				if other, dup := statics[pubKey]; dup {
					v.add(p, "public_address %q is already published by static NAT %q", n.PublicAddress, other)
				}
				statics[pubKey] = n.Name
			}
			if okServer && n.BidirectionalOn() {
				if other, dup := snat[n.Server]; dup {
					v.add(p, "server %q already has a bidirectional static NAT (%q); its outbound traffic can leave from one public address only", n.Server, other)
				}
				snat[n.Server] = n.Name
			}
			continue
		}

		// port-forward
		if n.Bidirectional != "" {
			v.add(p, "bidirectional is for static NAT")
		}
		switch n.Protocol {
		case "tcp", "udp":
		case "":
			v.add(p, "protocol required (tcp or udp)")
		default:
			v.add(p, "protocol must be tcp or udp, got %q", n.Protocol)
		}
		lo, hi, err := PortRange(n.PublicPort)
		if n.PublicPort == "" {
			v.add(p, "public_port required (a port or a range, e.g. 443 or 8000-8010)")
			continue
		}
		if err != nil {
			v.add(p, "public_port: %v", err)
			continue
		}
		if n.ServerPort != "" {
			slo, shi, err := PortRange(n.ServerPort)
			switch {
			case err != nil:
				v.add(p, "server_port: %v", err)
			case lo != hi && (slo != lo || shi != hi):
				v.add(p, "a public port range can only go to the same range on the server (leave server_port empty)")
			case lo == hi && slo != shi:
				v.add(p, "server_port must be one port when public_port is one port")
			}
		}
		key := pubKey + "|" + n.Protocol
		for _, o := range forwards[key] {
			if lo <= o.hi && o.lo <= hi {
				v.add(p, "%s port %s overlaps port-forward %q on the same interface and address", n.Protocol, n.PublicPort, o.name)
			}
		}
		forwards[key] = append(forwards[key], pub{n.Name, lo, hi})
	}

	// A port-forward on a static entry's public address would be shadowed
	// or shadow it, depending on order: refuse it.
	for i, n := range c.NAT {
		if n.Type != NATPortForward || n.PublicAddress == "" {
			continue
		}
		if other, ok := statics[n.Interface+"|"+n.PublicAddress]; ok {
			v.add(fmt.Sprintf("nat[%d] %q", i, n.Name), "public_address %q is already published by static NAT %q", n.PublicAddress, other)
		}
	}
}

func hasInterface(c *Config, name string) bool {
	for _, in := range c.Interfaces {
		if in.Name == name {
			return true
		}
	}
	return false
}

func vrfOf(c *Config, iface string) string {
	for _, in := range c.Interfaces {
		if in.Name == iface {
			return in.VRFOf()
		}
	}
	return VRFDefault
}

// serverVRF is the VRF of the interface whose configured subnet holds ip
// (ok false when no configured subnet does).
func serverVRF(c *Config, ip netip.Addr) (string, bool) {
	for _, in := range c.Interfaces {
		if p, err := netip.ParsePrefix(in.Address); err == nil && in.Name != c.System.MgmtInterface && p.Masked().Contains(ip) {
			return in.VRFOf(), true
		}
	}
	return "", false
}
