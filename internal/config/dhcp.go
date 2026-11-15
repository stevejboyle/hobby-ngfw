package config

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// DHCPServer serves DHCPv4 on an interface. Name is the interface; it must
// have an address in the config, whose network is the subnet served.
type DHCPServer struct {
	Name      string   `yaml:"name" json:"name"`
	Range     string   `yaml:"range" json:"range"`                     // pool, e.g. 192.168.150.100-192.168.150.199
	Gateway   string   `yaml:"gateway,omitempty" json:"gateway"`       // router option; default: the interface's address
	DNS       []string `yaml:"dns,omitempty" json:"dns"`               // default: the firewall's own upstream DNS servers
	Domain    string   `yaml:"domain,omitempty" json:"domain"`         // domain name option
	NTP       []string `yaml:"ntp,omitempty" json:"ntp"`               // NTP servers option
	LeaseTime int      `yaml:"lease_time,omitempty" json:"lease_time"` // seconds; 0 = 86400 (a day)
	Options   []string `yaml:"options,omitempty" json:"options"`       // more options: "66=tftp.lab", "150=0x0a000001"
}

// DHCPReservation gives a MAC address a fixed address on an interface that
// has a DHCP server.
type DHCPReservation struct {
	Name      string `yaml:"name" json:"name"`
	Interface string `yaml:"interface" json:"interface"`
	MAC       string `yaml:"mac" json:"mac"`         // aa:bb:cc:dd:ee:ff
	Address   string `yaml:"address" json:"address"` // in the interface's network
}

// DefaultLeaseTime is used when a DHCP server sets none.
const DefaultLeaseTime = 86400

// DHCPOption is one parsed entry of DHCPServer.Options.
type DHCPOption struct {
	Code int
	Data string // the value as written, or hex digits (no 0x) when Hex
	Hex  bool
}

// Options the server fields set, or the DHCP protocol owns, so they can't
// be given as generic options.
var managedDHCPOptions = map[int]string{
	1: "the subnet mask comes from the interface's address", 3: "use gateway", 6: "use dns",
	15: "use domain", 42: "use ntp", 50: "requested address (client only)", 51: "use lease_time",
	53: "message type (protocol)", 54: "server identifier (protocol)", 55: "parameter list (client only)",
	58: "renewal time follows lease_time", 59: "rebinding time follows lease_time", 61: "client identifier (client only)",
	82: "relay agent information (relays only)",
}

var (
	macRE    = regexp.MustCompile(`^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$`)
	hexRE    = regexp.MustCompile(`^(0x|0X)[0-9a-fA-F]+$`)
	domainRE = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,62})(\.[A-Za-z0-9]([A-Za-z0-9-]{0,62}))*$`)
)

// ParseDHCPOption reads "CODE=VALUE"; a value of 0x followed by hex digits
// is sent as raw bytes.
func ParseDHCPOption(s string) (DHCPOption, error) {
	code, val, ok := strings.Cut(s, "=")
	if !ok {
		return DHCPOption{}, fmt.Errorf("want CODE=VALUE, e.g. 66=tftp.lab")
	}
	n, err := strconv.Atoi(strings.TrimSpace(code))
	if err != nil || n < 1 || n > 254 {
		return DHCPOption{}, fmt.Errorf("option code must be 1-254")
	}
	if why, ok := managedDHCPOptions[n]; ok {
		return DHCPOption{}, fmt.Errorf("option %d can't be set here: %s", n, why)
	}
	val = strings.TrimSpace(val)
	if val == "" {
		return DHCPOption{}, fmt.Errorf("option %d has no value", n)
	}
	if hexRE.MatchString(val) {
		h := strings.ToLower(val[2:])
		if len(h)%2 == 1 {
			return DHCPOption{}, fmt.Errorf("option %d: hex value needs whole bytes (an even number of digits)", n)
		}
		return DHCPOption{Code: n, Data: h, Hex: true}, nil
	}
	return DHCPOption{Code: n, Data: val}, nil
}

// ParseDHCPRange reads "FIRST-LAST".
func ParseDHCPRange(s string) (first, last netip.Addr, err error) {
	a, b, ok := strings.Cut(s, "-")
	if !ok {
		return first, last, fmt.Errorf("want FIRST-LAST, e.g. 192.168.150.100-192.168.150.199")
	}
	if first, err = netip.ParseAddr(strings.TrimSpace(a)); err != nil || !first.Is4() {
		return first, last, fmt.Errorf("%q is not an IPv4 address", strings.TrimSpace(a))
	}
	if last, err = netip.ParseAddr(strings.TrimSpace(b)); err != nil || !last.Is4() {
		return first, last, fmt.Errorf("%q is not an IPv4 address", strings.TrimSpace(b))
	}
	if last.Less(first) {
		return first, last, fmt.Errorf("the range ends before it starts")
	}
	return first, last, nil
}

// InterfaceAddress returns the configured address of an interface.
func (c *Config) InterfaceAddress(name string) (netip.Prefix, bool) {
	for _, in := range c.Interfaces {
		if in.Name == name && in.Address != "" {
			p, err := netip.ParsePrefix(in.Address)
			return p, err == nil
		}
	}
	return netip.Prefix{}, false
}

// broadcast is the last address of p.
func broadcast(p netip.Prefix) netip.Addr {
	a := p.Masked().Addr().As4()
	for i := p.Bits(); i < 32; i++ {
		a[i/8] |= 1 << (7 - i%8)
	}
	return netip.AddrFrom4(a)
}

// usableHost reports whether a is a host address in the interface's network
// other than the interface's own.
func usableHost(iface netip.Prefix, a netip.Addr) string {
	net := iface.Masked()
	switch {
	case !a.Is4() || !net.Contains(a):
		return fmt.Sprintf("isn't in the interface's network %s", net)
	case a == iface.Addr():
		return "is the firewall's own address on the interface"
	case iface.Bits() < 31 && a == net.Addr():
		return "is the network address"
	case iface.Bits() < 31 && a == broadcast(iface):
		return "is the broadcast address"
	}
	return ""
}

func (v *validator) dhcp(c *Config) {
	servers := map[string]netip.Prefix{}
	subnets := map[netip.Prefix]string{}
	for i, s := range c.DHCPServers {
		p := fmt.Sprintf("dhcp_servers[%d] %q", i, s.Name)
		if _, dup := servers[s.Name]; dup {
			v.add(p, "duplicate dhcp server (one per interface)")
			continue
		}
		vrf := c.InterfaceVRF(s.Name)
		addr, hasAddr := c.InterfaceAddress(s.Name)
		switch {
		case vrf == "":
			v.add(p, "unknown interface %q", s.Name)
			continue
		case vrf == VRFMgmt:
			v.add(p, "no DHCP server on the management interface")
			continue
		case !hasAddr || !addr.Addr().Is4():
			v.add(p, "interface %s needs an IPv4 address in the config (set interface %s address ...) to serve DHCP", s.Name, s.Name)
			continue
		}
		servers[s.Name] = addr
		if other, dup := subnets[addr.Masked()]; dup {
			v.add(p, "network %s is already served on %s", addr.Masked(), other)
		}
		subnets[addr.Masked()] = s.Name
		if addr.Bits() > 30 {
			v.add(p, "interface %s's network %s is too small to hand out addresses", s.Name, addr.Masked())
		}
		first, last, err := ParseDHCPRange(s.Range)
		if err != nil {
			v.add(p, "range: %v", err)
		} else {
			ends := ""
			for _, a := range []netip.Addr{first, last} {
				if why := usableHost(addr, a); why != "" {
					v.add(p, "range: %s %s", a, why)
					ends = why
				}
			}
			if ends == "" && first.Compare(addr.Addr()) <= 0 && addr.Addr().Compare(last) <= 0 {
				v.add(p, "range: includes the firewall's own address %s", addr.Addr())
			}
		}
		if s.Gateway != "" {
			if g, err := netip.ParseAddr(s.Gateway); err != nil || !g.Is4() {
				v.add(p, "gateway %q is not an IPv4 address", s.Gateway)
			} else if g != addr.Addr() && !addr.Masked().Contains(g) {
				v.add(p, "gateway %s isn't in the interface's network %s", g, addr.Masked())
			}
		}
		for _, list := range []struct {
			field string
			vals  []string
		}{{"dns", s.DNS}, {"ntp", s.NTP}} {
			for _, a := range list.vals {
				if ip, err := netip.ParseAddr(a); err != nil || !ip.Is4() {
					v.add(p, "%s: %q is not an IPv4 address", list.field, a)
				}
			}
		}
		if s.Domain != "" && (len(s.Domain) > 253 || !domainRE.MatchString(s.Domain)) {
			v.add(p, "domain %q is not a valid domain name", s.Domain)
		}
		if s.LeaseTime != 0 && (s.LeaseTime < 60 || s.LeaseTime > 31536000) {
			v.add(p, "lease_time must be 60-31536000 seconds (or 0 for a day)")
		}
		codes := map[int]bool{}
		for _, o := range s.Options {
			opt, err := ParseDHCPOption(o)
			if err != nil {
				v.add(p, "options %q: %v", o, err)
				continue
			}
			if codes[opt.Code] {
				v.add(p, "options: option %d given twice", opt.Code)
			}
			codes[opt.Code] = true
		}
	}

	names := map[string]bool{}
	type key struct{ iface, val string }
	macs, addrs := map[key]string{}, map[key]string{}
	for i, r := range c.DHCPReservations {
		p := fmt.Sprintf("dhcp_reservations[%d] %q", i, r.Name)
		v.checkName(p, r.Name)
		if names[r.Name] {
			v.add(p, "duplicate name")
		}
		names[r.Name] = true
		iface, ok := servers[r.Interface]
		if !ok {
			v.add(p, "interface %q has no dhcp server", r.Interface)
			continue
		}
		if !macRE.MatchString(r.MAC) {
			v.add(p, "mac %q: want six hex pairs separated by colons, e.g. 52:54:00:12:34:56", r.MAC)
		} else {
			k := key{r.Interface, strings.ToLower(r.MAC)}
			if other, dup := macs[k]; dup {
				v.add(p, "mac %s already has reservation %q on %s", r.MAC, other, r.Interface)
			}
			macs[k] = r.Name
		}
		a, err := netip.ParseAddr(r.Address)
		if err != nil || !a.Is4() {
			v.add(p, "address %q is not an IPv4 address", r.Address)
			continue
		}
		if why := usableHost(iface, a); why != "" {
			v.add(p, "address %s %s", a, why)
		}
		k := key{r.Interface, a.String()}
		if other, dup := addrs[k]; dup {
			v.add(p, "address %s is already reserved for %q", a, other)
		}
		addrs[k] = r.Name
	}
}
