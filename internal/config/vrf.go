package config

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// ParseVLAN splits a VLAN subinterface name such as inside.20.
func ParseVLAN(name string) (parent string, id int, ok bool) {
	i := strings.LastIndexByte(name, '.')
	if i <= 0 || i == len(name)-1 {
		return "", 0, false
	}
	id, err := strconv.Atoi(name[i+1:])
	if err != nil || strconv.Itoa(id) != name[i+1:] {
		return "", 0, false
	}
	return name[:i], id, true
}

// VRFOf returns the VRF an interface is in.
func (i Interface) VRFOf() string {
	if i.VRF == "" {
		return VRFDefault
	}
	return i.VRF
}

// VRFOf returns the VRF a route goes into, honouring the older table field.
func (r Route) VRFOf() string {
	switch {
	case r.VRF != "":
		return r.VRF
	case r.Table == TableMgmt:
		return VRFMgmt
	}
	return VRFDefault
}

// VRFTables maps every VRF name, built-in ones included, to its routing
// table: default is 0 (main), mgmt 100, others their table or the next
// free number from 1001 in the order they are listed.
func (c *Config) VRFTables() map[string]int {
	out := map[string]int{VRFDefault: 0, VRFMgmt: MgmtTable}
	used := map[int]bool{}
	for _, v := range c.VRFs {
		if v.Table != 0 {
			used[v.Table] = true
		}
	}
	next := FirstVRFTable
	for _, v := range c.VRFs {
		t := v.Table
		if t == 0 {
			for used[next] {
				next++
			}
			t = next
			used[t] = true
		}
		out[v.Name] = t
	}
	return out
}

// VRFDevice is the Linux device name of a VRF ("" for default).
func VRFDevice(name string) string {
	if name == VRFDefault || name == "" {
		return ""
	}
	return "vrf-" + name
}

// RoutingFor returns the routing entry of a VRF, if any.
func (c *Config) RoutingFor(vrf string) *Routing {
	for i := range c.Routing {
		if c.Routing[i].Name == vrf {
			return &c.Routing[i]
		}
	}
	return nil
}

// VRFOf returns the VRF of a BGP neighbor.
func (n BGPNeighbor) VRFOf() string {
	if n.VRF == "" {
		return VRFDefault
	}
	return n.VRF
}

// InterfaceVRF returns the VRF of a named interface ("" if unknown).
func (c *Config) InterfaceVRF(name string) string {
	if name == c.System.MgmtInterface && name != "" {
		return VRFMgmt
	}
	for _, in := range c.Interfaces {
		if in.Name == name {
			return in.VRFOf()
		}
	}
	return ""
}

// ParsePrefixEntry reads one prefix-list entry:
// "permit|deny PREFIX|any [ge N] [le N]".
func ParsePrefixEntry(e string) (action, prefix string, ge, le int, err error) {
	f := strings.Fields(e)
	if len(f) < 2 {
		return "", "", 0, 0, fmt.Errorf("want: permit|deny PREFIX|any [ge N] [le N]")
	}
	action, prefix = f[0], f[1]
	if action != "permit" && action != "deny" {
		return "", "", 0, 0, fmt.Errorf("must start with permit or deny")
	}
	bits := 0
	if prefix != "any" {
		p, perr := netip.ParsePrefix(prefix)
		if perr != nil || !p.Addr().Is4() || p.Masked() != p {
			return "", "", 0, 0, fmt.Errorf("%q is not an IPv4 prefix without host bits", prefix)
		}
		bits = p.Bits()
	} else if len(f) > 2 {
		return "", "", 0, 0, fmt.Errorf("any takes no ge/le")
	}
	rest := f[2:]
	for len(rest) > 0 {
		if len(rest) < 2 {
			return "", "", 0, 0, fmt.Errorf("%s needs a length", rest[0])
		}
		n, nerr := strconv.Atoi(rest[1])
		if nerr != nil || n < 0 || n > 32 {
			return "", "", 0, 0, fmt.Errorf("%s %s: want 0-32", rest[0], rest[1])
		}
		switch rest[0] {
		case "ge":
			ge = n
		case "le":
			le = n
		default:
			return "", "", 0, 0, fmt.Errorf("unexpected %q", rest[0])
		}
		rest = rest[2:]
	}
	if (ge != 0 && ge <= bits) || (le != 0 && le < bits) || (ge != 0 && le != 0 && le < ge) {
		return "", "", 0, 0, fmt.Errorf("need prefix length < ge <= le")
	}
	return action, prefix, ge, le, nil
}

// NormalizeArea writes an OSPF area as a dotted quad ("0" -> "0.0.0.0").
func NormalizeArea(a string) (string, bool) {
	if n, err := strconv.ParseUint(a, 10, 32); err == nil {
		return fmt.Sprintf("%d.%d.%d.%d", n>>24, (n>>16)&255, (n>>8)&255, n&255), true
	}
	if ip, err := netip.ParseAddr(a); err == nil && ip.Is4() {
		return ip.String(), true
	}
	return "", false
}
