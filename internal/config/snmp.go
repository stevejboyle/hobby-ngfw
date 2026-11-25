package config

import (
	"fmt"
	"net/netip"
	"strings"
)

// SNMP is the SNMP agent (net-snmp's snmpd, read-only). Secrets never sit
// in the config: v3 users and v2c communities are credentials kept in
// /etc/ngfw/snmp-credentials (superusers manage them); the config names
// which ones may poll and which ones traps use.
type SNMP struct {
	// Enabled: "on" runs the agent; off (also when unset) stops it.
	Enabled  string `yaml:"enabled,omitempty" json:"enabled"`
	Location string `yaml:"location,omitempty" json:"location"` // sysLocation
	Contact  string `yaml:"contact,omitempty" json:"contact"`   // sysContact
	// V3Users are v3 credentials that may poll (authenticated, encrypted).
	V3Users []string `yaml:"v3_users,omitempty" json:"v3_users"`
	// Communities are v2c credentials that may poll, from Managers only.
	Communities []string `yaml:"v2c_communities,omitempty" json:"v2c_communities"`
	// Managers are the addresses (IPv4 hosts or prefixes) v2c polls are
	// accepted from. v3 users authenticate, so they aren't limited by it.
	Managers []string `yaml:"managers,omitempty" json:"managers"`
}

// On reports whether the agent runs.
func (s SNMP) On() bool { return s.Enabled == "on" }

// SNMPTrapReceiver is a manager the agent sends traps to (link up/down,
// service down, IPS engine down, commit failed), over the management
// network.
type SNMPTrapReceiver struct {
	Name       string `yaml:"name" json:"name"`
	Address    string `yaml:"address" json:"address"`       // IPv4
	Port       int    `yaml:"port,omitempty" json:"port"`   // default 162
	Credential string `yaml:"credential" json:"credential"` // a v3 user or v2c community credential
	// Inform: "on" sends v3 informs (acknowledged, retried) instead of
	// traps; v3 credentials only.
	Inform string `yaml:"inform,omitempty" json:"inform"`
}

// PortOrDefault is the receiver's port (162 when unset).
func (r SNMPTrapReceiver) PortOrDefault() int {
	if r.Port == 0 {
		return 162
	}
	return r.Port
}

// MaxSNMPTrapReceivers caps snmp_trap_receivers.
const MaxSNMPTrapReceivers = 8

// snmpText is what location and contact may hold: printable, one line, no
// quotes (they go into snmpd.conf).
func snmpText(s string) bool {
	if len(s) > 255 {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f || r == '"' || r == '\\' {
			return false
		}
	}
	return true
}

// SNMPManagerPrefix parses a manager: an IPv4 host or prefix.
func SNMPManagerPrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil || !p.Addr().Is4() {
			return netip.Prefix{}, fmt.Errorf("not an IPv4 prefix")
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil || !a.Is4() {
		return netip.Prefix{}, fmt.Errorf("not an IPv4 address")
	}
	return netip.PrefixFrom(a, 32), nil
}

func (v *validator) snmp(c *Config) {
	s := c.SNMP
	switch s.Enabled {
	case "", "on", "off":
	default:
		v.add("snmp", "enabled must be on or off, got %q", s.Enabled)
	}
	if !snmpText(s.Location) {
		v.add("snmp", "location: printable text without quotes or backslashes, at most 255 characters")
	}
	if !snmpText(s.Contact) {
		v.add("snmp", "contact: printable text without quotes or backslashes, at most 255 characters")
	}
	seen := map[string]string{}
	for _, list := range []struct {
		field string
		names []string
	}{{"v3_users", s.V3Users}, {"v2c_communities", s.Communities}} {
		for _, n := range list.names {
			v.checkName("snmp."+list.field, n)
			if other, ok := seen[n]; ok {
				v.add("snmp."+list.field, "%q is already listed in %s", n, other)
			}
			seen[n] = list.field
		}
	}
	for _, m := range s.Managers {
		if _, err := SNMPManagerPrefix(m); err != nil {
			v.add("snmp.managers", "%q: %v", m, err)
		}
	}
	if len(s.Communities) > 0 && len(s.Managers) == 0 {
		v.add("snmp", "v2c_communities need managers: v2c sends its community in clear text, so it's accepted only from the managers' addresses")
	}
	if len(c.SNMPTrapReceivers) > MaxSNMPTrapReceivers {
		v.add("snmp_trap_receivers", "at most %d receivers", MaxSNMPTrapReceivers)
	}
	names := map[string]bool{}
	targets := map[string]string{}
	for i, r := range c.SNMPTrapReceivers {
		p := fmt.Sprintf("snmp_trap_receivers[%d] %q", i, r.Name)
		v.checkName(p, r.Name)
		if names[r.Name] {
			v.add(p, "duplicate name")
		}
		names[r.Name] = true
		ip, err := netip.ParseAddr(r.Address)
		switch {
		case r.Address == "":
			v.add(p, "address required")
		case err != nil || !ip.Is4():
			v.add(p, "address must be an IPv4 address, got %q", r.Address)
		case ip.IsUnspecified() || ip.IsMulticast() || ip == netip.AddrFrom4([4]byte{255, 255, 255, 255}):
			v.add(p, "address %s can't receive traps", ip)
		}
		if r.Port < 0 || r.Port > 65535 {
			v.add(p, "port must be 1-65535 (or unset for 162)")
		}
		if r.Credential == "" {
			v.add(p, "credential required (a v3 user or v2c community credential)")
		} else {
			v.checkName(p+" credential", r.Credential)
		}
		switch r.Inform {
		case "", "on", "off":
		default:
			v.add(p, "inform must be on or off, got %q", r.Inform)
		}
		key := fmt.Sprintf("%s:%d", r.Address, r.PortOrDefault())
		if other, ok := targets[key]; ok {
			v.add(p, "same address and port as %q", other)
		} else {
			targets[key] = r.Name
		}
	}
}
