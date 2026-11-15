package config

import (
	"strings"
	"testing"
)

func dhcpBase() *Config {
	c := base()
	c.DHCPServers = []DHCPServer{{
		Name: "eth1", Range: "10.0.0.100-10.0.0.199", DNS: []string{"1.1.1.1"}, Domain: "lab.example",
		NTP: []string{"10.0.0.1"}, LeaseTime: 3600, Options: []string{"66=tftp.lab", "150=0x0a000001"},
	}}
	c.DHCPReservations = []DHCPReservation{{Name: "printer", Interface: "eth1", MAC: "52:54:00:AB:cd:01", Address: "10.0.0.20"}}
	return c
}

func TestDHCPValid(t *testing.T) {
	if err := dhcpBase().Validate(); err != nil {
		t.Fatalf("valid DHCP config rejected: %v", err)
	}
}

func TestDHCPInvalid(t *testing.T) {
	for _, tc := range []struct {
		name string
		mod  func(c *Config)
		want string
	}{
		{"unknown iface", func(c *Config) { c.DHCPServers[0].Name = "eth9" }, `unknown interface "eth9"`},
		{"mgmt", func(c *Config) { c.DHCPServers[0].Name = "mgmt0" }, "no DHCP server on the management interface"},
		{"no address", func(c *Config) { c.Interfaces[1].Address = "" }, "needs an IPv4 address in the config"},
		{"dup server", func(c *Config) { c.DHCPServers = append(c.DHCPServers, c.DHCPServers[0]) }, "duplicate dhcp server"},
		{"bad range", func(c *Config) { c.DHCPServers[0].Range = "10.0.0.100" }, "want FIRST-LAST"},
		{"backwards range", func(c *Config) { c.DHCPServers[0].Range = "10.0.0.199-10.0.0.100" }, "ends before it starts"},
		{"range off net", func(c *Config) { c.DHCPServers[0].Range = "10.0.0.100-10.0.1.5" }, "isn't in the interface's network 10.0.0.0/24"},
		{"range has fw", func(c *Config) { c.DHCPServers[0].Range = "10.0.0.0-10.0.0.50" }, "is the network address"},
		{"range spans fw", func(c *Config) {
			c.Interfaces[1].Address = "10.0.0.150/24"
		}, "includes the firewall's own address 10.0.0.150"},
		{"range broadcast", func(c *Config) { c.DHCPServers[0].Range = "10.0.0.200-10.0.0.255" }, "is the broadcast address"},
		{"gateway off net", func(c *Config) { c.DHCPServers[0].Gateway = "192.0.2.1" }, "isn't in the interface's network"},
		{"bad dns", func(c *Config) { c.DHCPServers[0].DNS = []string{"dns.example"} }, `dns: "dns.example" is not an IPv4 address`},
		{"bad domain", func(c *Config) { c.DHCPServers[0].Domain = "bad domain" }, "not a valid domain name"},
		{"lease too short", func(c *Config) { c.DHCPServers[0].LeaseTime = 10 }, "lease_time must be 60-31536000"},
		{"managed option", func(c *Config) { c.DHCPServers[0].Options = []string{"6=1.1.1.1"} }, "option 6 can't be set here: use dns"},
		{"bad option", func(c *Config) { c.DHCPServers[0].Options = []string{"tftp"} }, "want CODE=VALUE"},
		{"odd hex", func(c *Config) { c.DHCPServers[0].Options = []string{"150=0xabc"} }, "whole bytes"},
		{"dup option", func(c *Config) { c.DHCPServers[0].Options = []string{"66=a", "66=b"} }, "option 66 given twice"},
		{"overlapping subnets", func(c *Config) {
			c.Interfaces = append(c.Interfaces, Interface{Name: "eth1.20", Zone: "users", Address: "10.0.0.2/24"})
			c.DHCPServers = append(c.DHCPServers, DHCPServer{Name: "eth1.20", Range: "10.0.0.50-10.0.0.60"})
		}, "network 10.0.0.0/24 is already served on eth1"},
		{"res no server", func(c *Config) { c.DHCPReservations[0].Interface = "mgmt0" }, `interface "mgmt0" has no dhcp server`},
		{"res bad mac", func(c *Config) { c.DHCPReservations[0].MAC = "52-54-00-ab-cd-01" }, "six hex pairs"},
		{"res fw addr", func(c *Config) { c.DHCPReservations[0].Address = "10.0.0.1" }, "the firewall's own address"},
		{"res off net", func(c *Config) { c.DHCPReservations[0].Address = "10.9.0.1" }, "isn't in the interface's network"},
		{"res dup mac", func(c *Config) {
			c.DHCPReservations = append(c.DHCPReservations, DHCPReservation{Name: "other", Interface: "eth1", MAC: "52:54:00:ab:CD:01", Address: "10.0.0.21"})
		}, `already has reservation "printer"`},
		{"res dup addr", func(c *Config) {
			c.DHCPReservations = append(c.DHCPReservations, DHCPReservation{Name: "other", Interface: "eth1", MAC: "52:54:00:ab:cd:02", Address: "10.0.0.20"})
		}, `already reserved for "printer"`},
	} {
		c := dhcpBase()
		tc.mod(c)
		err := c.Validate()
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v, want %q", tc.name, err, tc.want)
		}
	}
}

func TestParseDHCPOption(t *testing.T) {
	o, err := ParseDHCPOption("150=0x0A000001")
	if err != nil || o.Code != 150 || !o.Hex || o.Data != "0a000001" {
		t.Fatalf("hex option: %+v %v", o, err)
	}
	o, err = ParseDHCPOption(" 66 = tftp.lab ")
	if err != nil || o.Code != 66 || o.Hex || o.Data != "tftp.lab" {
		t.Fatalf("string option: %+v %v", o, err)
	}
}
