package config

import (
	"strings"
	"testing"
)

// natBase is base() with an outside interface and server/public addresses.
func natBase() *Config {
	c := base()
	c.Interfaces = append(c.Interfaces, Interface{Name: "eth2", Zone: "internet"})
	c.Addresses = append(c.Addresses,
		Address{Name: "srv", CIDR: "10.0.0.20"},
		Address{Name: "srv2", CIDR: "10.0.0.21/32"},
		Address{Name: "pub1", CIDR: "203.0.113.20"},
		Address{Name: "pub2", CIDR: "203.0.113.21"},
	)
	return c
}

func fwd(name, pub, proto, port, srv, srvPort string) NATRule {
	return NATRule{Name: name, Type: NATPortForward, Interface: "eth2", PublicAddress: pub,
		Protocol: proto, PublicPort: port, Server: srv, ServerPort: srvPort}
}

func static(name, pub, srv, bidi string) NATRule {
	return NATRule{Name: name, Type: NATStatic, Interface: "eth2", PublicAddress: pub, Server: srv, Bidirectional: bidi}
}

func TestValidNAT(t *testing.T) {
	c := natBase()
	c.NAT = []NATRule{
		{Name: "out", From: []string{"users"}, To: []string{"internet"}, Type: NATMasquerade},
		fwd("web", "", "tcp", "443", "srv", "8443"),
		fwd("web-alt", "", "tcp", "8443", "srv", ""),
		fwd("games", "", "udp", "27000-27010", "srv", "27000-27010"),
		fwd("dns", "pub2", "udp", "53", "srv2", ""),
		fwd("dns-tcp", "pub2", "tcp", "53", "srv2", ""),
		static("mail", "pub1", "srv", ""),
		static("mail-in-only", "pub1", "srv2", "off"),
	}
	// mail and mail-in-only share pub1: that is refused, so give the second its own.
	c.Addresses = append(c.Addresses, Address{Name: "pub3", CIDR: "203.0.113.22"})
	c.NAT[7].PublicAddress = "pub3"
	if err := c.Validate(); err != nil {
		t.Fatalf("NAT should be valid: %v", err)
	}
	if !c.NAT[6].BidirectionalOn() || c.NAT[7].BidirectionalOn() || c.NAT[1].BidirectionalOn() {
		t.Error("BidirectionalOn: want on by default for static, off when set off and for port-forward")
	}
	c.NAT[1].Hairpin = "off"
	c.NAT[6].Hairpin = "on"
	if err := c.Validate(); err != nil {
		t.Fatalf("hairpin on/off should be valid: %v", err)
	}
	if !c.NAT[2].HairpinOn() || !c.NAT[6].HairpinOn() || c.NAT[1].HairpinOn() || c.NAT[0].HairpinOn() {
		t.Error("HairpinOn: want on by default for published entries, off when set off and for masquerade")
	}
}

func TestInvalidNAT(t *testing.T) {
	cases := []struct {
		name string
		nat  []NATRule
		want string
	}{
		{"bad type", []NATRule{{Name: "n", Type: "dnat"}}, "type must be masquerade, port-forward or static"},
		{"masquerade with server", []NATRule{{Name: "n", Type: NATMasquerade, Server: "srv"}}, "server is for port-forward"},
		{"forward with zones", []NATRule{func() NATRule { n := fwd("n", "", "tcp", "80", "srv", ""); n.From = []string{"internet"}; return n }()}, "from, to and source are for masquerade"},
		{"no interface", []NATRule{func() NATRule { n := fwd("n", "", "tcp", "80", "srv", ""); n.Interface = ""; return n }()}, "interface required"},
		{"mgmt interface", []NATRule{func() NATRule { n := fwd("n", "", "tcp", "80", "srv", ""); n.Interface = "mgmt0"; return n }()}, "is the management interface"},
		{"unknown interface", []NATRule{func() NATRule { n := fwd("n", "", "tcp", "80", "srv", ""); n.Interface = "eth9"; return n }()}, `unknown interface "eth9"`},
		{"no server", []NATRule{fwd("n", "", "tcp", "80", "", "")}, "server required"},
		{"server is a prefix", []NATRule{fwd("n", "", "tcp", "80", "lan", "")}, `server "lan" must be an address object naming one host`},
		{"server unknown", []NATRule{fwd("n", "", "tcp", "80", "nope", "")}, `server "nope" must be`},
		{"public is a prefix", []NATRule{fwd("n", "lan", "tcp", "80", "srv", "")}, `public_address "lan" must be`},
		{"public is server", []NATRule{fwd("n", "srv", "tcp", "80", "srv", "")}, "public_address and server are the same"},
		{"no protocol", []NATRule{fwd("n", "", "", "80", "srv", "")}, "protocol required"},
		{"icmp", []NATRule{fwd("n", "", "icmp", "80", "srv", "")}, "protocol must be tcp or udp"},
		{"no port", []NATRule{fwd("n", "", "tcp", "", "srv", "")}, "public_port required"},
		{"bad port", []NATRule{fwd("n", "", "tcp", "70000", "srv", "")}, "public_port: invalid port"},
		{"reversed range", []NATRule{fwd("n", "", "tcp", "90-80", "srv", "")}, "is reversed"},
		{"list of ports", []NATRule{fwd("n", "", "tcp", "80,443", "srv", "")}, "public_port: invalid port"},
		{"range to other range", []NATRule{fwd("n", "", "tcp", "8000-8010", "srv", "9000-9010")}, "same range on the server"},
		{"port to range", []NATRule{fwd("n", "", "tcp", "80", "srv", "80-81")}, "must be one port"},
		{"bad hairpin", []NATRule{func() NATRule { n := fwd("n", "", "tcp", "80", "srv", ""); n.Hairpin = "yes"; return n }()}, "hairpin must be on or off"},
		{"hairpin on masquerade", []NATRule{{Name: "n", Type: NATMasquerade, Hairpin: "on"}}, "hairpin is for port-forward"},
		{"bidirectional on forward", []NATRule{func() NATRule { n := fwd("n", "", "tcp", "80", "srv", ""); n.Bidirectional = "on"; return n }()}, "bidirectional is for static NAT"},
		{"overlapping forwards", []NATRule{fwd("a", "", "tcp", "8000-8010", "srv", ""), fwd("b", "", "tcp", "8005", "srv2", "")}, `overlaps port-forward "a"`},
		{"static without public", []NATRule{static("n", "", "srv", "")}, "public_address required for static NAT"},
		{"static with port", []NATRule{func() NATRule { n := static("n", "pub1", "srv", ""); n.PublicPort = "80"; return n }()}, "static NAT translates every port"},
		{"static bad bidirectional", []NATRule{static("n", "pub1", "srv", "yes")}, "bidirectional must be on or off"},
		{"two statics one public", []NATRule{static("a", "pub1", "srv", ""), static("b", "pub1", "srv2", "")}, `already published by static NAT "a"`},
		{"two bidirectional one server", []NATRule{static("a", "pub1", "srv", ""), static("b", "pub2", "srv", "")}, "already has a bidirectional static NAT"},
		{"forward on static public", []NATRule{fwd("f", "pub1", "tcp", "80", "srv2", ""), static("s", "pub1", "srv", "")}, `already published by static NAT "s"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := natBase()
			c.NAT = tc.nat
			err := c.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestNATPublicNotMgmt(t *testing.T) {
	c := natBase()
	c.Interfaces[0].Address = "192.168.1.5/24"
	c.Addresses = append(c.Addresses, Address{Name: "mgmt-ip", CIDR: "192.168.1.5"})
	c.NAT = []NATRule{fwd("n", "mgmt-ip", "tcp", "80", "srv", "")}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "is the management address") {
		t.Fatalf("want management address error, got %v", err)
	}
}

func TestNATServerSameVRF(t *testing.T) {
	c := natBase()
	c.VRFs = []VRF{{Name: "lab"}}
	c.Interfaces = append(c.Interfaces,
		Interface{Name: "eth1.50", Zone: "users", VRF: "lab", Address: "172.16.50.1/24"},
		Interface{Name: "eth1.60", Zone: "internet", VRF: "lab", Address: "198.51.100.1/24"})
	c.Addresses = append(c.Addresses, Address{Name: "lab-srv", CIDR: "172.16.50.10"})
	c.NAT = []NATRule{fwd("n", "", "tcp", "22", "lab-srv", "")}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "same VRF") {
		t.Fatalf("want same-VRF error, got %v", err)
	}
	c.NAT[0].Interface = "eth1.60"
	if err := c.Validate(); err != nil {
		t.Fatalf("server in the interface's own VRF should be valid: %v", err)
	}
}
