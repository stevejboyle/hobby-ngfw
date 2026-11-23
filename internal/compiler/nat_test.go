package compiler

import (
	"strings"
	"testing"

	"github.com/stevejboyle/sjb-os/internal/config"
)

// natCfg: eth2 (zone b) faces outside; the server 10.9.0.10 sits behind
// eth1 (zone a, 10.9.0.0/24).
func natCfg() *config.Config {
	c := base()
	c.Interfaces[0].Address = "10.9.0.1/24"
	c.Addresses = append(c.Addresses,
		config.Address{Name: "srv", CIDR: "10.9.0.10"},
		config.Address{Name: "srv-net", CIDR: "10.9.0.0/24"},
		config.Address{Name: "pub", CIDR: "198.51.100.7"},
	)
	return c
}

func TestPublishedNAT(t *testing.T) {
	c := natCfg()
	c.NAT = []config.NATRule{
		{Name: "out", From: []string{"a"}, To: []string{"b"}, Type: config.NATMasquerade},
		{Name: "web", Type: config.NATPortForward, Interface: "eth2", Protocol: "tcp", PublicPort: "443", Server: "srv", ServerPort: "8080"},
		{Name: "one", Type: config.NATStatic, Interface: "eth2", PublicAddress: "pub", Server: "srv", Bidirectional: "off"},
	}
	c.Rules = []config.Rule{{Name: "in", From: []string{"b"}, To: []string{"a"}, Destination: []string{"srv-net"}, Action: "allow"}}
	res := compile(t, c)
	for _, want := range []string{
		"type nat hook prerouting priority dstnat; policy accept;",
		`iifname "eth2" fib daddr type local ip daddr != 198.51.100.7 tcp dport 443 counter dnat ip to 10.9.0.10:8080 comment "nat:web"`,
		`iifname "eth2" ip daddr 198.51.100.7 counter dnat ip to 10.9.0.10 comment "nat:one"`,
		`counter masquerade comment "nat:out"`,
	} {
		if !strings.Contains(res.Ruleset, want) {
			t.Errorf("missing %q in:\n%s", want, res.Ruleset)
		}
	}
	if strings.Contains(res.Ruleset, "snat ip to") {
		t.Error("bidirectional off: no source NAT line for the static entry")
	}
	if len(res.Warnings) > 0 {
		t.Errorf("an allow rule covers the server; want no warnings, got %v", res.Warnings)
	}
	// Decryption's hand-over must come after the kernel's destination NAT
	// (dstnat, -100), so it sees a published server's inside address.
	if DecryptPriority != "dstnat + 10" {
		t.Errorf("DecryptPriority = %q", DecryptPriority)
	}
}

func TestBidirectionalBeforeMasquerade(t *testing.T) {
	c := natCfg()
	c.NAT = []config.NATRule{
		{Name: "out", From: []string{"a"}, To: []string{"b"}, Type: config.NATMasquerade},
		{Name: "one", Type: config.NATStatic, Interface: "eth2", PublicAddress: "pub", Server: "srv"},
	}
	res := compile(t, c)
	snat := strings.Index(res.Ruleset, `oifname "eth2" ip saddr 10.9.0.10 counter snat ip to 198.51.100.7 comment "nat:one"`)
	masq := strings.Index(res.Ruleset, `masquerade comment "nat:out"`)
	if snat < 0 || masq < 0 || snat > masq {
		t.Errorf("want the static source NAT line before masquerade:\n%s", res.Ruleset)
	}
}

func TestPortRangeKeepsPorts(t *testing.T) {
	c := natCfg()
	c.NAT = []config.NATRule{{Name: "g", Type: config.NATPortForward, Interface: "eth2", PublicAddress: "pub", Protocol: "udp", PublicPort: "27015-27020", Server: "srv", Hairpin: "off"}}
	res := compile(t, c)
	if want := `iifname "eth2" ip daddr 198.51.100.7 udp dport 27015-27020 counter dnat ip to 10.9.0.10 comment "nat:g"`; !strings.Contains(res.Ruleset, want) {
		t.Errorf("missing %q in:\n%s", want, res.Ruleset)
	}
	if strings.Contains(res.Ruleset, "chain postrouting") {
		t.Error("no source NAT: no postrouting chain")
	}
}

func TestPublishedWithoutAllowRuleWarns(t *testing.T) {
	cases := []struct {
		name  string
		rules []config.Rule
		warn  bool
	}{
		{"no rules", nil, true},
		{"deny only", []config.Rule{{Name: "d", From: []string{"b"}, Action: "deny"}}, true},
		{"wrong port", []config.Rule{{Name: "r", From: []string{"b"}, Destination: []string{"srv"}, Service: []string{"web"}, Action: "allow"}}, true},
		{"public port, not server port", []config.Rule{{Name: "r", From: []string{"b"}, Destination: []string{"srv"}, Service: []string{"dns"}, Action: "allow"}}, true},
		{"wrong zone", []config.Rule{{Name: "r", From: []string{"a"}, Action: "allow"}}, true},
		{"wrong destination", []config.Rule{{Name: "r", From: []string{"b"}, Destination: []string{"h1"}, Action: "allow"}}, true},
		{"to the wrong zone", []config.Rule{{Name: "r", From: []string{"b"}, To: []string{"b"}, Action: "allow"}}, true},
		{"server port", []config.Rule{{Name: "r", From: []string{"b"}, To: []string{"a"}, Destination: []string{"srv"}, Service: []string{"alt"}, Action: "allow"}}, false},
		{"tag group may match", []config.Rule{{Name: "r", From: []string{"b"}, Destination: []string{"bad"}, Action: "allow"}}, false},
		{"any", []config.Rule{{Name: "r", Action: "allow"}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := natCfg()
			// Public 53/udp to the server's 8080/tcp is impossible; use 8080/tcp.
			c.NAT = []config.NATRule{{Name: "web", Type: config.NATPortForward, Interface: "eth2", Protocol: "tcp", PublicPort: "53", Server: "srv", ServerPort: "8080"}}
			c.Rules = tc.rules
			res := compile(t, c)
			got := strings.Contains(strings.Join(res.Warnings, "\n"), `nat "web": no allow rule`)
			if got != tc.warn {
				t.Errorf("warning = %v, want %v (warnings: %v)", got, tc.warn, res.Warnings)
			}
		})
	}
}

func TestHairpin(t *testing.T) {
	c := natCfg()
	c.NAT = []config.NATRule{
		{Name: "out", From: []string{"a"}, To: []string{"b"}, Type: config.NATMasquerade},
		{Name: "web", Type: config.NATPortForward, Interface: "eth2", Protocol: "tcp", PublicPort: "443", Server: "srv", ServerPort: "8080"},
		{Name: "one", Type: config.NATStatic, Interface: "eth2", PublicAddress: "pub", Server: "srv", Bidirectional: "off"},
	}
	res := compile(t, c)
	for _, want := range []string{
		// eth1 (the server's own network) and eth3: every other zoned interface.
		`iifname { "eth1", "eth3" } ip daddr @ifaddr_eth2 tcp dport 443 counter dnat ip to 10.9.0.10:8080 comment "nat:web hairpin"`,
		`iifname { "eth1", "eth3" } ip daddr 198.51.100.7 counter dnat ip to 10.9.0.10 comment "nat:one hairpin"`,
		"set ifaddr_eth2 {",
	} {
		if !strings.Contains(res.Ruleset, want) {
			t.Errorf("missing %q in:\n%s", want, res.Ruleset)
		}
	}
	if res.IfAddrSets["eth2"] != "ifaddr_eth2" || len(res.IfAddrSets) != 1 {
		t.Errorf("IfAddrSets = %v", res.IfAddrSets)
	}
	// Clients on the server's own network are masqueraded, once per server,
	// ahead of the other source NAT.
	hair := `oifname "eth1" ip saddr 10.9.0.0/24 ip daddr 10.9.0.10 counter masquerade comment "nat:hairpin 10.9.0.10"`
	if n := strings.Count(res.Ruleset, hair); n != 1 {
		t.Fatalf("want the hairpin masquerade once, got %d:\n%s", n, res.Ruleset)
	}
	if strings.Index(res.Ruleset, hair) > strings.Index(res.Ruleset, `masquerade comment "nat:out"`) {
		t.Error("hairpin masquerade must come before the other source NAT")
	}
}

func TestHairpinConfiguredAddressVRFAndOff(t *testing.T) {
	c := natCfg()
	c.Interfaces[1].Address = "198.51.100.2/24"
	c.VRFs = []config.VRF{{Name: "blue"}}
	// eth1.30: another VRF, never hairpinned.
	c.Interfaces = append(c.Interfaces, config.Interface{Name: "eth1.30", Zone: "b", VRF: "blue", Address: "10.30.0.1/24"})
	c.NAT = []config.NATRule{
		{Name: "web", Type: config.NATPortForward, Interface: "eth2", Protocol: "tcp", PublicPort: "443", Server: "srv"},
		{Name: "dns", Type: config.NATPortForward, Interface: "eth2", PublicAddress: "pub", Protocol: "udp", PublicPort: "53", Server: "srv", Hairpin: "off"},
	}
	res := compile(t, c)
	if want := `iifname { "eth1", "eth3" } ip daddr 198.51.100.2 tcp dport 443 counter dnat ip to 10.9.0.10:443 comment "nat:web hairpin"`; !strings.Contains(res.Ruleset, want) {
		t.Errorf("missing %q in:\n%s", want, res.Ruleset)
	}
	if strings.Contains(res.Ruleset, "ifaddr_") || len(res.IfAddrSets) != 0 {
		t.Error("a configured interface address needs no live set")
	}
	if strings.Contains(res.Ruleset, "nat:dns hairpin") {
		t.Error("hairpin off: no hairpin line")
	}
	if strings.Contains(res.Ruleset, `"eth1.30" } ip daddr`) {
		t.Errorf("eth1.30 is in another VRF:\n%s", res.Ruleset)
	}
}
