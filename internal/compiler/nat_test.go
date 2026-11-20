package compiler

import (
	"strings"
	"testing"

	"github.com/stevejboyle/hobby-ngfw/internal/config"
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
	c.NAT = []config.NATRule{{Name: "g", Type: config.NATPortForward, Interface: "eth2", PublicAddress: "pub", Protocol: "udp", PublicPort: "27015-27020", Server: "srv"}}
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
