package compiler

import (
	"flag"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stevejboyle/hobby-ngfw/internal/appid"
	"github.com/stevejboyle/hobby-ngfw/internal/config"
)

var update = flag.Bool("update", false, "rewrite golden files")

// TestGolden compiles each example config and compares against
// testdata/<name>.nft. Run `go test ./internal/compiler -update` after an
// intended change, then review the diff.
func TestGolden(t *testing.T) {
	tags := map[string][]TagEntry{
		"quarantine": {
			{IP: netip.MustParseAddr("10.10.1.66"), Remaining: 90 * time.Minute},
			{IP: netip.MustParseAddr("10.10.1.20")},
		},
		"unused-tag": {{IP: netip.MustParseAddr("10.9.9.9")}},
	}
	for _, name := range []string{"basic", "lab", "vrf", "routing", "dhcp", "appid", "ips", "decryption", "nat"} {
		t.Run(name, func(t *testing.T) {
			cfg, err := config.Load(filepath.Join("..", "..", "examples", name+".yaml"))
			if err != nil {
				t.Fatal(err)
			}
			res, err := Compile(cfg, tags)
			if err != nil {
				t.Fatal(err)
			}
			got := res.Ruleset
			if len(res.Warnings) > 0 {
				got += "\n# warnings:\n# " + strings.Join(res.Warnings, "\n# ") + "\n"
			}
			golden := filepath.Join("testdata", name+".nft")
			if *update {
				if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatalf("%v (run with -update to create)", err)
			}
			if got != string(want) {
				t.Errorf("ruleset differs from %s; run with -update and review.\n--- got ---\n%s", golden, got)
			}
		})
	}
}

func compile(t *testing.T, c *config.Config) *Result {
	t.Helper()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	res, err := Compile(c, nil)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func base() *config.Config {
	return &config.Config{
		System: config.System{Hostname: "fw"},
		Zones:  []config.Zone{{Name: "a"}, {Name: "b"}, {Name: "empty"}},
		Interfaces: []config.Interface{
			{Name: "eth1", Zone: "a"}, {Name: "eth2", Zone: "b"}, {Name: "eth3", Zone: "b"},
		},
		Addresses: []config.Address{{Name: "h1", CIDR: "10.0.0.1"}, {Name: "n1", CIDR: "10.1.0.9/16"}},
		AddressGroups: []config.AddressGroup{
			{Name: "bad", Tag: "bad-actors"},
			{Name: "both", Static: []string{"h1", "n1"}},
		},
		Services: []config.Service{
			{Name: "web", Protocol: "tcp", Ports: "80,443"},
			{Name: "alt", Protocol: "tcp", Ports: "443,8080"},
			{Name: "dns", Protocol: "udp", Ports: "53"},
		},
	}
}

func TestExpansion(t *testing.T) {
	c := base()
	c.Rules = []config.Rule{{
		Name: "r", From: []string{"a"}, To: []string{"b"},
		Source:  []string{"h1", "bad"},
		Service: []string{"web", "alt", "dns"},
		Action:  "allow",
	}}
	res := compile(t, c)
	for _, want := range []string{
		`iifname "eth1" oifname { "eth2", "eth3" } ip saddr 10.0.0.1 meta l4proto tcp th dport { 80, 443, 8080 } counter accept comment "rule:r"`,
		`ip saddr 10.0.0.1 meta l4proto udp th dport 53 counter accept`,
		`ip saddr @dag_bad_actors meta l4proto tcp th dport { 80, 443, 8080 } counter accept`,
		`ip saddr @dag_bad_actors meta l4proto udp th dport 53 counter accept`,
		`set dag_bad_actors {`,
	} {
		if !strings.Contains(res.Ruleset, want) {
			t.Errorf("missing %q in:\n%s", want, res.Ruleset)
		}
	}
	if n := strings.Count(res.Ruleset, `comment "rule:r"`); n != 4 {
		t.Errorf("want 4 expanded lines, got %d", n)
	}
}

func TestStaticGroupMasksPrefix(t *testing.T) {
	c := base()
	c.Rules = []config.Rule{{Name: "r", Destination: []string{"both"}, Action: "deny"}}
	res := compile(t, c)
	if !strings.Contains(res.Ruleset, `ip daddr { 10.0.0.1, 10.1.0.0/16 } counter drop`) {
		t.Errorf("unexpected ruleset:\n%s", res.Ruleset)
	}
}

func TestResetVerdicts(t *testing.T) {
	c := base()
	c.Rules = []config.Rule{
		{Name: "any-svc", Action: "reset"},
		{Name: "udp-svc", Service: []string{"dns"}, Action: "reset"},
	}
	res := compile(t, c)
	for _, want := range []string{
		`meta l4proto tcp counter reject with tcp reset comment "rule:any-svc"`,
		`counter reject with icmpx type admin-prohibited comment "rule:any-svc"`,
		`meta l4proto udp th dport 53 counter reject with icmpx type admin-prohibited comment "rule:udp-svc"`,
	} {
		if !strings.Contains(res.Ruleset, want) {
			t.Errorf("missing %q in:\n%s", want, res.Ruleset)
		}
	}
}

func TestSkips(t *testing.T) {
	c := base()
	c.System.AppID = "off" // application rules need App Identification
	c.Rules = []config.Rule{
		{Name: "app", Application: []string{"bittorrent"}, Action: "deny"},
		{Name: "nozone", From: []string{"empty"}, Action: "allow"},
	}
	res := compile(t, c)
	if len(res.Warnings) != 2 {
		t.Fatalf("want 2 warnings, got %v", res.Warnings)
	}
	if strings.Contains(res.Ruleset, `comment "rule:app"`) || strings.Contains(res.Ruleset, `comment "rule:nozone"`) {
		t.Errorf("skipped rules must not compile to nft rules:\n%s", res.Ruleset)
	}
}

func TestIPv6Rejected(t *testing.T) {
	c := base()
	c.Addresses[0].CIDR = "2001:db8::1"
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := Compile(c, nil); err == nil || !strings.Contains(err.Error(), "IPv6") {
		t.Fatalf("want IPv6 error, got %v", err)
	}
}

func TestNAT(t *testing.T) {
	c := base()
	c.NAT = []config.NATRule{{Name: "out", From: []string{"a"}, To: []string{"b"}, Source: []string{"h1"}, Type: "masquerade"}}
	res := compile(t, c)
	for _, want := range []string{
		"type nat hook postrouting priority srcnat; policy accept;",
		`iifname "eth1" oifname { "eth2", "eth3" } ip saddr 10.0.0.1 counter masquerade comment "nat:out"`,
	} {
		if !strings.Contains(res.Ruleset, want) {
			t.Errorf("missing %q in:\n%s", want, res.Ruleset)
		}
	}
	if strings.Contains(compile(t, base()).Ruleset, "postrouting") {
		t.Error("no NAT rules should mean no postrouting chain")
	}
}

func TestInputProtectsFirewall(t *testing.T) {
	c := base()
	c.Interfaces = append(c.Interfaces, config.Interface{Name: "mgmt0"})
	c.System.MgmtInterface = "mgmt0"
	res := compile(t, c)
	for _, want := range []string{
		"type filter hook input priority filter; policy accept;",
		`iifname { "eth1", "eth2", "eth3" } meta l4proto icmp accept`,
		`iifname { "eth1", "eth2", "eth3" } counter drop comment "zone-to-firewall"`,
	} {
		if !strings.Contains(res.Ruleset, want) {
			t.Errorf("missing %q in:\n%s", want, res.Ruleset)
		}
	}
	if strings.Contains(res.Ruleset, `"mgmt0"`) {
		t.Error("management interface must never appear in the ruleset")
	}
}

func TestDefaultDenyAndTransaction(t *testing.T) {
	res := compile(t, base())
	for _, want := range []string{
		"table inet ngfw\ndelete table inet ngfw\ntable inet ngfw {",
		"policy drop;",
		"ct state established,related accept",
		`counter comment "default-deny"`,
	} {
		if !strings.Contains(res.Ruleset, want) {
			t.Errorf("missing %q", want)
		}
	}
}

func TestAppIDOff(t *testing.T) {
	c := base()
	c.Rules = []config.Rule{{Name: "web", From: []string{"a"}, To: []string{"b"}, Service: []string{"web"}, Action: "allow", Log: true}}
	on := compile(t, c).Ruleset
	if !strings.Contains(on, "chain appid {") || !strings.Contains(on, "queue flags bypass,fanout to 0-1") ||
		!strings.Contains(on, "ct mark set ct mark and 0x0000f7ff or 0x00010800 accept") {
		t.Fatalf("App Identification on (default):\n%s", on)
	}
	c.System.AppID = "off"
	off := compile(t, c).Ruleset
	if strings.Contains(off, "appid") || strings.Contains(off, "ct mark") {
		t.Fatalf("App Identification off still queues or marks:\n%s", off)
	}
}

// App policy: application rules act once App Identification names the connection;
// until then allowed connections are re-evaluated, not finalised.
func TestAppPolicy(t *testing.T) {
	c := base()
	c.Rules = []config.Rule{
		{Name: "early", From: []string{"a"}, To: []string{"b"}, Service: []string{"dns"}, Action: "allow"},
		{Name: "no-tube", From: []string{"a"}, To: []string{"b"}, Application: []string{"YouTube", "netflix"}, Action: "deny", Log: true},
		{Name: "ssh-only", From: []string{"a"}, To: []string{"b"}, Application: []string{"ssh", "unknown"}, Action: "allow", Log: true},
		{Name: "rest", From: []string{"a"}, To: []string{"b"}, Action: "allow"},
	}
	rs := compile(t, c).Ruleset
	for _, want := range []string{
		"chain allowed {",
		"ct mark and 0x4000 == 0x4000 drop",
		"ct state established ct mark and 0x2000 == 0x2000 accept",
		"ct state related ct mark set ct mark or 0x2000 accept",
		"ct state established ct direction reply accept",
		// Above every app rule: final at once.
		`meta l4proto udp th dport 53 counter ct mark set ct mark and 0x0000f7ff or 0x00002000 accept comment "rule:early"`,
		// Deny by app: both apps in one set, denied bit, logged inline.
		`ct mark and 0x7ff { 124, 133 } counter log prefix "ngfw no-tube deny " ct mark set ct mark or 0x4000 drop comment "rule:no-tube"`,
		// Logged app allow: log once, tag with the rule, then allowed.
		`ct mark and 0x7ff == 92 ct mark and 0x8000 == 0 log prefix "ngfw ssh-only allow " ct mark set ct mark or 0x8000`,
		`ct mark and 0x7ff == 92 counter ct mark set ct mark and 0x0000f7ff or 0x00030800 jump allowed comment "rule:ssh-only"`,
		// unknown: app 0, classification done.
		`ct mark and 0x17ff == 0x1000 counter ct mark set ct mark and 0x0000f7ff or 0x00030800 jump allowed`,
		// Not known yet: through, not final, at most AppPendingPackets packets,
		// tagged with the rule.
		`ct mark and 0x17ff == 0 ct packets < 40 counter ct mark set ct mark and 0x0000f7ff or 0x00030800 accept comment "rule:ssh-only (application pending)"`,
		// Below an app rule: final only via allowed, and its (empty) tag
		// replaces whatever an earlier evaluation wrote.
		`counter ct mark set ct mark and 0x0000f7ff or 0x00000000 jump allowed comment "rule:rest"`,
	} {
		if !strings.Contains(rs, want) {
			t.Errorf("missing %q in:\n%s", want, rs)
		}
	}
	if strings.Contains(rs, "ct state established,related accept\n\t\tct state invalid") && strings.Contains(rs, "chain forward {\n\t\ttype filter hook forward priority filter; policy drop;\n\t\tct state established,related accept") {
		t.Error("app mode must not fast-accept established connections before the rules")
	}
	// The pending line must come after the app-matched lines of its rule.
	if strings.Index(rs, "rule:ssh-only (application pending)") < strings.Index(rs, `jump allowed comment "rule:ssh-only"`) {
		t.Error("pending line before the app lines")
	}
}

// Application rule with an IPS profile: the packets that pass while the
// application is still unknown carry the rule's tag, so the IPS chain
// queues them under the rule's profile (a signature in the first request is
// inspected), and the pending allowance is bounded, so a stopped or
// overloaded appidd can't make the rule allow unidentified traffic for good.
func TestAppPolicyWithIPS(t *testing.T) {
	c := base()
	c.Rules = []config.Rule{
		{Name: "web-apps", From: []string{"a"}, To: []string{"b"}, Application: []string{"http"}, Action: "allow", IPSProfile: "default"},
		{Name: "rest", From: []string{"a"}, To: []string{"b"}, Action: "allow"},
	}
	rs := compile(t, c).Ruleset
	tag := fmt.Sprintf("0x%08x", 1<<RuleShift)
	pending := fmt.Sprintf(`ct mark and 0x17ff == 0 ct packets < %d counter ct mark set ct mark and 0x0000f7ff or %s accept comment "rule:web-apps (application pending)"`, AppPendingPackets, tag)
	for _, want := range []string{
		pending,
		// Identified as http: same tag, then allowed.
		"ct mark set ct mark and 0x0000f7ff or " + tag + " jump allowed comment \"rule:web-apps\"",
		// The IPS queue selects exactly that tag; the profile enforces it.
		"ct mark and 0xffff0000 == " + tag + " queue flags bypass,fanout to 2-3",
		tag + " : jump ips_p0",
		// The rule below clears the tag if the connection ends up there.
		`ct mark set ct mark and 0x0000f7ff or 0x00000000 jump allowed comment "rule:rest"`,
	} {
		if !strings.Contains(rs, want) {
			t.Errorf("missing %q in:\n%s", want, rs)
		}
	}
}

func TestShadowWarning(t *testing.T) {
	c := base()
	c.Rules = []config.Rule{
		{Name: "all-out", From: []string{"a"}, To: []string{"b"}, Action: "allow"},
		{Name: "no-tube", From: []string{"a"}, To: []string{"b"}, Application: []string{"youtube"}, Action: "deny"},
		{Name: "other-zone", From: []string{"b"}, To: []string{"a"}, Action: "deny"},
	}
	w := strings.Join(compile(t, c).Warnings, "\n")
	if !strings.Contains(w, `rule "no-tube" never matches: rule "all-out" above it`) || strings.Contains(w, "other-zone") {
		t.Fatalf("warnings: %s", w)
	}
	c.Rules[0], c.Rules[1] = c.Rules[1], c.Rules[0] // deny first: fine
	if w := compile(t, c).Warnings; len(w) != 0 {
		t.Fatalf("no shadowing expected: %v", w)
	}
}

func TestAppGroupsAndCategories(t *testing.T) {
	c := base()
	c.ApplicationGroups = []config.ApplicationGroup{{Name: "streaming", Members: []string{"youtube", "netflix"}}}
	c.Rules = []config.Rule{
		{Name: "no-streaming", From: []string{"a"}, To: []string{"b"}, Application: []string{"streaming", "netflix"}, Action: "deny"},
		{Name: "no-vpn", From: []string{"a"}, To: []string{"b"}, Application: []string{"category:vpn"}, Action: "deny"},
		{Name: "rest", From: []string{"a"}, To: []string{"b"}, Action: "allow"},
	}
	rs := compile(t, c).Ruleset
	// Group expanded, duplicate netflix once.
	if !strings.Contains(rs, `ct mark and 0x7ff { 124, 133 } counter ct mark set ct mark or 0x4000 drop comment "rule:no-streaming"`) {
		t.Errorf("group:\n%s", rs)
	}
	vpn, _ := appid.CategoryApps("category:vpn")
	m := regexp.MustCompile(`ct mark and 0x7ff \{ ([0-9, ]+) \} counter ct mark set ct mark or 0x4000 drop comment "rule:no-vpn"`).FindStringSubmatch(rs)
	if m == nil || len(strings.Split(m[1], ", ")) != len(vpn) {
		t.Errorf("category:vpn should match all %d VPN apps:\n%s", len(vpn), rs)
	}
}

func TestIPS(t *testing.T) {
	c := base()
	c.IPSProfiles = []config.IPSProfile{{Name: "loose", Major: config.IPSAlert}}
	c.Rules = []config.Rule{
		{Name: "web", From: []string{"a"}, To: []string{"b"}, Service: []string{"web"}, Action: "allow", Log: true, IPSProfile: "loose"},
		{Name: "rest", From: []string{"a"}, To: []string{"b"}, Action: "allow", IPSProfile: "default"},
		{Name: "plain", From: []string{"b"}, To: []string{"a"}, Action: "allow"},
	}
	rs := compile(t, c).Ruleset
	for _, want := range []string{
		"ct mark and 0x4000 == 0x4000 drop",
		// Logged: rule tag and session bit; unlogged with IPS: tag only.
		`ct mark set ct mark and 0x0000f7ff or 0x00010800 accept comment "rule:web"`,
		`ct mark set ct mark and 0x0000f7ff or 0x00020000 accept comment "rule:rest"`,
		`counter accept comment "rule:plain"`,
		"ct mark and 0xffff0000 { 0x00010000, 0x00020000 } queue flags bypass,fanout to 2-3",
		// loose: critical from the default, major alerted.
		`comment "ips:loose critical"`,
		"0x00010000 : jump ips_p0, 0x00020000 : jump ips_p1",
		`comment "ips:default major"`,
	} {
		if !strings.Contains(rs, want) {
			t.Errorf("missing %q in:\n%s", want, rs)
		}
	}
	if strings.Contains(rs, "ips:loose major") || strings.Contains(rs, "minor") {
		t.Errorf("only blocked severities get drop lines:\n%s", rs)
	}

	one := *c
	one.Rules = c.Rules[1:]
	if rs := compile(t, &one).Ruleset; !strings.Contains(rs, "ct mark and 0xffff0000 == 0x00010000 queue") {
		t.Errorf("one IPS rule: an equality, not a set:\n%s", rs)
	}

	c.System.IPS = "off"
	res := compile(t, c)
	if strings.Contains(res.Ruleset, "chain ips") || strings.Contains(res.Ruleset, "0x00020000") || len(res.Warnings) != 2 {
		t.Fatalf("IPS off: %v\n%s", res.Warnings, res.Ruleset)
	}
}

func TestTrunkDropsUntagged(t *testing.T) {
	c := base()
	c.Interfaces = []config.Interface{
		{Name: "eth1"}, // trunk
		{Name: "eth1.150", Zone: "a"},
		{Name: "eth2", Zone: "b"},
	}
	c.Rules = []config.Rule{{Name: "all", Action: "allow"}}
	res := compile(t, c)
	fwd := res.Ruleset[strings.Index(res.Ruleset, "chain forward {"):]
	in := res.Ruleset[strings.Index(res.Ruleset, "chain input {"):]
	drop := `iifname "eth1" counter drop comment "trunk: untagged"`
	if i, r := strings.Index(fwd, drop), strings.Index(fwd, `rule:all`); i < 0 || i > r {
		t.Errorf("forward: want %q before the rules:\n%s", drop, fwd)
	}
	if !strings.Contains(fwd, `oifname "eth1" counter drop comment "trunk: untagged"`) {
		t.Errorf("forward: no drop for traffic routed out of the trunk:\n%s", fwd)
	}
	if !strings.Contains(in[:strings.Index(in, "\n\t}")], drop) {
		t.Errorf("input: want %q:\n%s", drop, in)
	}
	if strings.Contains(compile(t, base()).Ruleset, "trunk: untagged") {
		t.Error("no trunks: no trunk drops")
	}
}
