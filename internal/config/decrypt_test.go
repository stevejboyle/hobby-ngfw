package config

import (
	"strings"
	"testing"
)

func decryptBase() *Config {
	c := base()
	c.Interfaces = append(c.Interfaces, Interface{Name: "eth2", Zone: "internet"})
	c.Services = append(c.Services, Service{Name: "https", Protocol: "tcp", Ports: "443"}, Service{Name: "dns", Protocol: "udp", Ports: "53"})
	c.DecryptionRules = []DecryptionRule{
		{Name: "skip-host", Source: []string{"hosts"}, Action: NoDecryptAction},
		{Name: "users-out", From: []string{"users"}, To: []string{"internet"}, Service: []string{"https"}, Action: DecryptAction},
	}
	c.DecryptionProfiles = []DecryptionProfile{{Name: "strict", BadCertificate: DecryptBlock, Unsupported: DecryptBlock, Pinned: DecryptBlock}}
	c.DecryptionExclusions = []DecryptionExclusion{{Name: "banks", Domains: []string{"bank.example", "*.pay.example"}}}
	return c
}

func TestDecryptionValid(t *testing.T) {
	c := decryptBase()
	c.DecryptionRules[1].Profile = "strict"
	if err := c.Validate(); err != nil {
		t.Fatalf("decryption config should be valid: %v", err)
	}
	if !c.DecryptionActive() {
		t.Error("a decrypt rule with decryption on should be active")
	}
	c.System.Decryption = "off"
	if c.DecryptionActive() {
		t.Error("decryption off should not be active")
	}
}

func TestDecryptionInvalid(t *testing.T) {
	cases := []struct {
		name string
		mod  func(c *Config)
		want string
	}{
		{"bad system switch", func(c *Config) { c.System.Decryption = "maybe" }, "system.decryption: must be on, off or observe"},
		{"bad builtin switch", func(c *Config) { c.System.DecryptionBuiltinExclusions = "no" }, "system.decryption_builtin_exclusions: must be on or off"},
		{"bad action", func(c *Config) { c.DecryptionRules[1].Action = "allow" }, `decryption_rules[1] "users-out": action must be decrypt or no-decrypt`},
		{"unknown zone", func(c *Config) { c.DecryptionRules[1].From = []string{"dmz"} }, `from: unknown zone "dmz"`},
		{"unknown address", func(c *Config) { c.DecryptionRules[0].Source = []string{"nope"} }, `source: unknown address or group "nope"`},
		{"udp service", func(c *Config) { c.DecryptionRules[1].Service = []string{"dns"} }, `service "dns" is udp`},
		{"unknown profile", func(c *Config) { c.DecryptionRules[1].Profile = "lax" }, `unknown decryption profile "lax"`},
		{"duplicate rule", func(c *Config) { c.DecryptionRules[1].Name = "skip-host" }, "duplicate decryption rule name"},
		{"bad profile value", func(c *Config) { c.DecryptionProfiles[0].BadCertificate = "pass" }, "bad_certificate must be warn or block"},
		{"bad pinned value", func(c *Config) { c.DecryptionProfiles[0].Pinned = "warn" }, "pinned must be exclude or block"},
		{"duplicate profile", func(c *Config) {
			c.DecryptionProfiles = append(c.DecryptionProfiles, DecryptionProfile{Name: "strict"})
		}, "duplicate decryption profile name"},
		{"upper-case domain", func(c *Config) { c.DecryptionExclusions[0].Domains = []string{"Bank.example"} }, `"Bank.example" is not a server name`},
		{"wildcard in the middle", func(c *Config) { c.DecryptionExclusions[0].Domains = []string{"a.*.example"} }, "is not a server name"},
		{"bare wildcard", func(c *Config) { c.DecryptionExclusions[0].Domains = []string{"*"} }, "is not a server name"},
		{"no domains", func(c *Config) { c.DecryptionExclusions[0].Domains = nil }, "domains required"},
		{"vrf zone", func(c *Config) {
			c.VRFs = []VRF{{Name: "blue"}}
			c.Interfaces = append(c.Interfaces, Interface{Name: "eth1.20", Zone: "users", VRF: "blue"})
		}, "decryption covers the default vrf only"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := decryptBase()
			tc.mod(c)
			err := c.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestDecryptionProfileDefaults(t *testing.T) {
	c := decryptBase()
	p, ok := c.DecryptionProfile("")
	if !ok || p.BadCertificate != DecryptWarn || p.Unsupported != DecryptPass || p.Pinned != DecryptExclude || p.AllowQUIC {
		t.Fatalf("built-in default = %+v, %v", p, ok)
	}
	c.DecryptionProfiles = append(c.DecryptionProfiles, DecryptionProfile{Name: "half", Unsupported: DecryptBlock})
	p, _ = c.DecryptionProfile("half")
	if p.BadCertificate != DecryptWarn || p.Unsupported != DecryptBlock {
		t.Fatalf("unset fields should come from the default: %+v", p)
	}
	if _, ok := c.DecryptionProfile("missing"); ok {
		t.Fatal("unknown profile found")
	}
}

func TestValidDomain(t *testing.T) {
	for d, want := range map[string]bool{
		"example.com": true, "*.example.com": true, "a-b.c.example": true, "localhost": true,
		"": false, "*": false, "*.": false, "-a.example": false, "a..b": false, "EXAMPLE.com": false, "a b": false, "*.*.x": false,
	} {
		if got := ValidDomain(d); got != want {
			t.Errorf("ValidDomain(%q) = %v, want %v", d, got, want)
		}
	}
}
