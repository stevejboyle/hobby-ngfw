package config

import (
	"fmt"
	"regexp"
	"strings"
)

// TLS decryption: which outbound TLS connections the firewall stands in the
// middle of (with a CA the clients trust), so the rules, App Identification
// and the IPS see what is inside. Decryption rules are their own ordered
// list, checked before routing; the security rules still decide what is
// allowed.

// Decryption rule actions.
const (
	DecryptAction   = "decrypt"
	NoDecryptAction = "no-decrypt"
)

// Decryption profile choices.
const (
	DecryptWarn    = "warn"    // bad server certificate: re-sign with the untrusted CA, so the browser warns
	DecryptBlock   = "block"   // refuse the connection
	DecryptPass    = "pass"    // pass it through undecrypted
	DecryptExclude = "exclude" // pinned apps: learn the server and pass it through from then on
)

// DefaultDecryptionProfile is the built-in profile name; a config may
// redefine it.
const DefaultDecryptionProfile = "default"

// DecryptionRule says which connections to decrypt. An empty match field
// means any. Only TCP services make sense (TLS over TCP); with no service,
// the rule covers TCP port 443.
type DecryptionRule struct {
	Name        string   `yaml:"name" json:"name"`
	From        []string `yaml:"from,omitempty" json:"from"`
	To          []string `yaml:"to,omitempty" json:"to"`
	Source      []string `yaml:"source,omitempty" json:"source"`
	Destination []string `yaml:"destination,omitempty" json:"destination"`
	Service     []string `yaml:"service,omitempty" json:"service"`
	Action      string   `yaml:"action" json:"action"`             // decrypt or no-decrypt
	Profile     string   `yaml:"profile,omitempty" json:"profile"` // default: default
}

// ProfileOf is the rule's profile name.
func (r DecryptionRule) ProfileOf() string {
	if r.Profile == "" {
		return DefaultDecryptionProfile
	}
	return r.Profile
}

// DecryptionProfile says what happens to connections decryption can't
// handle as usual. Empty fields take the built-in default's choice.
type DecryptionProfile struct {
	Name string `yaml:"name" json:"name"`
	// BadCertificate: the server's own certificate fails the checks
	// (expired, self-signed, wrong name): warn (default) or block.
	BadCertificate string `yaml:"bad_certificate,omitempty" json:"bad_certificate"`
	// Unsupported: TLS below 1.2, client certificates, not TLS at all on
	// the port, no server name: pass (default) or block.
	Unsupported string `yaml:"unsupported,omitempty" json:"unsupported"`
	// Pinned: the client rejects the firewall's certificate (a pinned
	// app): exclude (default: remember the server, pass it through from
	// then on) or block.
	Pinned string `yaml:"pinned,omitempty" json:"pinned"`
	// AllowQUIC lets QUIC (UDP 443), which can't be decrypted, through for
	// the rule's traffic. Off by default, so browsers fall back to TLS.
	AllowQUIC bool `yaml:"allow_quic,omitempty" json:"allow_quic"`
}

var builtinDecryption = DecryptionProfile{Name: DefaultDecryptionProfile, BadCertificate: DecryptWarn, Unsupported: DecryptPass, Pinned: DecryptExclude}

// Resolved fills empty choices from the built-in default.
func (p DecryptionProfile) Resolved() DecryptionProfile {
	if p.BadCertificate == "" {
		p.BadCertificate = builtinDecryption.BadCertificate
	}
	if p.Unsupported == "" {
		p.Unsupported = builtinDecryption.Unsupported
	}
	if p.Pinned == "" {
		p.Pinned = builtinDecryption.Pinned
	}
	return p
}

// DecryptionProfile returns the named profile, resolved: one in the
// config, or the built-in default.
func (c *Config) DecryptionProfile(name string) (DecryptionProfile, bool) {
	if name == "" {
		name = DefaultDecryptionProfile
	}
	for _, p := range c.DecryptionProfiles {
		if p.Name == name {
			return p.Resolved(), true
		}
	}
	if name == DefaultDecryptionProfile {
		return builtinDecryption, true
	}
	return DecryptionProfile{}, false
}

// DecryptionExclusion is a named list of server names never decrypted, on
// top of the built-in list: "bank.example" or "*.bank.example" (the name
// and everything under it).
type DecryptionExclusion struct {
	Name    string   `yaml:"name" json:"name"`
	Domains []string `yaml:"domains" json:"domains"`
}

// DecryptionOn reports whether decryption runs (on unless set off).
func (s System) DecryptionOn() bool { return s.Decryption != "off" }

// BuiltinExclusionsOn reports whether the built-in exclusion list applies.
func (s System) BuiltinExclusionsOn() bool { return s.DecryptionBuiltinExclusions != "off" }

// DecryptionActive reports whether any traffic is decrypted: decryption on
// and some rule decrypts.
func (c *Config) DecryptionActive() bool {
	if !c.System.DecryptionOn() {
		return false
	}
	for _, r := range c.DecryptionRules {
		if r.Action == DecryptAction {
			return true
		}
	}
	return false
}

var serverNameRE = regexp.MustCompile(`^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// ValidDomain reports whether s is a server name pattern: a host name, or
// *. and a host name. Lower case only.
func ValidDomain(s string) bool {
	return len(s) <= 253 && serverNameRE.MatchString(s) && strings.Trim(s, "*.") != ""
}

func (v *validator) decryption(c *Config, zones, addrs map[string]bool) {
	for _, f := range []struct{ path, val string }{
		{"system.decryption", c.System.Decryption},
		{"system.decryption_builtin_exclusions", c.System.DecryptionBuiltinExclusions},
	} {
		switch f.val {
		case "", "on", "off":
		default:
			v.add(f.path, "must be on or off, got %q", f.val)
		}
	}
	profiles := map[string]bool{}
	for i, p := range c.DecryptionProfiles {
		path := fmt.Sprintf("decryption_profiles[%d] %q", i, p.Name)
		v.checkName(path, p.Name)
		if profiles[p.Name] {
			v.add(path, "duplicate decryption profile name")
		}
		profiles[p.Name] = true
		check := func(field, val string, ok ...string) {
			if val == "" {
				return
			}
			for _, o := range ok {
				if val == o {
					return
				}
			}
			v.add(path, "%s must be %s, got %q", field, strings.Join(ok, " or "), val)
		}
		check("bad_certificate", p.BadCertificate, DecryptWarn, DecryptBlock)
		check("unsupported", p.Unsupported, DecryptPass, DecryptBlock)
		check("pinned", p.Pinned, DecryptExclude, DecryptBlock)
	}
	excl := map[string]bool{}
	for i, e := range c.DecryptionExclusions {
		path := fmt.Sprintf("decryption_exclusions[%d] %q", i, e.Name)
		v.checkName(path, e.Name)
		if excl[e.Name] {
			v.add(path, "duplicate exclusion name")
		}
		excl[e.Name] = true
		if len(e.Domains) == 0 {
			v.add(path, "domains required, e.g. bank.example or *.bank.example")
		}
		for _, d := range e.Domains {
			if !ValidDomain(d) {
				v.add(path, "%q is not a server name (bank.example or *.bank.example, lower case)", d)
			}
		}
	}
	services := map[string]Service{}
	for _, s := range c.Services {
		services[s.Name] = s
	}
	vrfIface := map[string]bool{}
	for _, in := range c.Interfaces {
		if in.VRFOf() != VRFDefault {
			vrfIface[in.Name] = true
		}
	}
	names := map[string]bool{}
	for i, r := range c.DecryptionRules {
		path := fmt.Sprintf("decryption_rules[%d] %q", i, r.Name)
		v.checkName(path, r.Name)
		if names[r.Name] {
			v.add(path, "duplicate decryption rule name")
		}
		names[r.Name] = true
		v.refs(path, "from", r.From, "zone", func(s string) bool { return zones[s] })
		v.refs(path, "to", r.To, "zone", func(s string) bool { return zones[s] })
		v.refs(path, "source", r.Source, "address or group", func(s string) bool { return addrs[s] })
		v.refs(path, "destination", r.Destination, "address or group", func(s string) bool { return addrs[s] })
		v.refs(path, "service", r.Service, "service", func(s string) bool { _, ok := services[s]; return ok })
		for _, s := range r.Service {
			if svc, ok := services[s]; ok && svc.Protocol != "tcp" {
				v.add(path, "service %q is %s: TLS decryption covers TCP services only", s, svc.Protocol)
			}
		}
		switch r.Action {
		case DecryptAction, NoDecryptAction:
		default:
			v.add(path, "action must be decrypt or no-decrypt, got %q", r.Action)
		}
		if _, ok := c.DecryptionProfile(r.ProfileOf()); !ok {
			v.add(path, "unknown decryption profile %q", r.Profile)
		}
		// Decryption works in the default VRF only for now.
		for _, z := range append(append([]string{}, r.From...), r.To...) {
			for _, in := range c.Interfaces {
				if in.Zone == z && vrfIface[in.Name] {
					v.add(path, "zone %q has interface %s in vrf %s: decryption covers the default vrf only in this release", z, in.Name, in.VRFOf())
				}
			}
		}
	}
}
