package config

import (
	"fmt"
	"sort"
	"strconv"
)

// IPS severities, most severe first. They are ET Open's signature_severity
// levels.
var IPSSeverities = []string{"critical", "major", "minor", "informational"}

// IPS actions a profile assigns to a severity.
const (
	IPSBlock  = "block"  // drop the packet and the rest of the connection; log
	IPSAlert  = "alert"  // let it through; log
	IPSIgnore = "ignore" // let it through; don't log
)

// IPSException stops one signature (SID) from blocking for some of the
// traffic the IPS inspects: connections of the named rules, from the
// source addresses (the connection's client) and/or to the destination
// addresses (its server's inside address, as rules name it). Every field
// given must match; at least one of rules, source and destination is
// needed (ips_disabled_signatures turns a signature off everywhere).
// Action alert (the default) still logs the match in the threat log,
// marked with the exception's name; ignore doesn't.
type IPSException struct {
	Name        string   `yaml:"name" json:"name"`
	SID         string   `yaml:"sid" json:"sid"`
	Rules       []string `yaml:"rules,omitempty" json:"rules"`
	Source      []string `yaml:"source,omitempty" json:"source"`
	Destination []string `yaml:"destination,omitempty" json:"destination"`
	Action      string   `yaml:"action,omitempty" json:"action"` // alert (default) or ignore
}

// ActionOf is the exception's action: alert unless set to ignore.
func (e IPSException) ActionOf() string {
	if e.Action == IPSIgnore {
		return IPSIgnore
	}
	return IPSAlert
}

// SIDNumber is the exception's signature ID (0 if it isn't a number).
func (e IPSException) SIDNumber() int {
	n, err := strconv.ParseUint(e.SID, 10, 32)
	if err != nil {
		return 0
	}
	return int(n)
}

// MaxIPSExceptionSIDs is how many different signatures exceptions can
// name: each gets a code in the packet mark (see internal/compiler).
const MaxIPSExceptionSIDs = 35

// IPSExceptionSIDs lists the signatures exceptions name, in numeric order.
func (c *Config) IPSExceptionSIDs() []int {
	seen := map[int]bool{}
	var out []int
	for _, e := range c.IPSExceptions {
		if n := e.SIDNumber(); n != 0 && !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	sort.Ints(out)
	return out
}

// DefaultIPSProfile is the built-in profile name; a config may redefine it.
const DefaultIPSProfile = "default"

// IPSProfile says what to do when a signature of each severity matches
// traffic of a rule that names the profile. An empty action takes the
// default profile's.
type IPSProfile struct {
	Name          string `yaml:"name" json:"name"`
	Critical      string `yaml:"critical,omitempty" json:"critical"`
	Major         string `yaml:"major,omitempty" json:"major"`
	Minor         string `yaml:"minor,omitempty" json:"minor"`
	Informational string `yaml:"informational,omitempty" json:"informational"`
}

// builtinIPS is the default profile: block critical and major, alert on
// minor, ignore informational.
var builtinIPS = IPSProfile{Name: DefaultIPSProfile, Critical: IPSBlock, Major: IPSBlock, Minor: IPSAlert, Informational: IPSIgnore}

// Action returns the profile's action for a severity, falling back to the
// built-in default's.
func (p IPSProfile) Action(severity string) string {
	get := func(q IPSProfile) string {
		switch severity {
		case "critical":
			return q.Critical
		case "major":
			return q.Major
		case "minor":
			return q.Minor
		default:
			return q.Informational
		}
	}
	if a := get(p); a != "" {
		return a
	}
	return get(builtinIPS)
}

// IPSProfile returns the named profile: one in the config, or the built-in
// default.
func (c *Config) IPSProfile(name string) (IPSProfile, bool) {
	for _, p := range c.IPSProfiles {
		if p.Name == name {
			return p, true
		}
	}
	if name == DefaultIPSProfile {
		return builtinIPS, true
	}
	return IPSProfile{}, false
}

// IPSOn reports whether IPS inspection runs (on unless set off).
func (s System) IPSOn() bool { return s.IPS != "off" }

// IPSRules reports whether any rule names an IPS profile.
func (c *Config) IPSRules() bool {
	for _, r := range c.Rules {
		if r.IPSProfile != "" && r.Action == "allow" {
			return true
		}
	}
	return false
}

// IPSActive reports whether the IPS engine should run: on, and in use.
func (c *Config) IPSActive() bool { return c.System.IPSOn() && c.IPSRules() }

func (v *validator) ips(c *Config) {
	switch c.System.IPS {
	case "", "on", "off":
	default:
		v.add("system.ips", "must be on or off, got %q", c.System.IPS)
	}
	for i, s := range c.System.IPSDisabledSignatures {
		if n, err := strconv.ParseUint(s, 10, 32); err != nil || n == 0 {
			v.add(fmt.Sprintf("system.ips_disabled_signatures[%d]", i), "%q is not a signature ID (a number)", s)
		}
	}
	names := map[string]bool{}
	for i, p := range c.IPSProfiles {
		path := fmt.Sprintf("ips_profiles[%d] %q", i, p.Name)
		v.checkName(path, p.Name)
		if names[p.Name] {
			v.add(path, "duplicate IPS profile name")
		}
		names[p.Name] = true
		for _, f := range []struct{ sev, act string }{{"critical", p.Critical}, {"major", p.Major}, {"minor", p.Minor}, {"informational", p.Informational}} {
			switch f.act {
			case "", IPSBlock, IPSAlert, IPSIgnore:
			default:
				v.add(path, "%s must be block, alert or ignore, got %q", f.sev, f.act)
			}
		}
	}
	for i, r := range c.Rules {
		if r.IPSProfile == "" {
			continue
		}
		path := fmt.Sprintf("rules[%d] %q", i, r.Name)
		if r.Action != "allow" {
			v.add(path, "ips_profile applies to allow rules only (this one is %s)", r.Action)
		}
		if _, ok := c.IPSProfile(r.IPSProfile); !ok {
			v.add(path, "unknown IPS profile %q", r.IPSProfile)
		}
	}
}

func (v *validator) ipsExceptions(c *Config, addrs map[string]bool) {
	names := map[string]bool{}
	for i, e := range c.IPSExceptions {
		p := fmt.Sprintf("ips_exceptions[%d] %q", i, e.Name)
		v.checkName(p, e.Name)
		if names[e.Name] {
			v.add(p, "duplicate IPS exception name")
		}
		names[e.Name] = true
		if e.SIDNumber() == 0 {
			v.add(p, "sid must be a signature ID (a number, as the threat log shows it), got %q", e.SID)
		}
		if len(e.Rules) == 0 && len(e.Source) == 0 && len(e.Destination) == 0 {
			v.add(p, "give rules, source or destination (to turn the signature off everywhere, use system ips_disabled_signatures)")
		}
		for _, name := range e.Rules {
			found := false
			for _, r := range c.Rules {
				if r.Name != name {
					continue
				}
				found = true
				if r.Action != "allow" || r.IPSProfile == "" {
					v.add(p, "rules: rule %q has no ips_profile, so the IPS doesn't inspect its traffic", name)
				}
			}
			if !found {
				v.add(p, "rules: unknown rule %q", name)
			}
		}
		for _, f := range []struct {
			field string
			vals  []string
		}{{"source", e.Source}, {"destination", e.Destination}} {
			for _, s := range f.vals {
				if s == Any {
					v.add(p, "%s: leave it out rather than %q", f.field, Any)
				} else if !addrs[s] {
					v.add(p, "%s: unknown address or group %q", f.field, s)
				}
			}
		}
		switch e.Action {
		case "", IPSAlert, IPSIgnore:
		default:
			v.add(p, "action must be alert or ignore, got %q", e.Action)
		}
	}
	if n := len(c.IPSExceptionSIDs()); n > MaxIPSExceptionSIDs {
		v.add("ips_exceptions", "name %d different signatures; at most %d can have exceptions", n, MaxIPSExceptionSIDs)
	}
}
