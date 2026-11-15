package config

import (
	"fmt"
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
