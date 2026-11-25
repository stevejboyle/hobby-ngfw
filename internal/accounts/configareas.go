package accounts

import (
	"fmt"
	"reflect"
	"slices"
	"strings"

	"github.com/stevejboyle/sjb-os/internal/config"
)

// configFieldArea maps each top-level config section (by Go field name) to
// its area. The system section is split by field (systemFieldArea). A test
// fails when a config field has no entry, so new config can't skip the
// access check.
var configFieldArea = map[string]Area{
	"Zones":                Policy,
	"Interfaces":           Network,
	"Addresses":            Policy,
	"AddressGroups":        Policy,
	"Services":             Policy,
	"Rules":                Policy,
	"ApplicationGroups":    Policy,
	"NAT":                  Policy,
	"Routes":               Network,
	"VRFs":                 Network,
	"Routing":              Network,
	"BGPNeighbors":         Network,
	"OSPFInterfaces":       Network,
	"PrefixLists":          Network,
	"DHCPServers":          DHCP,
	"DHCPReservations":     DHCP,
	"IPSProfiles":          IPS,
	"IPSExceptions":        IPS,
	"DecryptionRules":      Decryption,
	"DecryptionProfiles":   Decryption,
	"DecryptionExclusions": Decryption,
	"LogServers":           Logging,
	"SNMP":                 Logging,
	"SNMPTrapReceivers":    Logging,
}

var systemFieldArea = map[string]Area{
	"Hostname":                    Network,
	"MgmtInterface":               Network,
	"AppID":                       Policy,
	"IPS":                         IPS,
	"IPSDisabledSignatures":       IPS,
	"Decryption":                  Decryption,
	"DecryptionBuiltinExclusions": Decryption,
}

// ChangedAreas returns the config areas whose sections differ between two
// configs (YAML), in Areas order. A config that doesn't parse counts as
// touching every config area.
func ChangedAreas(from, to []byte) []Area {
	a, errA := parseLoose(from)
	b, errB := parseLoose(to)
	if errA != nil || errB != nil {
		return slices.Clone(ConfigAreas)
	}
	set := map[Area]bool{}
	va, vb := reflect.ValueOf(a).Elem(), reflect.ValueOf(b).Elem()
	t := va.Type()
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.Name == "System" {
			sa, sb := va.Field(i), vb.Field(i)
			for j := 0; j < sa.NumField(); j++ {
				if !equalish(sa.Field(j), sb.Field(j)) {
					set[systemArea(sa.Type().Field(j).Name)] = true
				}
			}
			continue
		}
		if !equalish(va.Field(i), vb.Field(i)) {
			set[fieldArea(f.Name)] = true
		}
	}
	var out []Area
	for _, ai := range Areas {
		if set[ai.Area] {
			out = append(out, ai.Area)
		}
	}
	return out
}

// fieldArea and systemArea fall back to Network (and a test fails) for a
// field nobody mapped.
func fieldArea(name string) Area {
	if a, ok := configFieldArea[name]; ok {
		return a
	}
	return Network
}

func systemArea(name string) Area {
	if a, ok := systemFieldArea[name]; ok {
		return a
	}
	return Network
}

// equalish treats nil and empty slices as equal.
func equalish(a, b reflect.Value) bool {
	if a.Kind() == reflect.Slice && a.Len() == 0 && b.Len() == 0 {
		return true
	}
	return reflect.DeepEqual(a.Interface(), b.Interface())
}

func parseLoose(data []byte) (*config.Config, error) {
	if strings.TrimSpace(string(data)) == "" {
		return &config.Config{}, nil
	}
	return config.Parse(data)
}

// CheckConfigChange returns ErrForbidden unless p may change every config
// area that differs between from and to. what names the action ("commit",
// "edit") for the message.
func (p Principal) CheckConfigChange(what string, from, to []byte) error {
	var missing []string
	for _, a := range ChangedAreas(from, to) {
		if !p.Can(a, Change) {
			missing = append(missing, string(a))
		}
	}
	if len(missing) == 0 {
		return nil
	}
	return fmt.Errorf("%w: this %s changes %s, which role %s can't change (%s)", ErrForbidden, what,
		strings.Join(missing, ", "), p.Role.Name, p.Name)
}
