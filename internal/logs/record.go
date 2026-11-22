package logs

import (
	"encoding/json"
	"strconv"
	"strings"
)

// Record kinds, as the log forwarder names them.
const (
	KindTraffic    = "traffic"
	KindThreat     = "threat"
	KindDecryption = "decryption"
	KindSystem     = "system"
)

// SystemUnits are the units whose journals make up the system log.
var SystemUnits = []string{"ngfwd.service", "ssh.service", "sjb-upgrade.service", "ngfw-firstboot.service", "kea-dhcp4-server.service"}

// FollowMatches are journalctl match arguments (OR-ed with "+") that select
// every record ParseRecord can turn into a log entry.
func FollowMatches() []string {
	units := append([]string{"appidd.service", TLSDUnit}, SystemUnits...)
	out := []string{"_TRANSPORT=kernel"}
	for _, u := range units {
		out = append(out, "+", "_SYSTEMD_UNIT="+u)
	}
	return out
}

// Record is one journal record turned into a log entry: Entry is a
// Traffic, Threat, Decryption or System value.
type Record struct {
	Kind  string
	Entry any
	// Cursor is the journal's position of the record (__CURSOR).
	Cursor string
}

type recordEntry struct {
	entry
	Cursor    string `json:"__CURSOR"`
	Transport string `json:"_TRANSPORT"`
}

// ParseRecord reads one line of `journalctl -o json` output. ok is false
// for records that belong to no log (other kernel messages, appidd's own
// diagnostics); their Cursor is still set. Traffic entries get zones and rule names like the Logs
// views (j.ZoneOf, j.RuleName).
func (j Journal) ParseRecord(line []byte) (Record, bool) {
	var e recordEntry
	if json.Unmarshal(line, &e) != nil {
		return Record{}, false
	}
	msg := e.message()
	r := Record{Cursor: e.Cursor}
	skip := Record{Cursor: e.Cursor}
	switch {
	case e.Transport == "kernel":
		t, ok := ParseTraffic(msg)
		if !ok {
			return skip, false
		}
		t.Time = e.time()
		if j.ZoneOf != nil {
			t.FromZone, t.ToZone = j.ZoneOf(t.In), j.ZoneOf(t.Out)
		}
		r.Kind, r.Entry = KindTraffic, t
	case strings.HasPrefix(e.Unit, "appidd"):
		t, ok := ParseSession(msg)
		if !ok {
			return skip, false
		}
		t.Time = e.time()
		if idx, err := strconv.Atoi(t.Rule); err == nil {
			t.Rule = "rule " + t.Rule
			if j.RuleName != nil {
				if name := j.RuleName(idx); name != "" {
					t.Rule = name
				}
			}
		}
		r.Kind, r.Entry = KindTraffic, t
	case e.Unit == TLSDUnit:
		d, ok := ParseDecryption(msg)
		if !ok {
			return skip, false
		}
		if d.Time.IsZero() {
			d.Time = e.time()
		}
		r.Kind, r.Entry = KindDecryption, d
	default:
		if t, ok := ParseThreat(msg); ok {
			if t.Time.IsZero() {
				t.Time = e.time()
			}
			r.Kind, r.Entry = KindThreat, t
			break
		}
		s := parseSystem(e.entry)
		if s.Message == "" {
			return skip, false
		}
		r.Kind, r.Entry = KindSystem, s
	}
	return r, true
}
