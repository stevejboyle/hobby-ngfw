package logs

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

// ThreatPrefix starts each threat line ngfwd writes to its journal,
// followed by the Threat as JSON.
const ThreatPrefix = "ngfw-threat "

// Threat is one IPS signature match on a rule's traffic.
type Threat struct {
	Time      time.Time `json:"time"`
	Rule      string    `json:"rule"`
	Profile   string    `json:"profile"`
	Action    string    `json:"action"`   // block or alert
	Severity  string    `json:"severity"` // critical, major, minor, informational
	SID       int       `json:"sid"`
	Signature string    `json:"signature"`
	Category  string    `json:"category"` // the signature's class, e.g. "Attempted Administrator Privilege Gain"
	App       string    `json:"app,omitempty"`
	Proto     string    `json:"proto"`
	Src       string    `json:"src"`
	SPort     int       `json:"sport,omitempty"`
	Dst       string    `json:"dst"`
	DPort     int       `json:"dport,omitempty"`
}

// Line is the journal line for t.
func (t Threat) Line() string {
	b, _ := json.Marshal(t)
	return ThreatPrefix + string(b)
}

// ParseThreat reads a line written by Line.
func ParseThreat(msg string) (Threat, bool) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(msg), ThreatPrefix)
	if !ok {
		return Threat{}, false
	}
	var t Threat
	if json.Unmarshal([]byte(rest), &t) != nil || t.SID == 0 {
		return Threat{}, false
	}
	return t, true
}

// ThreatColumns are the threat log's columns, in display order.
var ThreatColumns = []Column{
	{"time", "Time", "when the signature matched"},
	{"rule", "Rule", "the rule whose traffic it was"},
	{"profile", "Profile", "the rule's IPS profile"},
	{"action", "Action", "block (packet and connection dropped) or alert (let through)"},
	{"severity", "Severity", "critical, major, minor or informational"},
	{"sid", "SID", "signature ID (ips_disabled_signatures takes these)"},
	{"signature", "Signature", "what the signature detects"},
	{"category", "Category", "the signature's class"},
	{"app", "Application", "application, when known"},
	{"src", "Source", "source address"},
	{"sport", "Src port", "source port"},
	{"dst", "Destination", "destination address"},
	{"dport", "Dst port", "destination port"},
	{"proto", "Protocol", "tcp, udp, ..."},
}

// DefaultThreatColumns are shown when no columns are chosen.
var DefaultThreatColumns = []string{"time", "rule", "action", "severity", "sid", "signature", "src", "sport", "dst", "dport", "app"}

// ThreatSchema is the threat log's query fields.
var ThreatSchema = Schema{
	"rule":      {kText, []string{"rule"}, "rule name"},
	"profile":   {kText, []string{"profile"}, "IPS profile"},
	"action":    {kText, []string{"action"}, "block or alert"},
	"severity":  {kText, []string{"severity"}, "critical, major, minor, informational"},
	"sid":       {kNum, []string{"sid"}, "signature ID"},
	"signature": {kText, []string{"signature"}, "signature text, e.g. signature ~ trojan"},
	"category":  {kText, []string{"category"}, "signature class"},
	"app":       {kText, []string{"app"}, "application"},
	"src":       {kAddr, []string{"src"}, "source address or CIDR"},
	"dst":       {kAddr, []string{"dst"}, "destination address or CIDR"},
	"addr":      {kAddr, []string{"src", "dst"}, "either address"},
	"sport":     {kNum, []string{"sport"}, "source port"},
	"dport":     {kNum, []string{"dport"}, "destination port"},
	"port":      {kNum, []string{"sport", "dport"}, "either port"},
	"proto":     {kText, []string{"proto"}, "tcp, udp, ..."},
}

// Value is the text of one column of t.
func (t Threat) Value(col string) string {
	num := func(n int) string {
		if n == 0 {
			return ""
		}
		return strconv.Itoa(n)
	}
	switch col {
	case "time":
		return t.Time.Format(time.RFC3339)
	case "rule":
		return t.Rule
	case "profile":
		return t.Profile
	case "action":
		return t.Action
	case "severity":
		return t.Severity
	case "sid":
		return num(t.SID)
	case "signature":
		return t.Signature
	case "category":
		return t.Category
	case "app":
		return t.App
	case "src":
		return t.Src
	case "sport":
		return num(t.SPort)
	case "dst":
		return t.Dst
	case "dport":
		return num(t.DPort)
	case "proto":
		return t.Proto
	}
	return ""
}

func (t Threat) values() []string {
	out := make([]string, 0, len(ThreatColumns))
	for _, c := range ThreatColumns {
		if c.Name != "time" {
			out = append(out, t.Value(c.Name))
		}
	}
	return out
}

// ParseThreatColumns reads a comma-separated threat column list.
func ParseThreatColumns(s string) ([]string, error) { return parseColumns(ThreatColumns, s) }

// Threat reads IPS entries, newest first.
func (j Journal) Threat(n int, q string) ([]Threat, error) {
	query, err := ParseQuery(q, ThreatSchema)
	if err != nil {
		return nil, err
	}
	n = clamp(n)
	want := n
	if q != "" {
		want = MaxEntries * 5
	}
	out, err := j.run("-u", "ngfwd.service", "-o", "json", "--no-pager", "-r", "-n", strconv.Itoa(want), "--grep", "^"+strings.TrimSpace(ThreatPrefix)+" ")
	if err != nil {
		out, err = j.run("-u", "ngfwd.service", "-o", "json", "--no-pager", "-r", "-n", strconv.Itoa(want*5))
		if err != nil {
			return nil, err
		}
	}
	var res []Threat
	for _, e := range entries(out) {
		if t, ok := ParseThreat(e.message()); ok {
			if t.Time.IsZero() {
				t.Time = e.time()
			}
			if query.Match(t.Value, t.values()) {
				res = append(res, t)
			}
		}
	}
	res = newestFirst(res, func(i int) time.Time { return res[i].Time })
	if len(res) > n {
		res = res[:n]
	}
	return res, nil
}
