// Package logs reads the appliance's two logs from the systemd journal:
//
//   - traffic (data plane): kernel log lines written by rules with log: yes,
//     prefixed "ngfw <rule> <action> " by the compiler;
//   - system (management): ngfwd's own events (commits, logins, tags,
//     upgrades, routes), sshd and the upgrade and first-boot units.
package logs

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
)

// MaxEntries caps one query.
const MaxEntries = 1000

// Traffic is one data-plane log entry for a rule with logging on: the start
// of a connection (its first packet, from the kernel log), or its end
// (from appidd, with the application, bytes, packets and duration; allowed
// connections only).
type Traffic struct {
	Time     time.Time `json:"time"`
	Type     string    `json:"type"` // start or end
	Rule     string    `json:"rule"`
	Action   string    `json:"action"`
	FromZone string    `json:"from,omitempty"` // zone of In, by the running config
	ToZone   string    `json:"to,omitempty"`   // zone of Out
	In       string    `json:"in"`
	Out      string    `json:"out"`
	Src      string    `json:"src"`
	Dst      string    `json:"dst"`
	Proto    string    `json:"proto"`
	SPort    int       `json:"sport,omitempty"`
	DPort    int       `json:"dport,omitempty"`
	// App is the application App Identification named (end entries; start entries come
	// before the application is known).
	App      string  `json:"app,omitempty"`
	Category string  `json:"category,omitempty"` // the application's category
	Bytes    int64   `json:"bytes,omitempty"`    // both directions (end entries)
	Packets  int64   `json:"packets,omitempty"`
	Duration float64 `json:"duration,omitempty"` // seconds (end entries)
	Len      int     `json:"len,omitempty"`      // IP packet length
	TTL      int     `json:"ttl,omitempty"`
	Flags    string  `json:"flags,omitempty"` // TCP flags, e.g. "SYN"
	ICMP     string  `json:"icmp,omitempty"`  // ICMP type/code, e.g. "8/0"
	Geo
}

// Column is one traffic log column.
type Column struct {
	Name  string `json:"name"`  // as typed in the CLI
	Title string `json:"title"` // table header
	Help  string `json:"help"`
}

// TrafficColumns are the traffic log's columns, in display order, with a
// short description; the CLI and web UI pick from these names.
var TrafficColumns = []Column{
	{"time", "Time", "when the connection started (start entries) or ended (end entries)"},
	{"type", "Type", "start: the connection's first packet; end: when it closed, with app, bytes and duration"},
	{"rule", "Rule", "the rule it matched"},
	{"action", "Action", "allow, deny or reset"},
	{"from", "From zone", "zone of the ingress interface (by the running config)"},
	{"to", "To zone", "zone of the egress interface"},
	{"in", "In", "ingress interface"},
	{"out", "Out", "egress interface"},
	{"src", "Source", "source address"},
	{"sport", "Src port", "TCP/UDP source port"},
	{"src_country", "Src country", "the source's country (ISO code), from the DB-IP country database"},
	{"src_asn", "Src AS", "the source's autonomous system: number and organisation"},
	{"dst", "Destination", "destination address"},
	{"dport", "Dst port", "TCP/UDP destination port"},
	{"dst_country", "Dst country", "the destination's country (ISO code)"},
	{"dst_asn", "Dst AS", "the destination's autonomous system: number and organisation"},
	{"proto", "Protocol", "tcp, udp, icmp, ..."},
	{"app", "Application", "application (end entries)"},
	{"category", "Category", "the application's category, e.g. Media (end entries)"},
	{"bytes", "Bytes", "bytes in both directions (end entries)"},
	{"packets", "Packets", "packets in both directions (end entries)"},
	{"duration", "Duration", "how long the connection lasted (end entries)"},
	{"len", "Length", "IP packet length in bytes"},
	{"ttl", "TTL", "IP time to live"},
	{"flags", "TCP flags", "e.g. SYN"},
	{"icmp", "ICMP type", "ICMP type/code, e.g. 8/0 (echo request)"},
}

// DefaultTrafficColumns are shown when no columns are chosen.
var DefaultTrafficColumns = []string{"time", "type", "rule", "action", "from", "to", "src", "sport", "src_country", "dst", "dport", "dst_country", "proto", "app", "bytes"}

// Value is the text of one column of t (empty when it has none).
func (t Traffic) Value(col string) string {
	if v, ok := t.Geo.value(col); ok {
		return v
	}
	num := func(n int) string {
		if n == 0 {
			return ""
		}
		return strconv.Itoa(n)
	}
	switch col {
	case "time":
		return t.Time.Format(time.RFC3339)
	case "type":
		return t.Type
	case "category":
		return t.Category
	case "bytes":
		if t.Bytes == 0 {
			return ""
		}
		return strconv.FormatInt(t.Bytes, 10)
	case "packets":
		if t.Packets == 0 {
			return ""
		}
		return strconv.FormatInt(t.Packets, 10)
	case "duration":
		if t.Type != "end" {
			return ""
		}
		return strconv.FormatFloat(t.Duration, 'f', 1, 64) + "s"
	case "rule":
		return t.Rule
	case "action":
		return t.Action
	case "from":
		return t.FromZone
	case "to":
		return t.ToZone
	case "in":
		return t.In
	case "out":
		return t.Out
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
	case "app":
		return t.App
	case "len":
		return num(t.Len)
	case "ttl":
		return num(t.TTL)
	case "flags":
		return t.Flags
	case "icmp":
		return t.ICMP
	}
	return ""
}

// values is every column's text, for queries' bare words.
func (t Traffic) values() []string {
	out := make([]string, 0, len(TrafficColumns))
	for _, c := range TrafficColumns {
		if c.Name != "time" {
			out = append(out, t.Value(c.Name))
		}
	}
	return out
}

// Value is the text of one system log field.
func (s System) Value(col string) string {
	switch col {
	case "source":
		return s.Source
	case "level":
		return s.Level
	case "message":
		return s.Message
	case "fields":
		return s.Fields
	}
	return ""
}

// ParseColumns reads a comma-separated traffic column list, refusing
// unknown names.
func ParseColumns(s string) ([]string, error) { return parseColumns(TrafficColumns, s) }

func parseColumns(cols []Column, s string) ([]string, error) {
	known := map[string]bool{}
	var names []string
	for _, c := range cols {
		known[c.Name] = true
		names = append(names, c.Name)
	}
	var out []string
	for _, c := range strings.Split(s, ",") {
		c = strings.ToLower(strings.TrimSpace(c))
		if c == "" {
			continue
		}
		if !known[c] {
			return nil, fmt.Errorf("unknown column %q; columns: %s", c, strings.Join(names, ","))
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no columns given; columns: %s", strings.Join(names, ","))
	}
	return out, nil
}

// System is one management log entry.
type System struct {
	Time    time.Time `json:"time"`
	Source  string    `json:"source"` // ngfwd, sshd, upgrade, first-boot
	Level   string    `json:"level"`  // info, warn, error
	Message string    `json:"message"`
	Fields  string    `json:"fields,omitempty"` // key=value details
}

// Reader returns the newest entries first, at most n, keeping only those
// containing q (case-insensitive) when q is set.
type Reader interface {
	Traffic(n int, q string) ([]Traffic, error)
	System(n int, q string) ([]System, error)
	Threat(n int, q string) ([]Threat, error)
	Decryption(n int, q string) ([]Decryption, error)
}

// Journal reads with journalctl.
type Journal struct {
	Path string // journalctl binary
	// ZoneOf names the zone of an interface in the running config ("" if
	// none); nil leaves zones out.
	ZoneOf func(iface string) string
	// RuleName names the rule at a position in the running config (App Identification
	// end entries carry the position); nil or "" leaves "rule N".
	RuleName func(idx int) string
	// Geo looks up the country and AS of an address for the entries'
	// Geo fields; nil leaves them empty.
	Geo GeoFunc
	// Run executes journalctl; tests replace it.
	Run func(args ...string) ([]byte, error)
}

func (j Journal) run(args ...string) ([]byte, error) {
	if j.Run != nil {
		return j.Run(args...)
	}
	path := j.Path
	if path == "" {
		path = "journalctl"
	}
	out, err := exec.Command(path, args...).Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("journalctl: %v: %s", err, strings.TrimSpace(string(ee.Stderr)))
		}
		return nil, fmt.Errorf("logs are not available on this system: %w", err)
	}
	return out, nil
}

type entry struct {
	Realtime string `json:"__REALTIME_TIMESTAMP"`
	Message  any    `json:"MESSAGE"` // string, or byte array for non-UTF-8
	Ident    string `json:"SYSLOG_IDENTIFIER"`
	Unit     string `json:"_SYSTEMD_UNIT"`
	Priority string `json:"PRIORITY"`
}

func (e entry) time() time.Time {
	us, _ := strconv.ParseInt(e.Realtime, 10, 64)
	return time.UnixMicro(us).UTC()
}

func (e entry) message() string {
	switch m := e.Message.(type) {
	case string:
		return m
	case []any:
		b := make([]byte, 0, len(m))
		for _, x := range m {
			if f, ok := x.(float64); ok {
				b = append(b, byte(f))
			}
		}
		return string(b)
	}
	return ""
}

func entries(out []byte) []entry {
	var es []entry
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		var e entry
		if json.Unmarshal(sc.Bytes(), &e) == nil {
			es = append(es, e)
		}
	}
	return es
}

func clamp(n int) int {
	if n <= 0 || n > MaxEntries {
		return 200
	}
	return n
}

// Traffic reads data-plane entries.
func (j Journal) Traffic(n int, q string) ([]Traffic, error) {
	query, err := ParseQuery(q, TrafficSchema)
	if err != nil {
		return nil, err
	}
	n = clamp(n)
	// Read more than n lines when filtering, since some won't match.
	want := n
	if q != "" {
		want = MaxEntries * 5
	}
	out, err := j.run("-k", "-o", "json", "--no-pager", "-r", "-n", strconv.Itoa(want), "--grep", "^ngfw ")
	if err != nil {
		// journalctl built without pattern matching: read more kernel lines
		// and filter here instead.
		out, err = j.run("-k", "-o", "json", "--no-pager", "-r", "-n", strconv.Itoa(want*20))
		if err != nil {
			return nil, err
		}
	}
	var res []Traffic
	keep := func(t Traffic) {
		if j.ZoneOf != nil && t.Type == "start" {
			t.FromZone, t.ToZone = j.ZoneOf(t.In), j.ZoneOf(t.Out)
		}
		t.Geo.fill(j.Geo, t.Src, t.Dst)
		if query.Match(t.Value, t.values()) {
			res = append(res, t)
		}
	}
	for _, e := range entries(out) {
		if t, ok := ParseTraffic(e.message()); ok {
			t.Time = e.time()
			keep(t)
		}
	}
	// End entries from appidd (App Identification). Missing on appliances without it.
	sess, err := j.run("-u", "appidd.service", "-o", "json", "--no-pager", "-r", "-n", strconv.Itoa(want), "--grep", "^ngfw-session ")
	if err != nil {
		sess, err = j.run("-u", "appidd.service", "-o", "json", "--no-pager", "-r", "-n", strconv.Itoa(want*2))
	}
	if out := sess; err == nil {
		for _, e := range entries(out) {
			if t, ok := ParseSession(e.message()); ok {
				t.Time = e.time()
				if idx, err := strconv.Atoi(t.Rule); err == nil {
					t.Rule = "rule " + t.Rule
					if j.RuleName != nil {
						if name := j.RuleName(idx); name != "" {
							t.Rule = name
						}
					}
				}
				keep(t)
			}
		}
	}
	res = newestFirst(res, func(i int) time.Time { return res[i].Time })
	if len(res) > n {
		res = res[:n]
	}
	return res, nil
}

// ParseSession reads one appidd end-of-connection line:
// "ngfw-session rule=N app=NAME cat=CAT proto=tcp src=.. sport=.. dst=..
// dport=.. bytes=.. packets=.. dur=SECONDS". Rule is left as the number.
func ParseSession(msg string) (Traffic, bool) {
	f := strings.Fields(strings.TrimSpace(msg))
	if len(f) < 2 || f[0] != "ngfw-session" {
		return Traffic{}, false
	}
	t := Traffic{Type: "end", Action: "allow"}
	kv := map[string]string{}
	last := ""
	for _, w := range f[1:] {
		k, v, ok := strings.Cut(w, "=")
		if !ok && last != "" { // a value with spaces (an app name)
			kv[last] += " " + w
			continue
		}
		kv[k], last = v, k
	}
	if _, ok := kv["rule"]; !ok {
		return Traffic{}, false
	}
	t.Rule, t.App, t.Category, t.Proto, t.Src, t.Dst = kv["rule"], kv["app"], kv["cat"], kv["proto"], kv["src"], kv["dst"]
	t.SPort, _ = strconv.Atoi(kv["sport"])
	t.DPort, _ = strconv.Atoi(kv["dport"])
	t.Bytes, _ = strconv.ParseInt(kv["bytes"], 10, 64)
	t.Packets, _ = strconv.ParseInt(kv["packets"], 10, 64)
	t.Duration, _ = strconv.ParseFloat(kv["dur"], 64)
	return t, true
}

// ParseTraffic reads one "ngfw <rule> <action> IN=... SRC=..." kernel line.
func ParseTraffic(msg string) (Traffic, bool) {
	msg = strings.TrimSpace(msg)
	f := strings.Fields(msg)
	if len(f) < 3 || f[0] != "ngfw" {
		return Traffic{}, false
	}
	t := Traffic{Type: "start", Rule: f[1], Action: f[2]}
	var flags []string
	icmpType, icmpCode := "", ""
	for _, kv := range f[3:] {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			// TCP flags are bare words after the ports.
			switch kv {
			case "CWR", "ECE", "URG", "ACK", "PSH", "RST", "SYN", "FIN":
				flags = append(flags, kv)
			}
			continue
		}
		switch k {
		case "LEN":
			if t.Len == 0 { // the first LEN is the IP length; UDP repeats it
				t.Len, _ = strconv.Atoi(v)
			}
		case "TTL":
			t.TTL, _ = strconv.Atoi(v)
		case "TYPE":
			if icmpType == "" {
				icmpType = v
			}
		case "CODE":
			if icmpCode == "" {
				icmpCode = v
			}
		case "IN":
			t.In = v
		case "OUT":
			t.Out = v
		case "SRC":
			t.Src = v
		case "DST":
			t.Dst = v
		case "PROTO":
			t.Proto = strings.ToLower(v)
		case "SPT":
			t.SPort, _ = strconv.Atoi(v)
		case "DPT":
			t.DPort, _ = strconv.Atoi(v)
		}
	}
	if t.Proto == "" {
		t.Proto = "other"
	}
	if t.Proto == "tcp" {
		t.Flags = strings.Join(flags, " ")
	}
	if t.Proto == "icmp" && icmpType != "" {
		t.ICMP = icmpType + "/" + icmpCode
	}
	return t, true
}

// System reads management entries.
func (j Journal) System(n int, q string) ([]System, error) {
	query, err := ParseQuery(q, SystemSchema)
	if err != nil {
		return nil, err
	}
	n = clamp(n)
	want := n
	if q != "" {
		want = MaxEntries * 5
	}
	out, err := j.run("-o", "json", "--no-pager", "-r", "-n", strconv.Itoa(want),
		"-u", "ngfwd.service", "-u", "ssh.service", "-u", "sjb-upgrade.service", "-u", "ngfw-firstboot.service", "-u", "kea-dhcp4-server.service")
	if err != nil {
		return nil, err
	}
	var res []System
	for _, e := range entries(out) {
		s := parseSystem(e)
		if s.Message == "" {
			continue
		}
		if !query.Match(s.Value, []string{s.Source, s.Level, s.Message, s.Fields}) {
			continue
		}
		res = append(res, s)
		if len(res) == n {
			break
		}
	}
	return newestFirst(res, func(i int) time.Time { return res[i].Time }), nil
}

func parseSystem(e entry) System {
	msg := strings.TrimSpace(e.message())
	s := System{Time: e.time(), Level: priority(e.Priority)}
	switch {
	case strings.HasPrefix(e.Unit, "ngfwd") || e.Ident == "ngfwd":
		s.Source = "ngfwd"
	case strings.HasPrefix(e.Unit, "ssh") || e.Ident == "sshd" || strings.HasPrefix(e.Ident, "sshd"):
		s.Source = "sshd"
	case strings.HasPrefix(e.Unit, "sjb-upgrade") || e.Ident == "fwctl":
		s.Source = "upgrade"
	case strings.HasPrefix(e.Unit, "ngfw-firstboot"):
		s.Source = "first-boot"
	case strings.HasPrefix(e.Unit, "kea-dhcp4"):
		s.Source = "dhcp"
	case e.Ident != "":
		s.Source = e.Ident
	default:
		s.Source = "system"
	}
	// ngfwd logs in logfmt: time=... level=INFO msg="commit" key=value...
	if s.Source == "ngfwd" && strings.Contains(msg, "msg=") {
		kv := logfmt(msg)
		if lvl := strings.ToLower(kv.get("level")); lvl != "" {
			s.Level = map[string]string{"warn": "warn", "error": "error", "debug": "info"}[lvl]
			if s.Level == "" {
				s.Level = "info"
			}
		}
		s.Message = kv.get("msg")
		var rest []string
		for _, p := range kv {
			if p.k != "time" && p.k != "level" && p.k != "msg" {
				rest = append(rest, p.k+"="+p.v)
			}
		}
		s.Fields = strings.Join(rest, " ")
		return s
	}
	s.Message = msg
	return s
}

func priority(p string) string {
	switch p {
	case "0", "1", "2", "3":
		return "error"
	case "4":
		return "warn"
	}
	return "info"
}

type pair struct{ k, v string }
type pairs []pair

func (ps pairs) get(k string) string {
	for _, p := range ps {
		if p.k == k {
			return p.v
		}
	}
	return ""
}

// logfmt splits key=value pairs; values may be "quoted with \" escapes".
func logfmt(s string) pairs {
	var out pairs
	i := 0
	for i < len(s) {
		for i < len(s) && s[i] == ' ' {
			i++
		}
		eq := strings.IndexByte(s[i:], '=')
		if eq < 0 {
			break
		}
		k := s[i : i+eq]
		i += eq + 1
		var v string
		if i < len(s) && s[i] == '"' {
			j := i + 1
			var b strings.Builder
			for j < len(s) && s[j] != '"' {
				if s[j] == '\\' && j+1 < len(s) {
					j++
				}
				b.WriteByte(s[j])
				j++
			}
			v = b.String()
			i = j + 1
		} else {
			j := strings.IndexByte(s[i:], ' ')
			if j < 0 {
				j = len(s) - i
			}
			v = s[i : i+j]
			i += j
		}
		out = append(out, pair{k, v})
	}
	return out
}

func newestFirst[T any](s []T, t func(int) time.Time) []T {
	sort.SliceStable(s, func(i, j int) bool { return t(i).After(t(j)) })
	return s
}
