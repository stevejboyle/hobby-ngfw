package logs

import (
	"strings"
	"testing"
)

const kernel = `{"__REALTIME_TIMESTAMP":"1794300000000000","MESSAGE":"ngfw allow-web allow IN=inside OUT=outside MAC=52:54:00:12:34:57 SRC=10.10.1.50 DST=93.184.216.34 LEN=60 TTL=63 ID=1 DF PROTO=TCP SPT=40000 DPT=443 WINDOW=64240 SYN URGP=0 ","SYSLOG_IDENTIFIER":"kernel"}
{"__REALTIME_TIMESTAMP":"1794300005000000","MESSAGE":"ngfw block-quarantined deny IN=inside OUT=outside SRC=10.10.1.66 DST=1.1.1.1 LEN=84 PROTO=ICMP TYPE=8 CODE=0 ID=7 SEQ=1 ","SYSLOG_IDENTIFIER":"kernel"}
{"__REALTIME_TIMESTAMP":"1794300006000000","MESSAGE":"not ours at all","SYSLOG_IDENTIFIER":"kernel"}
not json
`

const system = `{"__REALTIME_TIMESTAMP":"1794300010000000","MESSAGE":"time=2026-11-10T12:00:10Z level=INFO msg=commit revision=4 author=web:admin message=\"allow \\\"ssh\\\" out\" confirm=5m0s","_SYSTEMD_UNIT":"ngfwd.service","SYSLOG_IDENTIFIER":"ngfwd","PRIORITY":"6"}
{"__REALTIME_TIMESTAMP":"1794300011000000","MESSAGE":"time=2026-11-10T12:00:11Z level=WARN msg=\"web login failed\" user=admin from=192.0.2.9","_SYSTEMD_UNIT":"ngfwd.service","SYSLOG_IDENTIFIER":"ngfwd","PRIORITY":"6"}
{"__REALTIME_TIMESTAMP":"1794300012000000","MESSAGE":"Accepted password for admin from 10.0.2.2 port 51000 ssh2","_SYSTEMD_UNIT":"ssh.service","SYSLOG_IDENTIFIER":"sshd-session","PRIORITY":"6"}
{"__REALTIME_TIMESTAMP":"1794300013000000","MESSAGE":"upgrading SJB-OS 0.6.1 -> 0.6.1-r01","_SYSTEMD_UNIT":"sjb-upgrade.service","SYSLOG_IDENTIFIER":"fwctl","PRIORITY":"6"}
{"__REALTIME_TIMESTAMP":"1794300014000000","MESSAGE":[80,97,112,101,114,115,44,32,112,108,101,97,115,101],"_SYSTEMD_UNIT":"ssh.service","SYSLOG_IDENTIFIER":"sshd","PRIORITY":"3"}
{"__REALTIME_TIMESTAMP":"1794300015000000","MESSAGE":"DHCP4_LEASE_ALLOC lease 10.10.1.100 has been allocated","_SYSTEMD_UNIT":"kea-dhcp4-server.service","SYSLOG_IDENTIFIER":"kea-dhcp4","PRIORITY":"6"}
`

func fake(out string, got *[]string) Journal {
	return Journal{Run: func(args ...string) ([]byte, error) {
		*got = args
		return []byte(out), nil
	}}
}

func TestTraffic(t *testing.T) {
	var args []string
	tr, err := fake(kernel, &args).Traffic(10, "")
	if err != nil {
		t.Fatal(err)
	}
	if a := strings.Join(args, " "); !strings.Contains(a, "-u appidd.service") || !strings.Contains(a, "--grep ^ngfw-session ") {
		t.Fatalf("journalctl args (last call, appidd): %v", args)
	}
	if len(tr) != 2 {
		t.Fatalf("entries: %+v", tr)
	}
	// Newest first.
	if tr[0].Rule != "block-quarantined" || tr[0].Action != "deny" || tr[0].Proto != "icmp" || tr[0].DPort != 0 {
		t.Fatalf("icmp entry: %+v", tr[0])
	}
	w := tr[1]
	if w.Rule != "allow-web" || w.In != "inside" || w.Out != "outside" || w.Src != "10.10.1.50" || w.Dst != "93.184.216.34" ||
		w.Proto != "tcp" || w.SPort != 40000 || w.DPort != 443 || w.Time.Unix() != 1794300000 {
		t.Fatalf("tcp entry: %+v", w)
	}
	if tr, _ := fake(kernel, &args).Traffic(10, "QUARANTINE"); len(tr) != 1 || tr[0].Src != "10.10.1.66" {
		t.Fatalf("filter: %+v", tr)
	}
	if tr, _ := fake(kernel, &args).Traffic(1, ""); len(tr) != 1 {
		t.Fatalf("limit: %+v", tr)
	}
}

func TestSystem(t *testing.T) {
	var args []string
	s, err := fake(system, &args).System(50, "")
	if err != nil {
		t.Fatal(err)
	}
	if a := strings.Join(args, " "); !strings.Contains(a, "-u ngfwd.service") || !strings.Contains(a, "-u ssh.service") {
		t.Fatalf("args: %s", a)
	}
	if len(s) != 6 {
		t.Fatalf("entries: %+v", s)
	}
	byMsg := map[string]System{}
	for _, e := range s {
		byMsg[e.Message] = e
	}
	c := byMsg["commit"]
	if c.Source != "ngfwd" || c.Level != "info" || !strings.Contains(c.Fields, "author=web:admin") || !strings.Contains(c.Fields, `message=allow "ssh" out`) {
		t.Fatalf("commit entry: %+v", c)
	}
	if w := byMsg["web login failed"]; w.Level != "warn" || !strings.Contains(w.Fields, "from=192.0.2.9") {
		t.Fatalf("warn entry: %+v", w)
	}
	if e := byMsg["Accepted password for admin from 10.0.2.2 port 51000 ssh2"]; e.Source != "sshd" {
		t.Fatalf("sshd entry: %+v", e)
	}
	if e := byMsg["upgrading SJB-OS 0.6.1 -> 0.6.1-r01"]; e.Source != "upgrade" {
		t.Fatalf("upgrade entry: %+v", e)
	}
	if e := byMsg["DHCP4_LEASE_ALLOC lease 10.10.1.100 has been allocated"]; e.Source != "dhcp" {
		t.Fatalf("kea entry: %+v", e)
	}
	if !strings.Contains(strings.Join(args, " "), "-u kea-dhcp4-server.service") {
		t.Fatalf("journalctl args: %q", args)
	}
	if e := byMsg["Papers, please"]; e.Level != "error" {
		t.Fatalf("byte-array message: %+v", e)
	}
	if s, _ := fake(system, &args).System(50, "login"); len(s) != 1 {
		t.Fatalf("filter: %+v", s)
	}
}

func TestParseTrafficRejects(t *testing.T) {
	for _, m := range []string{"", "ngfw", "ngfw only-two", "IN=inside ngfw x y"} {
		if _, ok := ParseTraffic(m); ok {
			t.Errorf("%q should not parse", m)
		}
	}
}

func TestTrafficWithoutGrep(t *testing.T) {
	calls := 0
	j := Journal{Run: func(args ...string) ([]byte, error) {
		calls++
		for _, a := range args {
			if a == "--grep" {
				return nil, errorString("Compiled without pattern matching support")
			}
		}
		return []byte(kernel), nil
	}}
	tr, err := j.Traffic(10, "")
	if err != nil || len(tr) != 2 || calls != 4 {
		t.Fatalf("fallback: %v %d entries, %d calls", err, len(tr), calls)
	}
}

type errorString string

func (e errorString) Error() string { return string(e) }

func TestTrafficColumns(t *testing.T) {
	var args []string
	j := fake(kernel, &args)
	j.ZoneOf = func(i string) string { return map[string]string{"inside": "trust", "outside": "untrust"}[i] }
	tr, err := j.Traffic(10, "")
	if err != nil || len(tr) != 2 {
		t.Fatalf("%v %+v", err, tr)
	}
	icmp, web := tr[0], tr[1] // newest first
	if web.FromZone != "trust" || web.ToZone != "untrust" || web.Len != 60 || web.TTL != 63 || web.Flags != "SYN" || web.ICMP != "" {
		t.Fatalf("tcp entry: %+v", web)
	}
	if icmp.ICMP != "8/0" || icmp.Flags != "" || icmp.Len != 84 {
		t.Fatalf("icmp entry: %+v", icmp)
	}
	if got := web.Value("sport") + " " + web.Value("dport") + " " + web.Value("app") + "|" + icmp.Value("sport"); got != "40000 443 |" {
		t.Fatalf("values: %q", got)
	}
	// Zones are searchable.
	if tr, _ := j.Traffic(10, "untrust"); len(tr) != 2 {
		t.Fatalf("zone search: %+v", tr)
	}
	for _, c := range TrafficColumns {
		_ = web.Value(c.Name) // every column has a value function
	}
	cols, err := ParseColumns(" SRC, sport ,dst,dport,app")
	if err != nil || strings.Join(cols, ",") != "src,sport,dst,dport,app" {
		t.Fatalf("columns: %v %v", cols, err)
	}
	if _, err := ParseColumns("src,bogus"); err == nil || !strings.Contains(err.Error(), `unknown column "bogus"`) {
		t.Fatalf("bad column: %v", err)
	}
	for _, d := range DefaultTrafficColumns {
		if _, err := ParseColumns(d); err != nil {
			t.Fatalf("default column %s: %v", d, err)
		}
	}
}

const sessions = `{"__REALTIME_TIMESTAMP":"1794300009000000","MESSAGE":"ngfw-session rule=1 app=YouTube cat=Media proto=tcp src=10.10.1.50 sport=40000 dst=142.250.1.1 dport=443 bytes=52341 packets=60 dur=12.5","_SYSTEMD_UNIT":"appidd.service","SYSLOG_IDENTIFIER":"appidd"}
{"__REALTIME_TIMESTAMP":"1794300008000000","MESSAGE":"ngfw-session rule=7 app=Apple iCloud cat=Cloud proto=udp src=10.10.1.51 sport=5000 dst=17.1.1.1 dport=443 bytes=900 packets=4 dur=0.2","_SYSTEMD_UNIT":"appidd.service","SYSLOG_IDENTIFIER":"appidd"}
{"__REALTIME_TIMESTAMP":"1794300007000000","MESSAGE":"appidd: nDPI 6.0.0 started","_SYSTEMD_UNIT":"appidd.service","SYSLOG_IDENTIFIER":"appidd"}
`

func TestTrafficSessions(t *testing.T) {
	j := Journal{
		Run: func(args ...string) ([]byte, error) {
			if args[0] == "-k" {
				return []byte(kernel), nil
			}
			return []byte(sessions), nil
		},
		RuleName: func(i int) string { return map[int]string{1: "allow-web"}[i] },
	}
	tr, err := j.Traffic(10, "")
	if err != nil || len(tr) != 4 {
		t.Fatalf("%v %+v", err, tr)
	}
	// Merged newest first: the YouTube end entry (…09) beats the kernel's …05.
	yt := tr[0]
	if yt.Type != "end" || yt.Rule != "allow-web" || yt.App != "YouTube" || yt.Category != "Media" || yt.Bytes != 52341 ||
		yt.Packets != 60 || yt.Duration != 12.5 || yt.SPort != 40000 || yt.Action != "allow" {
		t.Fatalf("end entry: %+v", yt)
	}
	if tr[1].App != "Apple iCloud" || tr[1].Rule != "rule 7" {
		t.Fatalf("app with a space / unknown rule: %+v", tr[1])
	}
	if tr[2].Type != "start" || tr[3].Type != "start" {
		t.Fatalf("start entries: %+v", tr[2:])
	}
	if got := yt.Value("duration") + " " + yt.Value("bytes") + " " + tr[2].Value("duration"); got != "12.5s 52341 " {
		t.Fatalf("values: %q", got)
	}
	if tr, _ := j.Traffic(10, "youtube"); len(tr) != 1 {
		t.Fatalf("app search: %+v", tr)
	}
	if tr, _ := j.Traffic(2, ""); len(tr) != 2 || tr[0].App != "YouTube" {
		t.Fatalf("n caps the merged list: %+v", tr)
	}
}
