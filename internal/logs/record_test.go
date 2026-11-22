package logs

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

func TestParseRecord(t *testing.T) {
	j := Journal{
		ZoneOf:   func(i string) string { return map[string]string{"inside": "users", "outside": "internet"}[i] },
		RuleName: func(i int) string { return map[int]string{3: "web-out"}[i] },
	}
	cases := []struct {
		line, kind, want string
	}{
		{`{"__CURSOR":"c1","__REALTIME_TIMESTAMP":"1763700000000000","_TRANSPORT":"kernel","MESSAGE":"ngfw web-out allow IN=inside OUT=outside SRC=10.0.0.5 DST=203.0.113.9 LEN=60 TTL=64 PROTO=TCP SPT=40000 DPT=443 SYN"}`,
			KindTraffic, "users"},
		{`{"__CURSOR":"c2","__REALTIME_TIMESTAMP":"1763700000000000","_SYSTEMD_UNIT":"appidd.service","MESSAGE":"ngfw-session rule=3 app=YouTube cat=Media proto=tcp src=10.0.0.5 sport=40000 dst=203.0.113.9 dport=443 bytes=900 packets=9 dur=1.5"}`,
			KindTraffic, "web-out"},
		{`{"__CURSOR":"c3","__REALTIME_TIMESTAMP":"1763700000000000","_SYSTEMD_UNIT":"ngfwd.service","MESSAGE":"ngfw-threat {\"rule\":\"web-out\",\"sid\":9900001,\"action\":\"block\",\"severity\":\"critical\",\"src\":\"10.0.0.5\",\"dst\":\"203.0.113.9\",\"proto\":\"tcp\"}"}`,
			KindThreat, "9900001"},
		{`{"__CURSOR":"c4","__REALTIME_TIMESTAMP":"1763700000000000","_SYSTEMD_UNIT":"sjb-tlsd.service","MESSAGE":"ngfw-decrypt {\"rule\":\"d1\",\"decision\":\"decrypted\",\"server_name\":\"example.com\",\"src\":\"10.0.0.5\",\"dst\":\"203.0.113.9\"}"}`,
			KindDecryption, "example.com"},
		{`{"__CURSOR":"c5","__REALTIME_TIMESTAMP":"1763700000000000","_SYSTEMD_UNIT":"ngfwd.service","MESSAGE":"time=2026-11-21T10:00:00Z level=INFO msg=commit revision=4 author=cli:admin"}`,
			KindSystem, "commit"},
		{`{"__CURSOR":"c6","__REALTIME_TIMESTAMP":"1763700000000000","_SYSTEMD_UNIT":"ssh.service","SYSLOG_IDENTIFIER":"sshd","MESSAGE":"Accepted publickey for admin"}`,
			KindSystem, "sshd"},
	}
	for _, tc := range cases {
		r, ok := j.ParseRecord([]byte(tc.line))
		if !ok || r.Kind != tc.kind {
			t.Fatalf("%s: got %v %+v", tc.line, ok, r)
		}
		if !strings.Contains(strings.ToLower(toJSON(r.Entry)), strings.ToLower(tc.want)) {
			t.Errorf("%s: entry %s lacks %q", tc.kind, toJSON(r.Entry), tc.want)
		}
		if r.Cursor == "" {
			t.Error("no cursor")
		}
	}
	for _, skip := range []string{
		`{"_TRANSPORT":"kernel","MESSAGE":"e1000: link up"}`,
		`{"_SYSTEMD_UNIT":"appidd.service","MESSAGE":"appidd: queue 0 bound"}`,
		`{"_SYSTEMD_UNIT":"sjb-tlsd.service","MESSAGE":"listening"}`,
		`not json`,
	} {
		if r, ok := j.ParseRecord([]byte(skip)); ok {
			t.Errorf("%s: parsed as %+v", skip, r)
		}
	}
	m := FollowMatches()
	if m[0] != "_TRANSPORT=kernel" || !slices.Contains(m, "_SYSTEMD_UNIT=sjb-tlsd.service") || !slices.Contains(m, "+") {
		t.Errorf("matches %v", m)
	}
}

func toJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
