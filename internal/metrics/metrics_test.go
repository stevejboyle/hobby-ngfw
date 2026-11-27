package metrics

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func write(t *testing.T, root, path, data string) {
	t.Helper()
	p := filepath.Join(root, path)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestReaders(t *testing.T) {
	root := t.TempDir()
	write(t, root, "proc/uptime", "1234.50 999.00\n")
	write(t, root, "proc/loadavg", "0.50 0.25 0.10 1/100 42\n")
	write(t, root, "proc/stat", "cpu  1000 100 500 8000 200 10 20 30 0 0\ncpu0 500 50 250 4000 100 5 10 15 0 0\ncpu1 500 50 250 4000 100 5 10 15 0 0\nintr 1\n")
	write(t, root, "proc/meminfo", "MemTotal:        4000 kB\nMemFree:  100 kB\nMemAvailable:    3000 kB\n")
	write(t, root, "proc/sys/net/netfilter/nf_conntrack_count", "17\n")
	write(t, root, "proc/sys/net/netfilter/nf_conntrack_max", "262144\n")
	for f, v := range map[string]string{"rx_bytes": "100", "tx_bytes": "200", "rx_packets": "3", "tx_packets": "4", "rx_errors": "0", "tx_errors": "1", "rx_dropped": "2", "tx_dropped": "0"} {
		write(t, root, "sys/class/net/inside/statistics/"+f, v+"\n")
	}
	write(t, root, "sys/class/net/inside/operstate", "up\n")

	s := ReadSystem(root, []string{"."})
	if s.UptimeSeconds != 1234.5 || s.Load != [3]float64{0.5, 0.25, 0.1} || s.CPUs != 2 {
		t.Errorf("system: %+v", s)
	}
	if s.CPUSeconds["user"] != 11 || s.CPUSeconds["system"] != 5 || s.CPUSeconds["idle"] != 80 || s.CPUSeconds["iowait"] != 2 || s.CPUSeconds["other"] < 0.599 || s.CPUSeconds["other"] > 0.601 {
		t.Errorf("cpu: %v", s.CPUSeconds)
	}
	if s.MemTotal != 4000*1024 || s.MemAvailable != 3000*1024 {
		t.Errorf("mem: %d %d", s.MemTotal, s.MemAvailable)
	}
	if len(s.Disks) != 1 || s.Disks[0].Size == 0 {
		t.Errorf("disks: %+v", s.Disks)
	}
	if got := ReadSessions(root); got != (Sessions{17, 262144}) {
		t.Errorf("sessions: %+v", got)
	}
	in, ok := ReadInterface(root, "inside")
	want := Interface{Name: "inside", Up: true, RxBytes: 100, TxBytes: 200, RxPackets: 3, TxPackets: 4, TxErrors: 1, RxDropped: 2}
	if !ok || in != want {
		t.Errorf("interface: %+v", in)
	}
	if _, ok := ReadInterface(root, "nope"); ok {
		t.Error("missing interface read")
	}
}

func sample() Snapshot {
	now := time.Unix(1795400000, 0)
	s := Snapshot{
		Time: now, Version: "0.9.13-r01", Hostname: `sjb "fw"`,
		System:     System{UptimeSeconds: 10, CPUSeconds: map[string]float64{"user": 1, "idle": 9}, CPUs: 2, Load: [3]float64{1, 2, 3}, MemTotal: 10, MemAvailable: 5, Disks: []Disk{{"/", 100, 50}}},
		Config:     Config{RunningRevision: 7, LastCommitOK: true, LastCommitTime: &now},
		Services:   []Service{{Name: "ngfwd", Up: true, Used: true}, {Name: "suricata", Used: true}, {Name: "tlsd", Unknown: true, Used: true}},
		Interfaces: []Interface{{Name: "inside", Zone: "trust", Up: true, RxBytes: 5}, {Name: "mgmt", Up: true}},
		Sessions:   Sessions{3, 100},
		Rules:      []Rule{{"web-in", "allow", 10, 1000}, {"default-deny", "deny", 2, 120}},
		NAT:        []NAT{{Name: "web", Type: "port-forward", Hits: 4, Hairpin: 1}, {Name: "srv", Type: "static", Hits: 1, OutHits: 2}},
		IPS:        IPS{State: "inspecting", Up: true, Loaded: 50000, Updated: &now, Matches: map[string]map[string]uint64{"critical": {"block": 3}}, ExceptionsActive: 1},
		AppID:      AppID{Enabled: true, Up: true, Apps: []App{{"YouTube", 900, 3}}},
		Decryption: Decryption{State: "decrypting", Up: true, Active: 2, Counts: map[string]int64{"decrypted": 5, "excluded": 1}},
		LogServers: []LogServer{{Name: "siem", Connected: true, Sent: 10}},
		Tags:       []TagCount{{"quarantine", 2}},
	}
	s.FillThreats()
	s.Sections = map[string]SectionStatus{}
	for _, sec := range Sections {
		s.Sections[sec] = SectionStatus{State: Current, CollectedAt: &now}
	}
	return s
}

// A strict reading of the text format: comments are HELP/TYPE, each family
// is declared once before its samples and its samples are contiguous, and
// every sample line parses.
var (
	sampleRE = regexp.MustCompile(`^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{([a-zA-Z_][a-zA-Z0-9_]*="(\\.|[^"\\])*"(,[a-zA-Z_][a-zA-Z0-9_]*="(\\.|[^"\\])*")*)\})? (-?[0-9.e+-]+|NaN|\+Inf|-Inf)$`)
	typeRE   = regexp.MustCompile(`^# TYPE ([a-zA-Z_:][a-zA-Z0-9_:]*) (counter|gauge|untyped)$`)
)

func checkFormat(t *testing.T, text string) map[string]int {
	t.Helper()
	declared := map[string]bool{}
	done := map[string]bool{}
	counts := map[string]int{}
	current := ""
	sc := bufio.NewScanner(strings.NewReader(text))
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "# HELP "):
		case strings.HasPrefix(line, "# TYPE "):
			m := typeRE.FindStringSubmatch(line)
			if m == nil {
				t.Fatalf("line %d: bad TYPE: %q", n, line)
			}
			if declared[m[1]] {
				t.Fatalf("line %d: %s declared twice", n, m[1])
			}
			declared[m[1]] = true
		default:
			m := sampleRE.FindStringSubmatch(line)
			if m == nil {
				t.Fatalf("line %d: bad sample: %q", n, line)
			}
			name := m[1]
			if !declared[name] {
				t.Fatalf("line %d: %s has no TYPE", n, name)
			}
			if name != current {
				if done[name] {
					t.Fatalf("line %d: %s samples not contiguous", n, name)
				}
				if current != "" {
					done[current] = true
				}
				current = name
			}
			if !strings.HasPrefix(name, "sjbos_") {
				t.Fatalf("line %d: %s lacks the sjbos_ prefix", n, name)
			}
			counts[name]++
		}
	}
	return counts
}

func TestWritePrometheus(t *testing.T) {
	var buf bytes.Buffer
	if err := WritePrometheus(&buf, sample()); err != nil {
		t.Fatal(err)
	}
	text := buf.String()
	counts := checkFormat(t, text)
	for _, want := range []string{
		`sjbos_info{version="0.9.13-r01",hostname="sjb \"fw\""} 1`,
		`sjbos_service_up{service="suricata"} 0`,
		`sjbos_interface_receive_bytes_total{interface="inside",zone="trust"} 5`,
		`sjbos_interface_up{interface="mgmt",zone=""} 1`,
		`sjbos_rule_packets_total{rule="web-in",action="allow"} 10`,
		`sjbos_rule_bytes_total{rule="default-deny",action="deny"} 120`,
		`sjbos_nat_translations_total{nat="srv",type="static",direction="outbound"} 2`,
		`sjbos_nat_hairpin_total{nat="web"} 1`,
		`sjbos_ips_state{state="inspecting"} 1`,
		`sjbos_ips_state{state="off"} 0`,
		`sjbos_ips_matches_total{severity="critical",action="block"} 3`,
		`sjbos_ips_matches_total{severity="minor",action="alert"} 0`,
		`sjbos_ips_signatures_loaded 50000`,
		`sjbos_app_bytes_total{app="YouTube"} 900`,
		`sjbos_decryption_connections_total{outcome="decrypted"} 5`,
		`sjbos_logforward_sent_total{server="siem"} 10`,
		`sjbos_tag_addresses{tag="quarantine"} 2`,
		`sjbos_config_running_revision 7`,
		`sjbos_sessions_max 100`,
		`sjbos_filesystem_free_bytes{mount="/"} 50`,
	} {
		if !strings.Contains(text, want+"\n") {
			t.Errorf("missing %s", want)
		}
	}
	if counts["sjbos_ips_matches_total"] != 8 {
		t.Errorf("ips matches: %d samples, want 8", counts["sjbos_ips_matches_total"])
	}
	// An empty snapshot still renders validly.
	buf.Reset()
	if err := WritePrometheus(&buf, Snapshot{}); err != nil {
		t.Fatal(err)
	}
	checkFormat(t, buf.String())
}

func TestSaveLoadAndTop(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "metrics.json")
	s := sample()
	if err := Save(path, s, 0o640, -1); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o640 {
		t.Fatalf("mode: %v %v", fi, err)
	}
	got, err := Load(path)
	if err != nil || got.Version != s.Version || len(got.Rules) != 2 || got.IPS.Matches["critical"]["block"] != 3 {
		t.Fatalf("load: %+v %v", got, err)
	}
	if len(got.Threats) != 4 || got.Threats[0] != (ThreatStat{"critical", 3, 0}) {
		t.Errorf("threats: %+v", got.Threats)
	}
	var apps []App
	for i := 0; i < MaxApps+5; i++ {
		apps = append(apps, App{Name: string(rune('a'+i%26)) + string(rune('A'+i/26)), Bytes: int64(i)})
	}
	top := TopApps(apps)
	if len(top) != MaxApps || top[0].Bytes != MaxApps+4 {
		t.Errorf("top: %d, first %+v", len(top), top[0])
	}
}

func TestPrometheusFreshness(t *testing.T) {
	s := sample()
	old := s.Time.Add(-time.Minute)
	s.Sections["ips"] = SectionStatus{State: Stale, CollectedAt: &old, Error: "not read in time"}
	s.Sections["config"] = SectionStatus{State: Never}
	s.Sections["decryption"] = SectionStatus{State: Failed, Error: "boom"}
	s.Config.RunningRevision = 0
	var buf bytes.Buffer
	if err := WritePrometheus(&buf, s); err != nil {
		t.Fatal(err)
	}
	text := buf.String()
	checkFormat(t, text)
	for _, want := range []string{
		`sjbos_collection_state{section="ips",state="stale"} 1`,
		`sjbos_collection_state{section="config",state="never"} 1`,
		`sjbos_collection_state{section="decryption",state="failed"} 1`,
		`sjbos_collection_state{section="rules",state="current"} 1`,
		`sjbos_collection_timestamp_seconds{section="ips"} 1795399940`,
		`sjbos_ips_state{state="inspecting"} 1`, // stale: last known, still shown
		`sjbos_config_last_commit_success 1`,    // the commit record is always current
	} {
		if !strings.Contains(text, want+"\n") {
			t.Errorf("missing %s", want)
		}
	}
	for _, absent := range []string{
		"sjbos_config_running_revision", // never read: no made-up zero
		"sjbos_decryption_state",        // failed: no values
		`sjbos_collection_timestamp_seconds{section="config"}`,
		`sjbos_service_up{service="tlsd"}`, // unknown: neither up nor down
	} {
		if strings.Contains(text, absent) {
			t.Errorf("%s exported", absent)
		}
	}
}

func TestPrometheusGeoIP(t *testing.T) {
	s := sample()
	var buf bytes.Buffer
	WritePrometheus(&buf, s)
	if strings.Contains(buf.String(), "sjbos_geoip") {
		t.Error("geoip metrics without a country database")
	}
	s.GeoIP = &GeoIP{AgeSeconds: 86400, LastUpdateOK: false, CountriesInUse: 3}
	buf.Reset()
	WritePrometheus(&buf, s)
	checkFormat(t, buf.String())
	for _, want := range []string{"sjbos_geoip_age_seconds 86400\n", "sjbos_geoip_last_update_success 0\n", "sjbos_geoip_countries_in_use 3\n"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("missing %q", want)
		}
	}
}
