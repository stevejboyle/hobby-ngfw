package stats

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func clock(t *time.Time) func() time.Time { return func() time.Time { return *t } }

func TestDeltasRestartAndWindows(t *testing.T) {
	now := time.Date(2026, 11, 14, 12, 0, 30, 0, time.UTC)
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "samples.jsonl"), clock(&now))
	if err != nil {
		t.Fatal(err)
	}
	tick := func(in Input) {
		now = now.Add(time.Minute)
		if err := s.Take(in); err != nil {
			t.Fatal(err)
		}
	}
	// Baseline, then two minutes of traffic, then appidd restarts.
	tick(Input{If: map[string]Pair{"inside": {1000, 2000}}, Apps: []Counter{{"YouTube", 100, 1}}, Hosts: []Counter{{"10.0.0.5", 100, 1}}})
	tick(Input{If: map[string]Pair{"inside": {61000, 2000}}, Apps: []Counter{{"YouTube", 600, 3}, {"DNS", 50, 2}}, Hosts: []Counter{{"10.0.0.5", 650, 5}}})
	s.AddThreat("critical", "block", 9900001, "test critical", "10.0.0.5")
	s.AddThreat("minor", "alert", 9900003, "test minor", "10.0.0.6")
	s.AddThreat("critical", "block", 9900001, "test critical", "10.0.0.5")
	tick(Input{If: map[string]Pair{"inside": {121000, 2600}}, Apps: []Counter{{"YouTube", 40, 1}}, Hosts: []Counter{{"10.0.0.5", 40, 1}}})

	r, err := s.Window("1h")
	if err != nil {
		t.Fatal(err)
	}
	if r.Samples != 3 || len(r.Times) != 60 || r.Step != 60 {
		t.Fatalf("samples %d points %d step %d", r.Samples, len(r.Times), r.Step)
	}
	if len(r.Interfaces) != 1 || r.Interfaces[0].InBytes != 120000 || r.Interfaces[0].OutBytes != 600 {
		t.Fatalf("interfaces %+v", r.Interfaces)
	}
	if r.Interfaces[0].PeakBps != 60000*8/60.0+0 && r.Interfaces[0].PeakBps < 8000 {
		t.Fatalf("peak %v", r.Interfaces[0].PeakBps)
	}
	// YouTube: 500 then (restart) 40; DNS 50.
	if len(r.Apps) != 2 || r.Apps[0].Name != "YouTube" || r.Apps[0].Bytes != 540 || r.Apps[0].Flows != 3 || r.Apps[1].Bytes != 50 {
		t.Fatalf("apps %+v", r.Apps)
	}
	if r.Hosts[0].Name != "10.0.0.5" || r.Hosts[0].Bytes != 590 || r.Hosts[0].Threats != 2 {
		t.Fatalf("hosts %+v", r.Hosts)
	}
	th := r.Threats
	sum := func(xs []int) (n int) {
		for _, x := range xs {
			n += x
		}
		return
	}
	if th.Blocked != 2 || th.Alerted != 1 || sum(th.Series["critical"]) != 2 || sum(th.Series["minor"]) != 1 ||
		th.Top[0].SID != 9900001 || th.Top[0].Count != 2 || th.Top[0].Signature != "test critical" {
		t.Fatalf("threats %+v", th)
	}

	// Reopen: history and signature names come back from disk.
	s2, err := Open(filepath.Join(dir, "samples.jsonl"), clock(&now))
	if err != nil {
		t.Fatal(err)
	}
	r2, _ := s2.Window("24h")
	if r2.Samples != 3 || len(r2.Times) != 96 || r2.Apps[0].Bytes != 540 || r2.Threats.Top[0].Signature != "test critical" {
		t.Fatalf("after reopen: %+v", r2)
	}
	if _, err := s.Window("2h"); err == nil {
		t.Fatal("unknown window accepted")
	}

	// Eight days on, everything has expired, also from the file.
	now = now.Add(8 * 24 * time.Hour)
	s3, err := Open(filepath.Join(dir, "samples.jsonl"), clock(&now))
	if err != nil {
		t.Fatal(err)
	}
	if r3, _ := s3.Window("7d"); r3.Samples != 0 {
		t.Fatalf("expired samples kept: %d", r3.Samples)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "samples.jsonl")); len(b) != 0 {
		t.Fatalf("file not compacted: %d bytes", len(b))
	}
}

func TestHostsCapped(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	s := &Store{Now: clock(&now)}
	var base, next []Counter
	for i := 0; i < 40; i++ {
		ip := "10.0.0." + string(rune('a'+i))
		base = append(base, Counter{ip, 0, 0})
		next = append(next, Counter{ip, int64(i + 1), 1})
	}
	s.Take(Input{Hosts: base})
	now = now.Add(time.Minute)
	s.Take(Input{Hosts: next})
	if n := len(s.samples[1].Hosts); n != hostsPerSample {
		t.Fatalf("hosts kept: %d", n)
	}
	if _, ok := s.samples[1].Hosts["10.0.0."+string(rune('a'+39))]; !ok {
		t.Fatal("busiest host dropped")
	}
}

func TestReadInterfaces(t *testing.T) {
	root := t.TempDir()
	d := filepath.Join(root, "sys/class/net/inside/statistics")
	os.MkdirAll(d, 0o755)
	os.WriteFile(filepath.Join(d, "rx_bytes"), []byte("12345\n"), 0o644)
	os.WriteFile(filepath.Join(d, "tx_bytes"), []byte("678\n"), 0o644)
	got := ReadInterfaces(root, []string{"inside", "missing"})
	if len(got) != 1 || got["inside"] != (Pair{12345, 678}) {
		t.Fatalf("%v", got)
	}
}
