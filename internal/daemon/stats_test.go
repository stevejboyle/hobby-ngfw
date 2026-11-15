package daemon

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stevejboyle/hobby-ngfw/internal/appid"
	"github.com/stevejboyle/hobby-ngfw/internal/compiler"
	"github.com/stevejboyle/hobby-ngfw/internal/ips"
	"github.com/stevejboyle/hobby-ngfw/internal/stats"
)

func TestDashboardStats(t *testing.T) {
	d, _ := setup(t)
	root := t.TempDir()
	counters := func(rx, tx string) {
		dir := filepath.Join(root, "sys/class/net/veth-users/statistics")
		os.MkdirAll(dir, 0o755)
		os.WriteFile(filepath.Join(dir, "rx_bytes"), []byte(rx), 0o644)
		os.WriteFile(filepath.Join(dir, "tx_bytes"), []byte(tx), 0o644)
	}
	statsFile := filepath.Join(root, "appid-stats.json")
	appids := func(yt, host string) {
		os.WriteFile(statsFile, []byte(`{"updated": 1, "apps": [{"id": 124, "name": "YouTube", "category": "Media", "flows": 2, "bytes": `+yt+`, "last_seen": 1}],
 "hosts": [{"ip": "10.10.1.50", "flows": 2, "bytes": `+host+`}]}`), 0o644)
	}
	st, err := stats.Open(filepath.Join(t.TempDir(), "samples.jsonl"), nil)
	if err != nil {
		t.Fatal(err)
	}
	d.SetStats(st, root)
	d.SetAppID(appid.Source{StatsFile: statsFile})
	if err := d.SetCandidate(lab(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Commit("t", "lab", 0); err != nil {
		t.Fatal(err)
	}

	counters("1000", "500")
	appids("100", "100")
	if err := d.SampleStats(); err != nil { // baseline
		t.Fatal(err)
	}
	counters("61000", "3500")
	appids("5100", "5100")
	// A logged threat counts; an ignored one doesn't.
	d.SetIPS(&fakeSuricata{mark: uint32(1) << compiler.RuleShift}, &ips.Engine{Dir: t.TempDir()})
	d.ips.emit = func(string) {}
	d.IPSAlert(ips.Alert{SID: 9900001, Message: "test critical", Severity: "critical", Proto: "tcp", Src: "10.10.1.50"})
	if err := d.SampleStats(); err != nil {
		t.Fatal(err)
	}

	v, err := d.Stats("1h")
	if err != nil {
		t.Fatal(err)
	}
	if !v.AppID || len(v.Interfaces) != 1 || v.Interfaces[0].Name != "veth-users" || v.Interfaces[0].InBytes != 60000 || v.Interfaces[0].OutBytes != 3000 {
		t.Fatalf("interfaces %+v", v.Interfaces)
	}
	if len(v.Apps) != 1 || v.Apps[0].Name != "YouTube" || v.Apps[0].Bytes != 5000 || len(v.Hosts) != 1 || v.Hosts[0].Name != "10.10.1.50" || v.Hosts[0].Bytes != 5000 {
		t.Fatalf("apps %+v hosts %+v", v.Apps, v.Hosts)
	}
	if v.Threats.Alerted+v.Threats.Blocked != 1 || len(v.Threats.Top) != 1 || v.Threats.Top[0].SID != 9900001 || v.Hosts[0].Threats != 1 {
		t.Fatalf("threats %+v", v.Threats)
	}
	if _, err := d.Stats("1y"); err == nil {
		t.Fatal("bad window accepted")
	}
}

// The sampler doesn't wait for the daemon lock: a commit that holds it for
// minutes (rebuilding the IPS signatures) must not make it skip samples.
func TestSamplerDoesNotWaitForCommits(t *testing.T) {
	d, _ := setup(t)
	st, err := stats.Open(filepath.Join(t.TempDir(), "samples.jsonl"), nil)
	if err != nil {
		t.Fatal(err)
	}
	d.SetStats(st, t.TempDir())
	d.SetCandidate(lab(t))
	if _, err := d.Commit("t", "lab", 0); err != nil {
		t.Fatal(err)
	}
	d.mu.Lock() // a long commit in progress
	done := make(chan error, 1)
	go func() { done <- d.SampleStats() }()
	select {
	case err := <-done:
		d.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		d.mu.Unlock()
		t.Fatal("SampleStats waited for the daemon lock")
	}
}
