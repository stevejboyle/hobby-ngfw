package daemon

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stevejboyle/sjb-os/internal/compiler"
	"github.com/stevejboyle/sjb-os/internal/ips"
	"github.com/stevejboyle/sjb-os/internal/logs"
)

type fakeSuricata struct {
	running       bool
	starts, stops int
	mem           uint64
	mark          uint32
	decrypted     bool
	src, dst      string
	reload        reloadCtl
}

// reloadCtl is fakeSuricata's blocking reload (ReloadRules): gate, when
// set, holds each reload until it is closed (a slow reload); err fails it.
// The daemon calls it from its own goroutine, hence the lock.
type reloadCtl struct {
	mu   sync.Mutex
	gate chan struct{}
	err  error
	n    int
}

func (r *reloadCtl) set(gate chan struct{}, err error) {
	r.mu.Lock()
	r.gate, r.err = gate, err
	r.mu.Unlock()
}

func (r *reloadCtl) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.n
}

func (f *fakeSuricata) Available() bool { return true }
func (f *fakeSuricata) Start() error    { f.starts++; f.running = true; return nil }
func (f *fakeSuricata) Stop() error     { f.stops++; f.running = false; return nil }
func (f *fakeSuricata) Running() bool   { return f.running }
func (f *fakeSuricata) ReloadRules() error {
	f.reload.mu.Lock()
	gate, err := f.reload.gate, f.reload.err
	f.reload.mu.Unlock()
	if gate != nil {
		<-gate
	}
	f.reload.mu.Lock()
	f.reload.n++
	f.reload.mu.Unlock()
	return err
}
func (f *fakeSuricata) MemTotal() uint64         { return f.mem }
func (f *fakeSuricata) LoadedRules() (int, bool) { return 4, f.running }
func (f *fakeSuricata) ConnMark(proto, src string, sport int, dst string, dport int) (uint32, bool, bool) {
	f.src, f.dst = src, dst
	return f.mark, f.decrypted, f.mark != 0
}

// testEngine is an IPS engine whose downloads fail at once. A commit with
// IPS rules starts a background download, which records its failure in
// the engine's directory; the cleanup waits for it, so it can't write
// there after the test's TempDir is removed.
func testEngine(t *testing.T, d *Daemon) *ips.Engine {
	e := &ips.Engine{Dir: t.TempDir(), URL: "http://127.0.0.1:1/none"}
	t.Cleanup(func() {
		if d.ips.lastTry.IsZero() {
			return // no download was started
		}
		for deadline := time.Now().Add(10 * time.Second); e.Status().LastAttempt.IsZero() && time.Now().Before(deadline); {
			time.Sleep(5 * time.Millisecond)
		}
		d.ips.updating.Lock() // held until the download has returned
		d.ips.updating.Unlock()
	})
	return e
}

func TestIPSLifecycleAndAlerts(t *testing.T) {
	d, nf := setup(t)
	fs := &fakeSuricata{mem: 2 << 30}
	e := testEngine(t, d)
	d.SetIPS(fs, e)
	var lines []string
	d.ips.emit = func(s string) { lines = append(lines, s) }

	cfg := strings.Replace(string(lab(t)), "    service: [web]\n    action: allow\n    log: true", "    service: [web]\n    action: allow\n    log: true\n    ips_profile: strict", 1) +
		"ips_profiles:\n  - name: strict\n    minor: block\n    informational: alert\n"
	if err := d.SetCandidate([]byte(cfg)); err != nil {
		t.Fatal(err)
	}
	res, err := d.Commit("t", "ips", 0)
	if err != nil {
		t.Fatal(err)
	}
	w := strings.Join(res.Warnings, "\n")
	if !strings.Contains(w, "give it 4 GB") || !strings.Contains(w, "being downloaded") {
		t.Errorf("warnings: %s", w)
	}
	if fs.starts != 1 || !e.Installed() || !strings.Contains(nf.Last(), "chain ips_enforce") {
		t.Fatalf("starts=%d installed=%v\n%s", fs.starts, e.Installed(), nf.Last())
	}
	if st := d.IPS(); !st.Running || st.Loaded != 4 || st.Loading {
		t.Fatalf("status %+v", st)
	}
	// The periodic pass leaves a running engine alone.
	d.ReconcileRoutes()
	if fs.starts != 1 {
		t.Fatalf("restarted: %d", fs.starts)
	}

	idx := -1
	for i, r := range d.running.Rules {
		if r.Name == "allow-web" {
			idx = i
		}
	}
	fs.mark = uint32(idx+1)<<compiler.RuleShift | compiler.SessionBit | compiler.AppDoneBit | 124 // YouTube
	d.IPSAlert(ips.Alert{SID: 2001219, Message: "ET SCAN x", Severity: "minor", Proto: "tcp", Src: "93.184.216.34", SPort: 80, Dst: "10.10.1.50", DPort: 40000})
	d.IPSAlert(ips.Alert{SID: 9900004, Severity: "informational", Proto: "tcp"})
	if len(lines) != 2 {
		t.Fatalf("lines: %v", lines)
	}
	th, ok := logs.ParseThreat(lines[0])
	if !ok || th.Rule != "allow-web" || th.Profile != "strict" || th.Action != "block" || th.App != "YouTube" || th.Src != "93.184.216.34" {
		t.Fatalf("threat: %+v (%s)", th, lines[0])
	}
	if th, _ := logs.ParseThreat(lines[1]); th.Action != "alert" {
		t.Fatalf("informational under strict alerts: %+v", th)
	}
	if th.Decrypted {
		t.Fatal("not decrypted traffic")
	}
	// A match in decrypted traffic: the rule comes from the loop leg.
	fs.decrypted = true
	d.IPSAlert(ips.Alert{SID: 9900001, Severity: "critical", Proto: "tcp"})
	fs.decrypted = false
	if th, _ := logs.ParseThreat(lines[len(lines)-1]); !th.Decrypted || th.Rule != "allow-web" || th.Action != "block" || th.Value("decrypted") != "yes" {
		t.Fatalf("decrypted threat: %+v", th)
	}
	lines = lines[:2]
	// Default profile ignores informational: nothing logged.
	d.mu.Lock()
	d.running.Rules[idx].IPSProfile = "default"
	d.mu.Unlock()
	d.IPSAlert(ips.Alert{SID: 9900004, Severity: "informational", Proto: "tcp"})
	if len(lines) != 2 {
		t.Fatalf("ignored severity logged: %v", lines[2:])
	}

	// No IPS rules any more: the engine stops, the chains go.
	if err := d.SetCandidate(lab(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Commit("t", "no ips", 0); err != nil {
		t.Fatal(err)
	}
	if fs.stops != 1 || fs.running || strings.Contains(nf.Last(), "chain ips") {
		t.Fatalf("stops=%d", fs.stops)
	}
	if st := d.IPS(); st.InUse || len(st.Rules) != 0 || st.Engine.Source != "test signatures only" {
		t.Fatalf("status %+v", st)
	}
}
