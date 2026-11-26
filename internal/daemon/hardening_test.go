package daemon

// Tests for the 0.9.13-r03 hardening: SNMP credential transactions (H-01),
// monitoring freshness (H-02), SNMP recovery (H-03), bounded collection
// (M-01), counter failures (M-02), the credential store (M-03), and the
// API key lifecycle.

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stevejboyle/sjb-os/internal/accounts"
	"github.com/stevejboyle/sjb-os/internal/metrics"
	"github.com/stevejboyle/sjb-os/internal/nft"
	"github.com/stevejboyle/sjb-os/internal/snmp"
)

var nmsV3 = snmp.Credential{Name: "nms", Kind: "v3", Auth: "SHA-256", AuthPass: "auth-pass-1", Priv: "AES", PrivPass: "priv-pass-1"}

func snmpDaemon(t *testing.T) (*Daemon, *fakeSNMPD, string) {
	t.Helper()
	d, _ := setup(t)
	withAccounts(t, d)
	fake := &fakeSNMPD{}
	creds := filepath.Join(t.TempDir(), "snmp-credentials")
	d.SetSNMP(fake, creds, "")
	d.SetCandidate(lab(t))
	if _, err := d.Commit("steve", "lab", 0); err != nil {
		t.Fatal(err)
	}
	return d, fake, creds
}

// runningRefsOK is the invariant H-01 protects: the running config never
// names a credential that is missing or of the wrong kind.
func runningRefsOK(t *testing.T, d *Daemon) {
	t.Helper()
	d.mu.Lock()
	cfg := d.running
	d.mu.Unlock()
	if cfg == nil || !cfg.SNMP.On() {
		return
	}
	cs, err := d.loadSNMPCreds()
	if err != nil {
		t.Fatalf("credentials unreadable: %v", err)
	}
	if err := snmp.CheckRefs(cfg, cs); err != nil {
		t.Fatalf("running config names a bad credential: %v", err)
	}
}

// H-01: a delete racing a commit that adds a reference never leaves the
// running config naming a missing credential.
func TestCredentialDeleteRacesCommit(t *testing.T) {
	d, _, _ := snmpDaemon(t)
	withSNMP := append(lab(t), []byte(snmpYAML)...)
	for i := 0; i < 20; i++ {
		if _, err := d.AddSNMPCredential(accounts.Root, nmsV3, false); err != nil && !strings.Contains(err.Error(), "exists") {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			d.SetCandidate(withSNMP)
			d.Commit("steve", "snmp on", 0)
		}()
		go func() {
			defer wg.Done()
			d.DeleteSNMPCredential(accounts.Root, "nms")
		}()
		wg.Wait()
		runningRefsOK(t, d)
		// Back to a config without SNMP for the next round.
		d.SetCandidate(lab(t))
		d.Commit("steve", "snmp off", 0)
	}
}

// H-01: a kind change racing a commit that names the credential as a v3
// user never leaves it a v2c credential under a v3 reference.
func TestCredentialKindChangeRacesCommit(t *testing.T) {
	d, _, _ := snmpDaemon(t)
	withSNMP := append(lab(t), []byte(snmpYAML)...)
	v2c := snmp.Credential{Name: "nms", Kind: "v2c", Community: "community-1"}
	for i := 0; i < 20; i++ {
		d.SetCandidate(lab(t))
		d.Commit("steve", "snmp off", 0)
		d.DeleteSNMPCredential(accounts.Root, "nms")
		if _, err := d.AddSNMPCredential(accounts.Root, nmsV3, false); err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			d.SetCandidate(withSNMP)
			d.Commit("steve", "snmp on", 0)
		}()
		go func() {
			defer wg.Done()
			d.AddSNMPCredential(accounts.Root, v2c, true)
		}()
		wg.Wait()
		runningRefsOK(t, d)
	}
}

// H-01: kind changes and deletes are refused while the running config or
// the candidate names the credential; replacing secrets is allowed.
func TestCredentialChangesWhileReferenced(t *testing.T) {
	d, _, _ := snmpDaemon(t)
	if _, err := d.AddSNMPCredential(accounts.Root, nmsV3, false); err != nil {
		t.Fatal(err)
	}
	// Named only by the candidate.
	d.SetCandidate(append(lab(t), []byte(snmpYAML)...))
	v2c := snmp.Credential{Name: "nms", Kind: "v2c", Community: "community-1"}
	if _, err := d.AddSNMPCredential(accounts.Root, v2c, true); err == nil || !strings.Contains(err.Error(), "can't become v2c") {
		t.Errorf("kind change under a candidate reference: %v", err)
	}
	if err := d.DeleteSNMPCredential(accounts.Root, "nms"); err == nil || !strings.Contains(err.Error(), "candidate") {
		t.Errorf("delete under a candidate reference: %v", err)
	}
	// Committed: the running config names it.
	if _, err := d.Commit("steve", "snmp", 0); err != nil {
		t.Fatal(err)
	}
	d.SetCandidate(lab(t)) // the candidate no longer does
	if _, err := d.AddSNMPCredential(accounts.Root, v2c, true); err == nil {
		t.Error("kind change under a running reference")
	}
	if err := d.DeleteSNMPCredential(accounts.Root, "nms"); err == nil {
		t.Error("delete under a running reference")
	}
	rotated := nmsV3
	rotated.AuthPass = "auth-pass-2"
	if _, err := d.AddSNMPCredential(accounts.Root, rotated, true); err != nil {
		t.Errorf("rotating secrets: %v", err)
	}
	runningRefsOK(t, d)
}

// H-01: a restore racing deletes and kind changes keeps the store valid and
// the running config's references good.
func TestCredentialRestoreRacesMutations(t *testing.T) {
	d, _, creds := snmpDaemon(t)
	if _, err := d.AddSNMPCredential(accounts.Root, nmsV3, false); err != nil {
		t.Fatal(err)
	}
	d.SetCandidate(append(lab(t), []byte(snmpYAML)...))
	if _, err := d.Commit("steve", "snmp", 0); err != nil {
		t.Fatal(err)
	}
	if _, err := d.AddSNMPCredential(accounts.Root, snmp.Credential{Name: "spare", Kind: "v2c", Community: "community-9"}, false); err != nil {
		t.Fatal(err)
	}
	b, err := d.ExportBackup(accounts.Root, true, "a-good-passphrase")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(3)
		go func() {
			defer wg.Done()
			d.RestoreBackup(accounts.Root, RestoreRequest{Data: b.Data, Passphrase: "a-good-passphrase", Accounts: true})
		}()
		go func() { defer wg.Done(); d.DeleteSNMPCredential(accounts.Root, "spare") }()
		go func() {
			defer wg.Done()
			d.AddSNMPCredential(accounts.Root, snmp.Credential{Name: "nms", Kind: "v2c", Community: "community-1"}, true)
		}()
		wg.Wait()
		runningRefsOK(t, d)
		if _, err := snmp.Load(creds); err != nil {
			t.Fatalf("store left invalid: %v", err)
		}
	}
}

// H-01/M-03: a write that fails leaves the store as it was, and the daemon
// works again once it can write.
func TestCredentialPersistenceFailure(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	d, _ := setup(t)
	withAccounts(t, d)
	dir := filepath.Join(t.TempDir(), "etc")
	os.MkdirAll(dir, 0o755)
	creds := filepath.Join(dir, "snmp-credentials")
	d.SetSNMP(&fakeSNMPD{}, creds, "")
	if _, err := d.AddSNMPCredential(accounts.Root, nmsV3, false); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(creds)
	os.Chmod(dir, 0o500)
	defer os.Chmod(dir, 0o755)
	if _, err := d.AddSNMPCredential(accounts.Root, snmp.Credential{Name: "ro", Kind: "v2c", Community: "community-1"}, false); err == nil {
		t.Fatal("write into a read-only directory succeeded")
	}
	if err := d.DeleteSNMPCredential(accounts.Root, "nms"); err == nil {
		t.Fatal("delete in a read-only directory succeeded")
	}
	after, _ := os.ReadFile(creds)
	if string(before) != string(after) {
		t.Error("a failed write changed the store")
	}
	if st := d.SNMP(); len(st.Credentials) != 1 || st.Credentials[0].Name != "nms" {
		t.Errorf("status after failures: %+v", st.Credentials)
	}
	os.Chmod(dir, 0o755)
	if _, err := d.AddSNMPCredential(accounts.Root, snmp.Credential{Name: "ro", Kind: "v2c", Community: "community-1"}, false); err != nil {
		t.Errorf("after the directory is writable again: %v", err)
	}
}

// M-03: a store that fails validation is reported and never written over,
// not even by the internal-passphrase repair.
func TestInvalidStoreNeverOverwritten(t *testing.T) {
	d, fake, creds := snmpDaemon(t)
	bad := `{"credentials":[{"name":"nms","kind":"v3","auth":"SHA-256","auth_pass":"auth-pass-1","priv":"AES","priv_pass":"priv-pass-1"},{"name":"nms","kind":"v2c","community":"community-1"}]}`
	os.WriteFile(creds, []byte(bad), 0o600)
	d.SetCandidate(append(lab(t), []byte(snmpYAML)...))
	if _, err := d.Commit("steve", "snmp", 0); err == nil || !errors.Is(err, snmp.ErrStore) {
		t.Errorf("commit on an invalid store: %v", err)
	}
	if _, err := d.AddSNMPCredential(accounts.Root, snmp.Credential{Name: "ro", Kind: "v2c", Community: "community-2"}, false); err == nil {
		t.Error("added to an invalid store")
	}
	if got, _ := os.ReadFile(creds); string(got) != bad {
		t.Error("an invalid store was written over")
	}
	if st := d.SNMP(); st.CredsError == "" || strings.Contains(st.CredsError, "auth-pass-1") || strings.Contains(st.CredsError, "community-1") {
		t.Errorf("status: %q", st.CredsError)
	}
	if len(fake.applied) != 0 {
		t.Error("snmpd configured from an invalid store")
	}
}

// H-03: a start systemd accepted but snmpd didn't survive is retried with
// backoff, a bounded number of times, then left; a commit tries again.
func TestSNMPStartFailureBounded(t *testing.T) {
	d, fake, _ := snmpDaemon(t)
	clock := time.Now()
	d.Now = func() time.Time { return clock }
	fake.set(func(f *fakeSNMPD) { f.failStart = true })
	if _, err := d.AddSNMPCredential(accounts.Root, nmsV3, false); err != nil {
		t.Fatal(err)
	}
	d.SetCandidate(append(lab(t), []byte(snmpYAML)...))
	if _, err := d.Commit("steve", "snmp", 0); err != nil {
		t.Fatal(err)
	}
	if st := d.SNMP(); st.State != "starting" || st.Running || !st.ConfigCurrent {
		t.Fatalf("after the commit: %+v", st)
	}
	// Run the 10 s reconcile for a long simulated hour.
	for i := 0; i < 360; i++ {
		clock = clock.Add(10 * time.Second)
		d.ReconcileRoutes()
	}
	st := d.SNMP()
	if st.State != "gave-up" || fake.restarts != snmpRetryMax-1 || !strings.Contains(st.Error, "didn't stay up") {
		t.Fatalf("after an hour of failures: state %s, %d restarts, %q", st.State, fake.restarts, st.Error)
	}
	// A commit gives it a fresh set of tries; this time it starts.
	fake.set(func(f *fakeSNMPD) { f.failStart = false })
	if _, err := d.Commit("steve", "again", 0); err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(10 * time.Second)
	d.ReconcileRoutes()
	if st := d.SNMP(); st.State != "running" || st.VerifiedAt == nil || st.Error != "" {
		t.Errorf("after recovery: %+v", st)
	}
}

// H-03: snmpd dying unexpectedly is noticed and restarted; the backoff
// grows between attempts.
func TestSNMPUnexpectedExit(t *testing.T) {
	d, fake, _ := snmpDaemon(t)
	clock := time.Now()
	d.Now = func() time.Time { return clock }
	d.AddSNMPCredential(accounts.Root, nmsV3, false)
	d.SetCandidate(append(lab(t), []byte(snmpYAML)...))
	d.Commit("steve", "snmp", 0)
	clock = clock.Add(10 * time.Second)
	d.ReconcileRoutes()
	if st := d.SNMP(); st.State != "running" {
		t.Fatalf("not running: %+v", st)
	}
	fake.set(func(f *fakeSNMPD) { f.running = false })
	clock = clock.Add(10 * time.Second)
	d.ReconcileRoutes()
	if fake.restarts != 1 {
		t.Fatalf("restarts after an exit: %d", fake.restarts)
	}
	clock = clock.Add(10 * time.Second)
	d.ReconcileRoutes()
	if st := d.SNMP(); st.State != "running" || st.Attempts != 0 {
		t.Errorf("after the restart: %+v", st)
	}
	if snmpRetryDelay(1) != 10*time.Second || snmpRetryDelay(3) != 40*time.Second || snmpRetryDelay(20) != snmpBackoffMax {
		t.Error("backoff")
	}
}

// H-03: a credential rotation whose restart fails is visible: the config
// is current on disk, the agent isn't running, and the status says why.
func TestSNMPRotationThenRestartFailure(t *testing.T) {
	d, fake, _ := snmpDaemon(t)
	clock := time.Now()
	d.Now = func() time.Time { return clock }
	d.AddSNMPCredential(accounts.Root, nmsV3, false)
	d.SetCandidate(append(lab(t), []byte(snmpYAML)...))
	d.Commit("steve", "snmp", 0)
	clock = clock.Add(10 * time.Second)
	d.ReconcileRoutes()
	fake.set(func(f *fakeSNMPD) { f.failStart = true })
	rotated := nmsV3
	rotated.AuthPass = "auth-pass-2"
	if _, err := d.AddSNMPCredential(accounts.Root, rotated, true); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(fake.applied[len(fake.applied)-1], `"auth-pass-2"`) {
		t.Fatal("rotated secret not written")
	}
	clock = clock.Add(30 * time.Second)
	d.ReconcileRoutes()
	st := d.SNMP()
	if st.Running || !st.ConfigCurrent || (st.State != "failed" && st.State != "starting") || st.Error == "" {
		t.Errorf("after a failed restart: %+v", st)
	}
}

// H-03: snmpd installed later (an upgrade's packages install in the
// background) is configured when it appears, with no retries counted.
func TestSNMPDelayedInstall(t *testing.T) {
	d, fake, _ := snmpDaemon(t)
	fake.set(func(f *fakeSNMPD) { f.notInstalled = true })
	d.AddSNMPCredential(accounts.Root, nmsV3, false)
	d.SetCandidate(append(lab(t), []byte(snmpYAML)...))
	res, err := d.Commit("steve", "snmp", 0)
	if err != nil || !strings.Contains(strings.Join(res.Warnings, " "), "isn't installed yet") {
		t.Fatalf("commit: %v %+v", err, res)
	}
	for i := 0; i < 5; i++ {
		d.ReconcileRoutes()
	}
	if st := d.SNMP(); st.State != "waiting-install" || st.Attempts != 0 || len(fake.applied) != 0 {
		t.Fatalf("while not installed: %+v, %d applies", st, len(fake.applied))
	}
	fake.set(func(f *fakeSNMPD) { f.notInstalled = false })
	d.ReconcileRoutes()
	d.ReconcileRoutes()
	if st := d.SNMP(); st.State != "running" {
		t.Errorf("after the install: %+v", st)
	}
}

// H-03: turning SNMP off during recovery stops it, and nothing retries.
func TestSNMPOffDuringRecovery(t *testing.T) {
	d, fake, _ := snmpDaemon(t)
	clock := time.Now()
	d.Now = func() time.Time { return clock }
	fake.set(func(f *fakeSNMPD) { f.failStart = true })
	d.AddSNMPCredential(accounts.Root, nmsV3, false)
	d.SetCandidate(append(lab(t), []byte(snmpYAML)...))
	d.Commit("steve", "snmp", 0)
	clock = clock.Add(30 * time.Second)
	d.ReconcileRoutes()
	d.SetCandidate(lab(t))
	d.Commit("steve", "snmp off", 0)
	n := fake.restarts
	for i := 0; i < 60; i++ {
		clock = clock.Add(10 * time.Second)
		d.ReconcileRoutes()
	}
	if st := d.SNMP(); st.State != "off" || fake.restarts != n || fake.applied[len(fake.applied)-1] != "" {
		t.Errorf("after SNMP off: %+v, restarts %d -> %d", st, n, fake.restarts)
	}
}

// slowCounters is a counter reader that can fail or hang.
type slowCounters struct {
	*nft.Fake
	mu    sync.Mutex
	fail  error
	block chan struct{} // while non-nil and open, reads hang
	calls atomic.Int64
	data  map[string]map[string]nft.Counter
}

func (c *slowCounters) Counters(table string, chains ...string) (map[string]map[string]nft.Counter, error) {
	c.calls.Add(1)
	c.mu.Lock()
	block, fail, data := c.block, c.fail, c.data
	c.mu.Unlock()
	if block != nil {
		<-block
	}
	if fail != nil {
		return nil, fail
	}
	return data, nil
}

func quickMetrics(t *testing.T) {
	t.Helper()
	oldAge, oldWait, oldSlow := MetricsMaxAge, MetricsWait, slowWait
	MetricsMaxAge, MetricsWait, slowWait = 0, 500*time.Millisecond, 200*time.Millisecond
	t.Cleanup(func() { MetricsMaxAge, MetricsWait, slowWait = oldAge, oldWait, oldSlow })
}

// H-02: the first collection while a commit holds d.mu says "never" for
// what it couldn't read, with no made-up values; afterwards it's current.
func TestMetricsFirstCollectionDuringCommit(t *testing.T) {
	quickMetrics(t)
	d, _ := setup(t)
	d.SetCandidate(lab(t))
	d.Commit("steve", "lab", 0)
	d.metrics.collectMu.Lock()
	d.metrics.latest = nil // no collection yet
	d.metrics.collectMu.Unlock()
	d.metrics.slow.Store(nil)
	d.mu.Lock()
	s := d.Metrics()
	for _, sec := range []string{"config", "ips", "decryption", "nat"} {
		if st := s.Sections[sec].State; st != metrics.Never {
			t.Errorf("%s: %s, want never", sec, st)
		}
	}
	if s.Sections["system"].State != metrics.Current || s.Config.RunningRevision != 0 || s.IPS.State != "" {
		t.Errorf("first snapshot: %+v %+v", s.Sections["system"], s.Config)
	}
	for _, sv := range s.Services {
		if (sv.Name == "suricata" || sv.Name == "tlsd") && !sv.Unknown {
			t.Errorf("%s not unknown before the IPS/decryption reads", sv.Name)
		}
	}
	d.mu.Unlock()
	waitFor(t, func() bool { return d.metrics.slow.Load() != nil })
	s = d.Metrics()
	if s.Sections["config"].State != metrics.Current || s.Config.RunningRevision != 1 {
		t.Errorf("after the commit: %+v rev %d", s.Sections["config"], s.Config.RunningRevision)
	}
}

// H-02: during a long commit the last values are kept but marked stale,
// with their read time, and a fresh read makes them current again.
func TestMetricsStaleDuringLongCommit(t *testing.T) {
	quickMetrics(t)
	d, _ := setup(t)
	d.SetCandidate(lab(t))
	d.Commit("steve", "lab", 0)
	first := d.Metrics()
	if first.Sections["config"].State != metrics.Current {
		t.Fatalf("first: %+v", first.Sections)
	}
	read := first.Sections["config"].CollectedAt
	d.mu.Lock()
	time.Sleep(20 * time.Millisecond)
	s := d.Metrics()
	d.mu.Unlock()
	for _, sec := range []string{"config", "ips", "decryption", "nat"} {
		st := s.Sections[sec]
		if st.State != metrics.Stale || st.CollectedAt == nil || !st.CollectedAt.Equal(*read) || st.Error == "" {
			t.Errorf("%s during the commit: %+v", sec, st)
		}
	}
	if s.Config.RunningRevision != 1 || !s.Time.After(*read) {
		t.Errorf("stale values lost or snapshot time wrong: rev %d, time %v vs read %v", s.Config.RunningRevision, s.Time, read)
	}
	for _, sv := range s.Services {
		if sv.Name == "suricata" && !sv.Unknown {
			t.Error("suricata's state presented as fresh from a stale read")
		}
	}
	waitFor(t, func() bool { return !d.metrics.slowBusy.Load() })
	time.Sleep(5 * time.Millisecond)
	if s := d.Metrics(); s.Sections["config"].State != metrics.Current {
		t.Errorf("after the commit: %+v", s.Sections["config"])
	}
}

// M-02/H-02: counter failures make the rules section failed (never read)
// or stale (last known values kept), never zeros; recovery makes it
// current, and a legitimate zero is current.
func TestMetricsCounterFailureAndRecovery(t *testing.T) {
	quickMetrics(t)
	d, f := setup(t)
	d.SetCandidate(lab(t))
	d.Commit("steve", "lab", 0)
	c := &slowCounters{Fake: f, fail: fmt.Errorf("%w: chain forward: exit status 1: Operation not permitted", nft.ErrCounters)}
	d.nft = c
	s := d.Metrics()
	if st := s.Sections["rules"]; st.State != metrics.Failed || !strings.Contains(st.Error, "Operation not permitted") || len(s.Rules) != 0 {
		t.Fatalf("never read: %+v, %d rules", st, len(s.Rules))
	}
	c.mu.Lock()
	c.fail, c.data = nil, map[string]map[string]nft.Counter{"forward": {"rule:allow-web": {Packets: 7, Bytes: 700}}}
	c.mu.Unlock()
	s = d.Metrics()
	if s.Sections["rules"].State != metrics.Current || s.Rules[ruleIndex(s, "allow-web")].Packets != 7 {
		t.Fatalf("after recovery: %+v", s.Sections["rules"])
	}
	c.mu.Lock()
	c.fail = fmt.Errorf("%w: malformed", nft.ErrCounters)
	c.mu.Unlock()
	s = d.Metrics()
	if st := s.Sections["rules"]; st.State != metrics.Stale || s.Rules[ruleIndex(s, "allow-web")].Packets != 7 {
		t.Errorf("failure after success: %+v, rules %+v", st, s.Rules)
	}
	// Present but nothing counted (a reset, a new ruleset): a real zero.
	c.mu.Lock()
	c.fail, c.data = nil, map[string]map[string]nft.Counter{"forward": {}}
	c.mu.Unlock()
	s = d.Metrics()
	if s.Sections["rules"].State != metrics.Current || s.Rules[ruleIndex(s, "allow-web")].Packets != 0 {
		t.Errorf("legitimate zero: %+v", s.Rules)
	}
}

func ruleIndex(s metrics.Snapshot, name string) int {
	for i, r := range s.Rules {
		if r.Name == name {
			return i
		}
	}
	return -1
}

// M-01: many concurrent scrapers share collections; a hung counter read
// doesn't pile up collections, goroutines or subprocesses, and the
// collector recovers once it returns.
func TestMetricsBoundedUnderLoad(t *testing.T) {
	quickMetrics(t)
	MetricsMaxAge = 2 * time.Second
	d, f := setup(t)
	d.SetCandidate(lab(t))
	d.Commit("steve", "lab", 0)
	c := &slowCounters{Fake: f, data: map[string]map[string]nft.Counter{}}
	d.nft = c
	d.Metrics()
	base := d.metrics.collects.Load()
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); d.Metrics() }()
	}
	wg.Wait()
	if n := d.metrics.collects.Load() - base; n != 0 {
		t.Errorf("100 scrapes within the max age ran %d collections", n)
	}

	// A hung read: callers wait at most MetricsWait and share the one
	// collection under way.
	MetricsMaxAge = 0
	block := make(chan struct{})
	c.mu.Lock()
	c.block = block
	c.mu.Unlock()
	goroutines := runtime.NumGoroutine()
	readsBefore := c.calls.Load()
	start := time.Now()
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); d.Metrics() }()
	}
	wg.Wait()
	if took := time.Since(start); took > 3*time.Second {
		t.Errorf("scrapes behind a hung read took %v", took)
	}
	// One collection (rules) and one read behind d.mu (NAT): at most two
	// reads hang, however many scrapes wait.
	if n := c.calls.Load() - readsBefore; n > 2 {
		t.Errorf("%d counter reads started while one hung", n)
	}
	if g := runtime.NumGoroutine(); g > goroutines+10 {
		t.Errorf("goroutines grew from %d to %d", goroutines, g)
	}
	close(block)
	c.mu.Lock()
	c.block = nil
	c.mu.Unlock()
	waitFor(t, func() bool {
		d.metrics.collectMu.Lock()
		defer d.metrics.collectMu.Unlock()
		return d.metrics.inflight == nil
	})
	if s := d.Metrics(); s.Sections["rules"].State != metrics.Current {
		t.Errorf("after the hang: %+v", s.Sections["rules"])
	}
}

// API key lifecycle: scopes are enforced alike on every endpoint, and a
// deleted key stops working everywhere at once.
func TestAPIKeyLifecycleAcrossEndpoints(t *testing.T) {
	d, _ := setup(t)
	withAccounts(t, d)
	d.SetCandidate(lab(t))
	d.Commit("steve", "lab", 0)
	keyFile := filepath.Join(t.TempDir(), "api-keys")
	os.WriteFile(keyFile, nil, 0o600)
	d.SetAPIKeysFile(keyFile)
	srv := httptest.NewServer(d.APIHandler(nil))
	defer srv.Close()
	add := func(name string, scopes ...string) string {
		k, err := d.AddAPIKey(accounts.Root, name, scopes)
		if err != nil {
			t.Fatal(err)
		}
		return k.Key
	}
	read, write, mon := add("read", ScopeTagsRead), add("write", ScopeTagsWrite), add("mon", ScopeMetricsRead)
	do := func(method, path, key, body string) int {
		req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
		if key != "" {
			req.Header.Set("Authorization", "Bearer "+key)
		}
		if method == "POST" && path != "/api/" {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp.StatusCode
	}
	reg := `{"ip":"10.10.1.10","tags":["quarantine"],"ttl":60}`
	type call struct{ method, path, body string }
	listTags, register, scrape := call{"GET", "/api/v1/tags", ""}, call{"POST", "/api/v1/tags/register", reg}, call{"GET", "/metrics", ""}
	cases := []struct {
		c    call
		key  string
		want int
	}{
		{listTags, "", 401}, {listTags, read, 200}, {listTags, write, 403}, {listTags, mon, 403},
		{register, read, 403}, {register, write, 200}, {register, mon, 403},
		{scrape, read, 403}, {scrape, write, 403}, {scrape, mon, 200}, {scrape, "not-a-key-0000000000000000", 401},
	}
	for _, tc := range cases {
		if got := do(tc.c.method, tc.c.path, tc.key, tc.c.body); got != tc.want {
			t.Errorf("%s %s with %q: %d, want %d", tc.c.method, tc.c.path, keyName(tc.key, read, write, mon), got, tc.want)
		}
	}
	// Revoked: refused at once, everywhere (the XML endpoint included).
	for _, n := range []string{"read", "write", "mon"} {
		if err := d.DeleteAPIKey(accounts.Root, n); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		c   call
		key string
	}{{listTags, read}, {register, write}, {scrape, mon}} {
		if got := do(tc.c.method, tc.c.path, tc.key, tc.c.body); got != 401 {
			t.Errorf("revoked %s on %s: %d", keyName(tc.key, read, write, mon), tc.c.path, got)
		}
	}
	xml := "type=user-id&key=" + write + "&cmd=%3Cuid-message%2F%3E"
	req, _ := http.NewRequest("POST", srv.URL+"/api/", strings.NewReader(xml))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 && resp.StatusCode != 403 {
		t.Errorf("revoked key on the XML endpoint: %d", resp.StatusCode)
	}
	// Only superusers manage keys.
	if _, err := d.AddAPIKey(accounts.Caller{Name: "ops", Via: "cli"}, "x", []string{ScopeMetricsRead}); err == nil {
		t.Error("an admin added a key")
	}
}

func keyName(k, read, write, mon string) string {
	switch k {
	case read:
		return "tags:read"
	case write:
		return "tags:write"
	case mon:
		return "metrics:read"
	case "":
		return "no key"
	}
	return "unknown key"
}
