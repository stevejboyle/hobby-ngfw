package daemon

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stevejboyle/sjb-os/internal/compiler"
	"github.com/stevejboyle/sjb-os/internal/ips"
)

// Exception codes and Suricata's asynchronous reloads (ChatGPT's review of
// 0.9.12-r01): a code may not take a new signature's meaning while a rules
// file Suricata may still run gives it another one. These tests drive the
// daemon with a fake Suricata whose reload can be held (a slow reload) or
// failed; they check the ruleset and rules file the daemon writes, not
// live traffic.

// excYAML is examples/ips.yaml with one exception per SID, on web-in.
func excYAML(t *testing.T, sids ...int) []byte {
	t.Helper()
	b, err := os.ReadFile("../../examples/ips.yaml")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	i, j := strings.Index(s, "ips_exceptions:\n"), strings.Index(s, "\nrules:\n")
	var ex strings.Builder
	ex.WriteString("ips_exceptions:\n")
	for _, sid := range sids {
		fmt.Fprintf(&ex, "  - name: e%d\n    sid: \"%d\"\n    rules: [web-in]\n", sid, sid)
	}
	if len(sids) == 0 {
		ex.Reset()
		ex.WriteString("ips_exceptions: []\n")
	}
	return []byte(s[:i] + ex.String() + s[j+1:])
}

func commitExc(t *testing.T, d *Daemon, sids ...int) *CommitResult {
	t.Helper()
	if err := d.SetCandidate(excYAML(t, sids...)); err != nil {
		t.Fatal(err)
	}
	res, err := d.Commit("t", "exceptions", 0)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// settle waits for the daemon's reload confirmation to finish.
func settle(t *testing.T, d *Daemon) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(2 * time.Millisecond) {
		d.mu.Lock()
		busy := d.ips.confirming
		d.mu.Unlock()
		if !busy {
			return
		}
	}
	t.Fatal("reload confirmation still running")
}

func liveFiles(d *Daemon) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.ips.files)
}

// excLine reports whether the ruleset has an exception line for code.
func excLine(ruleset string, code uint32) bool {
	return strings.Contains(ruleset, fmt.Sprintf("meta mark and 0x%08x == 0x%08x", compiler.IPSExcMask|compiler.IPSPlainBit, code))
}

// markOf is the nfq_set_mark the rules file gives sid.
func markOf(t *testing.T, e *ips.Engine, sid int) string {
	t.Helper()
	b, _ := os.ReadFile(filepath.Join(e.Dir, ips.RulesFile))
	for _, l := range strings.Split(string(b), "\n") {
		if strings.Contains(l, fmt.Sprintf("sid:%d;", sid)) {
			if i := strings.Index(l, "nfq_set_mark:"); i >= 0 {
				return strings.SplitN(l[i+len("nfq_set_mark:"):], "/", 2)[0]
			}
		}
	}
	t.Fatalf("sid %d not in the rules file", sid)
	return ""
}

// holdReloads makes Suricata's reloads take until release is called.
func holdReloads(t *testing.T, d *Daemon, fs *fakeSuricata) (release func()) {
	gate := make(chan struct{})
	fs.reload.set(gate, nil)
	var once sync.Once
	release = func() {
		once.Do(func() {
			fs.reload.set(nil, nil)
			close(gate)
		})
	}
	t.Cleanup(func() {
		release()
		settle(t, d) // let the confirmation finish before the state dir goes
	})
	return release
}

// withSignatures gives the engine a downloaded rule set with these SIDs
// (as if fetched from ET Open), so exceptions on them change the rules
// file.
func withSignatures(t *testing.T, e *ips.Engine, sids ...int) {
	t.Helper()
	var rules bytes.Buffer
	for _, sid := range sids {
		fmt.Fprintf(&rules, "alert http any any -> any any (msg:\"ET TEST %d\"; content:\"x%dx\"; classtype:trojan-activity; sid:%d; rev:1; metadata:signature_severity Major;)\n", sid, sid, sid)
	}
	var tgz bytes.Buffer
	zw := gzip.NewWriter(&tgz)
	tw := tar.NewWriter(zw)
	tw.WriteHeader(&tar.Header{Name: "rules/emerging-test.rules", Mode: 0o644, Size: int64(rules.Len()), Typeflag: tar.TypeReg})
	tw.Write(rules.Bytes())
	tw.Close()
	zw.Close()
	p := filepath.Join(e.Dir, ips.CacheFile)
	os.MkdirAll(filepath.Dir(p), 0o755)
	if err := os.WriteFile(p, tgz.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

func ipsDaemon(t *testing.T, dir string) (*Daemon, *fakeSuricata, *ips.Engine) {
	d, _ := setupAt(t, dir)
	fs := &fakeSuricata{mem: 8 << 30}
	e := testEngine(t, d)
	d.SetIPS(fs, e)
	return d, fs, e
}

// Remove A's exception, commit, add B's while Suricata is still loading:
// B can't take A's code. Once the reload is confirmed, the code is free.
func TestIPSCodeNotReusedDuringSlowReload(t *testing.T) {
	dir := t.TempDir()
	d, fs, e := ipsDaemon(t, dir)
	nf := d.nft.(interface{ Last() string })
	commitExc(t, d, 9900001)
	settle(t, d)
	a := d.ipsCodes[9900001]
	if a == 0 || liveFiles(d) != 1 {
		t.Fatalf("code %#x, %d live files", a, liveFiles(d))
	}

	release := holdReloads(t, d, fs)
	commitExc(t, d)          // A removed: a new rules file, its reload held
	commitExc(t, d, 9900002) // B added before Suricata confirms
	b := d.ipsCodes[9900002]
	if b == 0 || b == a {
		t.Fatalf("B's code %#x (A had %#x): reused while A's rules file may still run", b, a)
	}
	if !excLine(nf.Last(), b) || excLine(nf.Last(), a) {
		t.Fatalf("ruleset: want B's line (%#x) only:\n%s", b, nf.Last())
	}
	var vb uint32
	fmt.Sscanf(markOf(t, e, 9900002), "0x%x", &vb)
	if vb&compiler.IPSExcMask != b || vb&compiler.IPSPlainBit != 0 {
		t.Fatalf("rules file marks 9900002 with %#x, want code %#x", vb, b)
	}
	var v uint32
	fmt.Sscanf(markOf(t, e, 9900001), "0x%x", &v)
	if v&compiler.IPSExcMask != 0 || v&compiler.IPSPlainBit == 0 {
		t.Fatalf("9900001 should mark plain now: %#x", v)
	}
	if n := liveFiles(d); n != 3 {
		t.Fatalf("%d live files while the reload is held, want 3", n)
	}

	// The reload completes: the older files are released.
	release()
	settle(t, d)
	d.ReconcileRoutes() // the periodic pass confirms anything left
	settle(t, d)
	if n := liveFiles(d); n != 1 {
		t.Fatalf("%d live files after the reload, want 1", n)
	}
	commitExc(t, d, 9900002, 9900003)
	settle(t, d)
	if d.ipsCodes[9900002] != b {
		t.Fatalf("B moved: %v", d.ipsCodes)
	}
	if d.ipsCodes[9900003] != a {
		t.Fatalf("after the reload, A's code is free again: got %#x, want %#x", d.ipsCodes[9900003], a)
	}
}

// A reload that fails releases nothing; the periodic pass retries.
func TestIPSCodeReservedWhileReloadFails(t *testing.T) {
	d, fs, _ := ipsDaemon(t, t.TempDir())
	commitExc(t, d, 9900001)
	settle(t, d)
	a := d.ipsCodes[9900001]
	fs.reload.set(nil, errors.New("Suricata's command socket: connection refused"))
	commitExc(t, d)
	settle(t, d)
	d.ReconcileRoutes()
	settle(t, d)
	if fs.reload.count() < 2 || liveFiles(d) != 2 {
		t.Fatalf("%d reloads, %d live files: a failed reload must release nothing", fs.reload.count(), liveFiles(d))
	}
	commitExc(t, d, 9900002)
	settle(t, d)
	if d.ipsCodes[9900002] == a {
		t.Fatalf("A's code reused after a failed reload")
	}
	fs.reload.set(nil, nil)
	d.ReconcileRoutes()
	settle(t, d)
	if n := liveFiles(d); n != 1 {
		t.Fatalf("%d live files once a reload succeeds, want 1", n)
	}
}

// All 35 codes in use, then every signature replaced while the old file
// may still run: no code is reused; the new exceptions stay inactive, with
// warnings, until the old file is released and the config is committed
// again.
func TestIPSCodesExhaustedStayInactive(t *testing.T) {
	d, fs, e := ipsDaemon(t, t.TempDir())
	nf := d.nft.(interface{ Last() string })
	var old, repl []int
	for i := 0; i < 35; i++ {
		old = append(old, 2000000+i)
		repl = append(repl, 3000000+i)
	}
	withSignatures(t, e, append(append([]int{}, old...), repl...)...)
	commitExc(t, d, old...)
	settle(t, d)
	used := map[uint32]bool{}
	for _, c := range d.ipsCodes {
		used[c] = true
	}
	release := holdReloads(t, d, fs)
	res := commitExc(t, d, repl...)
	if len(d.ipsCodes) != 0 {
		t.Fatalf("codes given while all 35 may still mean the old signatures: %v", d.ipsCodes)
	}
	w := strings.Join(res.Warnings, "\n")
	if strings.Count(w, "inactive: no exception code") != 35 {
		t.Fatalf("want 35 inactive warnings:\n%s", w)
	}
	if strings.Contains(nf.Last(), "ips-exception:") {
		t.Fatalf("no exception line may be compiled:\n%s", nf.Last())
	}
	for _, es := range d.IPS().Exceptions {
		if !es.Inactive {
			t.Fatalf("%s should show inactive", es.Name)
		}
	}
	release()
	settle(t, d)
	d.ReconcileRoutes()
	settle(t, d)
	// Commit again (one exception changed so the candidate differs): now
	// every replacement gets a code.
	b := excYAML(t, repl...)
	b = []byte(strings.Replace(string(b), "  - name: e3000000\n    sid: \"3000000\"\n    rules: [web-in]\n", "  - name: e3000000\n    sid: \"3000000\"\n    rules: [web-in]\n    action: ignore\n", 1))
	if err := d.SetCandidate(b); err != nil {
		t.Fatal(err)
	}
	res, err := d.Commit("t", "again", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.ipsCodes) != 35 || strings.Contains(strings.Join(res.Warnings, "\n"), "inactive") {
		t.Fatalf("after the reload: %d codes, warnings %v", len(d.ipsCodes), res.Warnings)
	}
	if d.IPS().Exceptions[0].Inactive {
		t.Fatal("still shown inactive")
	}
}

// A restart of ngfwd during a held reload keeps the live files: the new
// daemon still won't reuse the removed signature's code.
func TestIPSCodesSurviveRestart(t *testing.T) {
	dir := t.TempDir()
	d, fs, _ := ipsDaemon(t, dir)
	commitExc(t, d, 9900001)
	settle(t, d)
	a := d.ipsCodes[9900001]
	holdReloads(t, d, fs)
	commitExc(t, d) // A removed; Suricata hasn't confirmed

	d2, _, _ := ipsDaemon(t, dir)
	if n := liveFiles(d2); n != 2 {
		t.Fatalf("restart forgot the live files: %d", n)
	}
	commitExc(t, d2, 9900002)
	if c := d2.ipsCodes[9900002]; c == 0 || c == a {
		t.Fatalf("after a restart B got %#x, A's code was %#x", c, a)
	}
}

// Rolling back to a revision with A's exception while B's file is live:
// A keeps its own code, which never meant anything else, and a third
// signature takes neither.
func TestIPSCodesAcrossRollback(t *testing.T) {
	d, fs, _ := ipsDaemon(t, t.TempDir())
	commitExc(t, d, 9900001)
	settle(t, d)
	a := d.ipsCodes[9900001]
	revA, _, _ := d.store.Running()
	holdReloads(t, d, fs)
	commitExc(t, d, 9900002)
	b := d.ipsCodes[9900002]
	if b == 0 || b == a {
		t.Fatalf("B got %#x, A's code %#x is still live", b, a)
	}
	if _, err := d.Rollback(revA, "t"); err != nil {
		t.Fatal(err)
	}
	if d.ipsCodes[9900001] != a {
		t.Fatalf("rollback gave A %#x, it had %#x", d.ipsCodes[9900001], a)
	}
	commitExc(t, d, 9900001, 9900003)
	if c := d.ipsCodes[9900003]; c == a || c == b || c == 0 {
		t.Fatalf("C got %#x (A %#x, B %#x)", c, a, b)
	}
}

// An upgrade from a version that kept no record, with Suricata running:
// every code the running config doesn't use is held until a reload is
// confirmed.
func TestIPSCodesUnknownAfterUpgrade(t *testing.T) {
	dir := t.TempDir()
	d, _, _ := ipsDaemon(t, dir)
	commitExc(t, d, 9900001)
	settle(t, d)
	a := d.ipsCodes[9900001]
	os.Remove(filepath.Join(dir, ipsFilesFile))

	d2, _ := setupAt(t, dir) // Start before SetIPS: no engine known, so no reservation
	if n := liveFiles(d2); n != 1 {
		t.Fatalf("without a running engine, only the running codes are held: %d files", n)
	}
	os.Remove(filepath.Join(dir, ipsFilesFile))
	d3 := New(d2.store, d2.tags, d2.nft, d2.ct, d2.log)
	fs := &fakeSuricata{mem: 8 << 30, running: true}
	holdReloads(t, d3, fs)
	d3.SetIPS(fs, testEngine(t, d3))
	if err := d3.Start(); err != nil {
		t.Fatal(err)
	}
	commitExc(t, d3, 9900001, 9900002)
	if d3.ipsCodes[9900001] != a {
		t.Fatalf("A kept %#x? got %#x", a, d3.ipsCodes[9900001])
	}
	if _, ok := d3.ipsCodes[9900002]; ok {
		t.Fatalf("B got %#x before Suricata confirmed what it runs", d3.ipsCodes[9900002])
	}
}
