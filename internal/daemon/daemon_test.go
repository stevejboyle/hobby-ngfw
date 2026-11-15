package daemon

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stevejboyle/hobby-ngfw/internal/config"
	"github.com/stevejboyle/hobby-ngfw/internal/conntrack"
	"github.com/stevejboyle/hobby-ngfw/internal/nft"
	"github.com/stevejboyle/hobby-ngfw/internal/routes"
	"github.com/stevejboyle/hobby-ngfw/internal/store"
	"github.com/stevejboyle/hobby-ngfw/internal/tags"
)

func setup(t *testing.T) (*Daemon, *nft.Fake) {
	t.Helper()
	return setupAt(t, t.TempDir())
}

// setupAt starts a daemon on an existing state directory: calling it twice
// on one directory simulates an ngfwd restart.
func setupAt(t *testing.T, dir string) (*Daemon, *nft.Fake) {
	t.Helper()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	reg, err := tags.Open(filepath.Join(dir, "tags.json"))
	if err != nil {
		t.Fatal(err)
	}
	f := &nft.Fake{}
	d := New(st, reg, f, &conntrack.Fake{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := d.Start(); err != nil {
		t.Fatal(err)
	}
	return d, f
}

func lab(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("../../examples/lab.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// withoutWeb is the lab config minus the allow-web rule.
func withoutWeb(t *testing.T) []byte {
	s := string(lab(t))
	i := strings.Index(s, "  - name: allow-web")
	return []byte(s[:i])
}

func TestStartWithNothingIsDefaultDeny(t *testing.T) {
	_, f := setup(t)
	if !strings.Contains(f.Last(), "policy drop;") {
		t.Fatalf("start should apply a default-deny ruleset:\n%s", f.Last())
	}
}

func TestCommitAndRollback(t *testing.T) {
	d, f := setup(t)
	if err := d.SetCandidate(lab(t)); err != nil {
		t.Fatal(err)
	}
	r1, err := d.Commit("steve", "lab", 0)
	if err != nil || r1.Revision.N != 1 {
		t.Fatalf("commit 1: %+v %v", r1, err)
	}
	if !strings.Contains(f.Last(), "rule:allow-web") {
		t.Fatal("rev 1 should contain allow-web")
	}

	if err := d.SetCandidate(withoutWeb(t)); err != nil {
		t.Fatal(err)
	}
	if diff, _ := d.Diff(); !strings.Contains(diff, "- ") {
		t.Fatalf("diff should show removed lines, got %q", diff)
	}
	if _, err := d.Commit("steve", "drop web", 0); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(f.Last(), "rule:allow-web") {
		t.Fatal("rev 2 should not contain allow-web")
	}

	r3, err := d.Rollback(1, "steve")
	if err != nil || r3.Revision.N != 3 || r3.Revision.Message != "rollback to 1" {
		t.Fatalf("rollback: %+v %v", r3, err)
	}
	if !strings.Contains(f.Last(), "rule:allow-web") {
		t.Fatal("rollback should restore allow-web")
	}
	if _, err := d.Rollback(99, "steve"); err == nil {
		t.Fatal("rollback to missing revision should fail")
	}
}

func TestInvalidCandidateRejected(t *testing.T) {
	d, _ := setup(t)
	if err := d.SetCandidate([]byte("zones:\n  - name: any\n")); err == nil {
		t.Fatal("invalid candidate accepted")
	}
	if _, err := d.Commit("x", "", 0); err == nil {
		t.Fatal("commit of empty candidate should fail")
	}
}

func TestFailedApplyKeepsRunning(t *testing.T) {
	d, f := setup(t)
	d.SetCandidate(lab(t))
	if _, err := d.Commit("steve", "lab", 0); err != nil {
		t.Fatal(err)
	}
	d.SetCandidate(withoutWeb(t))
	f.FailOn = "rule:allow-ping"
	if _, err := d.Commit("steve", "broken", 0); err == nil {
		t.Fatal("expected commit failure")
	}
	if n, _, _ := d.Running(); n != 1 {
		t.Fatalf("running should still be 1, got %d", n)
	}
}

func TestCommitConfirmed(t *testing.T) {
	d, f := setup(t)
	d.SetCandidate(lab(t))
	d.Commit("steve", "lab", 0)

	// Unconfirmed commit rolls back to revision 1.
	d.SetCandidate(withoutWeb(t))
	res, err := d.Commit("steve", "risky", 100*time.Millisecond)
	if err != nil || res.ConfirmBy == nil {
		t.Fatalf("commit confirmed: %+v %v", res, err)
	}
	waitFor(t, func() bool { n, _, _ := d.Running(); return n == 3 })
	if !strings.Contains(f.Last(), "rule:allow-web") {
		t.Fatal("auto-rollback should restore allow-web")
	}
	revs, _ := d.Revisions()
	if !strings.Contains(revs[2].Message, "auto-rollback") {
		t.Fatalf("rev 3 message = %q", revs[2].Message)
	}

	// Confirmed commit stays.
	d.SetCandidate(withoutWeb(t))
	if _, err := d.Commit("steve", "risky", 100*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if err := d.Confirm(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	if n, _, _ := d.Running(); n != 4 {
		t.Fatalf("confirmed commit should stay running, got %d", n)
	}
	if err := d.Confirm(); err == nil {
		t.Fatal("second confirm should fail")
	}
}

func TestFirstCommitUnconfirmedFallsBackToDefaultDeny(t *testing.T) {
	d, f := setup(t)
	d.SetCandidate(lab(t))
	if _, err := d.Commit("steve", "first", 50*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { n, _, _ := d.Running(); return n == 0 })
	if strings.Contains(f.Last(), "rule:") {
		t.Fatalf("expected empty default-deny ruleset:\n%s", f.Last())
	}
}

func TestTagsFollowSets(t *testing.T) {
	d, f := setup(t)
	ip := netip.MustParseAddr("10.10.1.10")

	// Before any group uses the tag: registry only, nothing applied.
	before := len(f.Applied)
	if err := d.RegisterTags(ip, []string{"quarantine"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	if len(f.Applied) != before {
		t.Fatal("no set exists yet; nothing should be applied")
	}

	// Commit: the registration is written into the set in the same transaction.
	d.SetCandidate(lab(t))
	d.Commit("steve", "lab", 0)
	if !strings.Contains(f.Last(), "elements = { 10.10.1.10 timeout") {
		t.Fatalf("commit should carry the registration:\n%s", f.Last())
	}

	// Now register and unregister go straight to the set.
	other := netip.MustParseAddr("10.10.1.11")
	if err := d.RegisterTags(other, []string{"quarantine"}, 0); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.Last(), "add element inet ngfw dag_quarantine { 10.10.1.11 }") {
		t.Fatalf("register script:\n%s", f.Last())
	}
	ct := d.ct.(*conntrack.Fake)
	if len(ct.Flushed) != 1 || ct.Flushed[0] != other {
		t.Fatalf("register should flush the host's sessions, flushed %v", ct.Flushed)
	}
	if ct.All != 1 {
		t.Fatalf("start should flush all sessions once, got %d", ct.All)
	}
	if err := d.UnregisterTags(other, []string{"quarantine"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.Last(), "delete element inet ngfw dag_quarantine { 10.10.1.11 }") {
		t.Fatalf("unregister script:\n%s", f.Last())
	}
	if got := d.ListTags("quarantine"); len(got) != 1 || got[0].IP != ip {
		t.Fatalf("list = %v", got)
	}
}

func TestAPIAuthAndPanXML(t *testing.T) {
	d, f := setup(t)
	d.SetCandidate(lab(t))
	d.Commit("steve", "lab", 0)
	keys := []APIKey{
		{Name: "nac", Key: "write-key-000000000000000", Scopes: map[string]bool{ScopeTagsWrite: true}},
		{Name: "dash", Key: "read-key-0000000000000000", Scopes: map[string]bool{ScopeTagsRead: true}},
	}
	srv := httptest.NewServer(d.APIHandler(keys))
	defer srv.Close()

	post := func(path, key, body string) int {
		req, _ := http.NewRequest("POST", srv.URL+path, strings.NewReader(body))
		if key != "" {
			req.Header.Set("X-API-Key", key)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	body := `{"ip":"10.10.1.10","tags":["quarantine"],"ttl":60}`
	if c := post("/api/v1/tags/register", "", body); c != 401 {
		t.Errorf("no key: %d", c)
	}
	if c := post("/api/v1/tags/register", "read-key-0000000000000000", body); c != 403 {
		t.Errorf("read key writing: %d", c)
	}
	if c := post("/api/v1/tags/register", "write-key-000000000000000", body); c != 200 {
		t.Errorf("write key: %d", c)
	}
	if resp, err := http.Get(srv.URL + "/api/v1/tags"); err != nil || resp.Header.Get("X-SJB-OS") != "Stops Junk at the Border" {
		t.Errorf("missing X-SJB-OS header: %v %v", resp, err)
	} else {
		resp.Body.Close()
	}
	if c := post("/api/v1/tags/register", "write-key-000000000000000", `{"ip":"nope","tags":["x"]}`); c != 400 {
		t.Errorf("bad ip: %d", c)
	}

	cmd := `<uid-message><version>2.0</version><type>update</type><payload>
<register><entry ip="10.10.1.12"><tag><member timeout="300">quarantine</member></tag></entry></register>
</payload></uid-message>`
	form := url.Values{"type": {"user-id"}, "key": {"write-key-000000000000000"}, "cmd": {cmd}}
	resp, err := http.PostForm(srv.URL+"/api/", form)
	if err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(out), `status="success"`) {
		t.Fatalf("XML user-ID register: %d %s", resp.StatusCode, out)
	}
	if !strings.Contains(f.Last(), "10.10.1.12 timeout 300s") {
		t.Fatalf("XML user-ID did not reach nft:\n%s", f.Last())
	}

	form.Set("key", "wrong-key-0000000000000000")
	resp, _ = http.PostForm(srv.URL+"/api/", form)
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Errorf("XML user-ID wrong key: %d", resp.StatusCode)
	}
}

func TestLoadKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys")
	os.WriteFile(path, []byte("# comment\nnac tags:read,tags:write abcdefghijklmnopqrstuvwxyz\n"), 0o600)
	keys, err := LoadKeys(path)
	if err != nil || len(keys) != 1 || !keys[0].Scopes[ScopeTagsWrite] {
		t.Fatalf("%+v %v", keys, err)
	}
	os.WriteFile(path, []byte("nac tags:write short\n"), 0o600)
	if _, err := LoadKeys(path); err == nil {
		t.Fatal("short key accepted")
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met within 2s")
}

type fakeRouter struct{ want [][]routes.Route }

func (f *fakeRouter) Sync(want []routes.Route) ([]routes.State, error) {
	f.want = append(f.want, want)
	var out []routes.State
	for _, r := range want {
		st := routes.State{Route: r, Installed: r.Gateway != "172.31.0.1"}
		if !st.Installed {
			st.Error = "Nexthop has invalid gateway"
		}
		out = append(out, st)
	}
	return out, nil
}

func TestCommitInstallsRoutes(t *testing.T) {
	d, _ := setup(t)
	fr := &fakeRouter{}
	d.SetRouter(fr)
	withRoutes := string(lab(t)) + `
routes:
  - name: lab-net
    destination: 10.20.0.0/16
    gateway: 10.10.1.254
  - name: far
    destination: 10.40.0.0/16
    gateway: 172.31.0.1
`
	if err := d.SetCandidate([]byte(withRoutes)); err != nil {
		t.Fatal(err)
	}
	res, err := d.Commit("t", "routes", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	last := fr.want[len(fr.want)-1]
	if len(last) != 2 || last[0].Dest != "10.20.0.0/16" || last[0].Table != 0 {
		t.Fatalf("synced routes: %+v", last)
	}
	if len(res.Warnings) == 0 || !strings.Contains(strings.Join(res.Warnings, "\n"), `route "far"`) {
		t.Fatalf("an uninstallable route should warn, not fail: %v", res.Warnings)
	}
	if st := d.Routes(); len(st) != 2 || !st[0].Installed || st[1].Installed {
		t.Fatalf("route states: %+v", st)
	}
	// Committing without routes removes them.
	if err := d.SetCandidate(lab(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Commit("t", "no routes", 0); err != nil {
		t.Fatal(err)
	}
	if last := fr.want[len(fr.want)-1]; len(last) != 0 {
		t.Fatalf("routes should be removed: %+v", last)
	}
	d.ReconcileRoutes()
	if len(d.Routes()) != 0 {
		t.Fatal("no routes expected after reconcile")
	}
}

func TestMgmtRouteUsesVRFTable(t *testing.T) {
	cfg := &config.Config{System: config.System{MgmtInterface: "mgmt"}, Routes: []config.Route{
		{Name: "a", Destination: "192.0.2.0/24", Gateway: "10.0.2.2", Table: "mgmt"},
	}}
	got := wantedRoutes(cfg)
	if len(got) != 1 || got[0].Table != routes.MgmtTable || got[0].Dev != "mgmt" {
		t.Fatalf("mgmt route: %+v", got)
	}
}

func TestPendingConfirmSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	d, _ := setupAt(t, dir)
	d.SetCandidate(lab(t))
	d.Commit("steve", "lab", 0)
	d.SetCandidate(withoutWeb(t))
	if _, err := d.Commit("steve", "risky", 400*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	d.pending.timer.Stop() // "ngfwd stops" before the timer fires

	d2, f2 := setupAt(t, dir)
	st, _ := d2.Status()
	if st.Running != 2 || st.ConfirmBy == nil {
		t.Fatalf("after restart the commit should still await confirmation: %+v", st)
	}
	// The rollback records revision 3, then clears pending.json.
	waitFor(t, func() bool {
		n, _, _ := d2.Running()
		p, _ := d2.store.LoadPending()
		return n == 3 && p == nil
	})
	d2.mu.Lock()
	last := f2.Last()
	d2.mu.Unlock()
	if !strings.Contains(last, "rule:allow-web") {
		t.Fatal("re-armed timer should restore allow-web")
	}
}

func TestDeadlinePassedWhileStoppedRollsBackAtStart(t *testing.T) {
	dir := t.TempDir()
	d, _ := setupAt(t, dir)
	d.SetCandidate(lab(t))
	d.Commit("steve", "lab", 0)
	d.SetCandidate(withoutWeb(t))
	d.Commit("steve", "risky", time.Minute)
	d.pending.timer.Stop()

	// Restart two minutes later.
	st, _ := store.Open(dir)
	reg, _ := tags.Open(filepath.Join(dir, "tags.json"))
	f := &nft.Fake{}
	d2 := New(st, reg, f, &conntrack.Fake{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	d2.Now = func() time.Time { return time.Now().Add(2 * time.Minute) }
	if err := d2.Start(); err != nil {
		t.Fatal(err)
	}
	if n, _, _ := d2.Running(); n != 3 {
		t.Fatalf("should have rolled back at start to a new revision 3, running %d", n)
	}
	revs, _ := d2.Revisions()
	if !strings.Contains(revs[2].Message, "deadline passed while ngfwd was stopped") || !strings.Contains(f.Last(), "rule:allow-web") {
		t.Fatalf("rollback at start: %q", revs[2].Message)
	}
	if s, _ := d2.Status(); s.ConfirmBy != nil {
		t.Fatal("nothing should be pending after the rollback")
	}
}

func TestConfirmedCommitNotPendingAfterRestart(t *testing.T) {
	dir := t.TempDir()
	d, _ := setupAt(t, dir)
	d.SetCandidate(lab(t))
	d.Commit("steve", "lab", time.Minute)
	if err := d.Confirm(); err != nil {
		t.Fatal(err)
	}
	d2, _ := setupAt(t, dir)
	if s, _ := d2.Status(); s.ConfirmBy != nil || s.Running != 1 {
		t.Fatalf("confirmed commit should not be pending after restart: %+v", s)
	}
}

func TestFirstCommitDeadlinePassedWhileStopped(t *testing.T) {
	dir := t.TempDir()
	d, _ := setupAt(t, dir)
	d.SetCandidate(lab(t))
	d.Commit("steve", "first", time.Minute)
	d.pending.timer.Stop()

	st, _ := store.Open(dir)
	reg, _ := tags.Open(filepath.Join(dir, "tags.json"))
	f := &nft.Fake{}
	d2 := New(st, reg, f, &conntrack.Fake{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	d2.Now = func() time.Time { return time.Now().Add(2 * time.Minute) }
	if err := d2.Start(); err != nil {
		t.Fatal(err)
	}
	if n, _, _ := d2.Running(); n != 0 || strings.Contains(f.Last(), "rule:") {
		t.Fatalf("expected default-deny with nothing running, got revision %d", n)
	}
	if p, _ := d2.store.LoadPending(); p != nil {
		t.Fatal("pending.json should be cleared")
	}
}

func TestWantedVRFsVLANsAndRoutes(t *testing.T) {
	cfg := &config.Config{
		System: config.System{MgmtInterface: "mgmt"},
		VRFs:   []config.VRF{{Name: "blue"}, {Name: "red"}},
		Interfaces: []config.Interface{
			{Name: "mgmt"}, {Name: "inside", Zone: "in"},
			{Name: "inside.20", Zone: "in", VRF: "blue", Address: "10.20.0.1/24"},
			{Name: "inside.30", Zone: "in", Address: "10.30.0.1/24"},
		},
		Routes: []config.Route{
			{Name: "b", Destination: "10.40.0.0/16", Gateway: "10.20.0.254", VRF: "blue"},
			{Name: "leak", Destination: "10.50.0.0/16", VRF: "blue", NextVRF: "red"},
			{Name: "m", Destination: "192.0.2.0/24", Gateway: "10.0.2.2", Table: "mgmt"},
		},
	}
	w := wantedNet(cfg)
	if len(w.VRFs) != 2 || w.VRFs[0].Dev != "vrf-blue" || w.VRFs[0].Table != 1001 || w.VRFs[1].Table != 1002 {
		t.Fatalf("vrfs: %+v", w.VRFs)
	}
	if len(w.VLANs) != 2 || w.VLANs[0].VRF != "vrf-blue" || w.VLANs[0].ID != 20 || w.VLANs[1].VRF != "" {
		t.Fatalf("vlans: %+v", w.VLANs)
	}
	r := wantedRoutes(cfg)
	if r[0].VRFDev != "vrf-blue" || r[0].Table != 1001 || r[1].Dev != "vrf-red" || r[1].Gateway != "" || r[2].Table != 100 || r[2].Dev != "mgmt" || r[2].VRFDev != "" {
		t.Fatalf("routes: %+v", r)
	}
}
