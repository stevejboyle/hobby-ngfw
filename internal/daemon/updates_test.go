package daemon

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stevejboyle/sjb-os/internal/accounts"
	"github.com/stevejboyle/sjb-os/internal/upgrade"
)

// updateServer is a fake update server: an index and the bundles it names.
type updateServer struct {
	t     *testing.T
	srv   *httptest.Server
	key   ed25519.PrivateKey
	mu    sync.Mutex
	files map[string][]byte
	gets  int
}

func newUpdateServer(t *testing.T, key ed25519.PrivateKey) *updateServer {
	s := &updateServer{t: t, key: key, files: map[string][]byte{}}
	s.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.gets++
		b, ok := s.files[r.URL.Path]
		s.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write(b)
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func testBundle(t *testing.T, key ed25519.PrivateKey, version string) []byte {
	t.Helper()
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "etc"), 0o755)
	os.WriteFile(filepath.Join(dir, "etc/ngfw-version"), []byte(version+"\n"), 0o644)
	var buf bytes.Buffer
	if _, err := upgrade.Build(&buf, dir, version, "", key); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// publish serves bundle as the newest release, with an index published at
// when. mod may change the index before it is signed.
func (s *updateServer) publish(version string, bundle []byte, when time.Time, mod func(*upgrade.Index)) {
	s.t.Helper()
	sum := sha256.Sum256(bundle)
	path := "/releases/sjb-os-" + version + ".upgrade"
	ix := &upgrade.Index{Schema: upgrade.IndexSchema, Channel: upgrade.IndexChannel, Published: when,
		Latest: upgrade.Release{Version: version, URL: s.srv.URL + path, Size: int64(len(bundle)), SHA256: hex.EncodeToString(sum[:])}}
	if mod != nil {
		mod(ix)
	}
	data, err := upgrade.MarshalIndex(ix)
	if err != nil {
		s.t.Fatal(err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.files[path] = bundle
	s.files["/"+upgrade.IndexPath] = data
	s.files["/"+upgrade.IndexSigPath] = upgrade.SignIndex(data, s.key)
}

type updatesFixture struct {
	d       *Daemon
	srv     *updateServer
	key     ed25519.PrivateKey
	root    string
	started []string
	free    uint64
}

// setupUpdates: a daemon on SJB-OS 0.9.16-r01 whose running config points
// at a fake update server.
func setupUpdates(t *testing.T, extra string) *updatesFixture {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(nil)
	fx := &updatesFixture{key: priv, root: t.TempDir(), free: 1 << 40}
	fx.srv = newUpdateServer(t, priv)
	os.MkdirAll(filepath.Join(fx.root, "etc"), 0o755)
	os.WriteFile(filepath.Join(fx.root, upgrade.VersionFile), []byte("0.9.16-r01\n"), 0o644)
	kd := filepath.Join(fx.root, upgrade.KeysDir)
	os.MkdirAll(kd, 0o755)
	os.WriteFile(filepath.Join(kd, "test.pub"), []byte(upgrade.FormatPublicKey(pub, "test-release")), 0o644)
	d, _ := setup(t)
	fx.d = d
	cfg := strings.Replace(string(lab(t)), "system:\n  hostname: fw-lab\n", "system:\n  hostname: fw-lab\n  update_server: "+fx.srv.srv.URL+"\n"+extra, 1)
	if err := d.SetCandidate([]byte(cfg)); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Commit("steve", "lab", 0); err != nil {
		t.Fatal(err)
	}
	fx.setUpdates()
	return fx
}

func (fx *updatesFixture) setUpdates() {
	fx.d.SetUpdates(UpdateSource{
		Installer: &upgrade.Installer{Root: fx.root},
		Client:    fx.srv.srv.Client(),
		Start:     func(p string) error { fx.started = append(fx.started, p); return nil },
		FreeBytes: func(string) (uint64, error) { return fx.free, nil },
	})
}

var t0 = time.Date(2026, 11, 28, 12, 0, 0, 0, time.UTC)

func TestUpdateCheckDownloadsAndInstalls(t *testing.T) {
	fx := setupUpdates(t, "")
	d := fx.d
	// Nothing newer: up to date.
	fx.srv.publish("0.9.16-r01", testBundle(t, fx.key, "0.9.16-r01"), t0, nil)
	st, err := d.CheckUpdates(context.Background())
	if err != nil || st.UpdateReady || st.Staged != nil || !strings.Contains(st.LastCheck.Result, "up to date") {
		t.Fatalf("same version: %+v %v", st, err)
	}
	if _, err := d.InstallUpdate(accounts.Root); err == nil {
		t.Error("install with nothing staged")
	}

	// A newer release is downloaded, verified and staged; not installed.
	fx.srv.publish("0.9.17-r01", testBundle(t, fx.key, "0.9.17-r01"), t0.Add(time.Hour), nil)
	st, err = d.CheckUpdates(context.Background())
	if err != nil || !st.UpdateReady || st.Staged == nil || st.Staged.Version != "0.9.17-r01" || !st.LastCheck.OK {
		t.Fatalf("newer: %+v %v", st, err)
	}
	if len(fx.started) != 0 {
		t.Fatal("a check installed something")
	}
	staged := filepath.Join(fx.root, upgrade.StateDir, "incoming", stagedUpdateName)
	if _, err := os.Stat(staged); err != nil {
		t.Fatal(err)
	}
	// A second check doesn't download it again.
	fx.srv.mu.Lock()
	before := fx.srv.gets
	fx.srv.mu.Unlock()
	if st, err = d.CheckUpdates(context.Background()); err != nil || !st.UpdateReady {
		t.Fatalf("recheck: %+v %v", st, err)
	}
	if fx.srv.gets-before != 2 {
		t.Errorf("recheck made %d requests, want 2 (index and signature)", fx.srv.gets-before)
	}

	// Install: refused while a commit awaits confirmation.
	if _, err := d.Commit("steve", "confirm me", time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err := d.InstallUpdate(accounts.Root); err == nil || !strings.Contains(err.Error(), "confirmation") {
		t.Errorf("install during commit-confirm: %v", err)
	}
	if err := d.Confirm(); err != nil {
		t.Fatal(err)
	}
	if _, err := d.InstallUpdate(accounts.Root); err != nil {
		t.Fatal(err)
	}
	if len(fx.started) != 1 || fx.started[0] != staged {
		t.Errorf("started %v", fx.started)
	}

	// After the upgrade (the new version installed, ngfwd restarted), the
	// staged bundle is removed.
	os.WriteFile(filepath.Join(fx.root, upgrade.VersionFile), []byte("0.9.17-r01\n"), 0o644)
	fx.setUpdates()
	if st := d.Updates(); st.Staged != nil || st.UpdateReady {
		t.Errorf("after the upgrade: %+v", st)
	}
	if _, err := os.Stat(staged); !os.IsNotExist(err) {
		t.Error("staged bundle left behind")
	}
}

func TestUpdateCheckRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		prep func(fx *updatesFixture)
		want string
	}{
		"index signed with another key": {func(fx *updatesFixture) {
			_, other, _ := ed25519.GenerateKey(nil)
			fx.srv.key = other
			fx.srv.publish("0.9.17-r01", testBundle(t, fx.key, "0.9.17-r01"), t0, nil)
		}, "signature"},
		"bundle signed with another key": {func(fx *updatesFixture) {
			_, other, _ := ed25519.GenerateKey(nil)
			fx.srv.publish("0.9.17-r01", testBundle(t, other, "0.9.17-r01"), t0, nil)
		}, "trusted key"},
		"SHA-256 mismatch": {func(fx *updatesFixture) {
			b := testBundle(t, fx.key, "0.9.17-r01")
			fx.srv.publish("0.9.17-r01", b, t0, func(ix *upgrade.Index) { ix.Latest.SHA256 = strings.Repeat("00", 32) })
		}, "SHA-256"},
		"short body": {func(fx *updatesFixture) {
			b := testBundle(t, fx.key, "0.9.17-r01")
			fx.srv.publish("0.9.17-r01", b, t0, func(ix *upgrade.Index) { ix.Latest.Size += 10 })
		}, "bytes"},
		"bundle version differs from the index": {func(fx *updatesFixture) {
			fx.srv.publish("0.9.17-r01", testBundle(t, fx.key, "0.9.18-r01"), t0, nil)
		}, "the bundle is SJB-OS 0.9.18-r01"},
		"not found": {func(fx *updatesFixture) {}, "404"},
		"not enough disk": {func(fx *updatesFixture) {
			fx.free = 1 << 20
			fx.srv.publish("0.9.17-r01", testBundle(t, fx.key, "0.9.17-r01"), t0, nil)
		}, "disk space"},
		"needs a newer installed version": {func(fx *updatesFixture) {
			fx.srv.publish("0.9.17-r01", testBundle(t, fx.key, "0.9.17-r01"), t0, func(ix *upgrade.Index) { ix.Latest.MinFromVersion = "0.9.17" })
		}, "can't install here"},
	} {
		t.Run(name, func(t *testing.T) {
			fx := setupUpdates(t, "")
			tc.prep(fx)
			st, err := fx.d.CheckUpdates(context.Background())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err %v, want %q", err, tc.want)
			}
			if st.Staged != nil || st.LastCheck.OK || !strings.Contains(st.LastCheck.Result, tc.want) {
				t.Errorf("status %+v", st)
			}
			matches, _ := filepath.Glob(filepath.Join(fx.root, upgrade.StateDir, "incoming", "*"))
			if len(matches) != 0 {
				t.Errorf("left files: %v", matches)
			}
		})
	}
}

func TestUpdateCheckReplayAndReplace(t *testing.T) {
	fx := setupUpdates(t, "")
	d := fx.d
	fx.srv.publish("0.9.17-r01", testBundle(t, fx.key, "0.9.17-r01"), t0, nil)
	if _, err := d.CheckUpdates(context.Background()); err != nil {
		t.Fatal(err)
	}
	// A newer release replaces the staged one.
	fx.srv.publish("0.9.17-r02", testBundle(t, fx.key, "0.9.17-r02"), t0.Add(time.Hour), nil)
	st, err := d.CheckUpdates(context.Background())
	if err != nil || st.Staged == nil || st.Staged.Version != "0.9.17-r02" {
		t.Fatalf("replace: %+v %v", st, err)
	}
	// An older index (a replay) is refused, and what is staged stays.
	fx.srv.publish("0.9.17-r01", testBundle(t, fx.key, "0.9.17-r01"), t0, nil)
	st, err = d.CheckUpdates(context.Background())
	if err == nil || !strings.Contains(err.Error(), "older") {
		t.Fatalf("replay: %v", err)
	}
	if st.Staged == nil || st.Staged.Version != "0.9.17-r02" || !st.UpdateReady {
		t.Errorf("staged release lost on a failed check: %+v", st)
	}
	// A failure keeps it too, and survives a restart.
	fx.srv.mu.Lock()
	fx.srv.files = map[string][]byte{}
	fx.srv.mu.Unlock()
	if _, err := d.CheckUpdates(context.Background()); err == nil {
		t.Fatal("check against an empty server passed")
	}
	fx.setUpdates()
	if st := d.Updates(); st.Staged == nil || st.Staged.Version != "0.9.17-r02" || st.LastCheck.OK {
		t.Errorf("after restart: %+v", st)
	}
}

func TestUpdateCheckDue(t *testing.T) {
	fx := setupUpdates(t, "")
	d := fx.d
	now := t0
	d.Now = func() time.Time { return now }
	if !d.updateCheckDue() {
		t.Error("never checked: not due")
	}
	fx.srv.publish("0.9.16-r01", testBundle(t, fx.key, "0.9.16-r01"), t0, nil)
	if _, err := d.CheckUpdates(context.Background()); err != nil {
		t.Fatal(err)
	}
	if d.updateCheckDue() {
		t.Error("due right after a check")
	}
	now = now.Add(23 * time.Hour)
	if !d.updateCheckDue() {
		t.Error("not due after 23 h")
	}

	off := setupUpdates(t, "  update_check: \"off\"\n")
	if off.d.updateCheckDue() {
		t.Error("due with update-check off")
	}
	// Check now still works with the daily check off.
	off.srv.publish("0.9.17-r01", testBundle(t, off.key, "0.9.17-r01"), t0, nil)
	if st, err := off.d.CheckUpdates(context.Background()); err != nil || !st.UpdateReady || st.Enabled {
		t.Errorf("manual check with the daily check off: %+v %v", st, err)
	}
}

func TestUpdatesUnavailable(t *testing.T) {
	d, _ := setup(t)
	if _, err := d.CheckUpdates(context.Background()); !errors.Is(err, ErrInvalid) {
		t.Errorf("check: %v", err)
	}
	if _, err := d.InstallUpdate(accounts.Root); !errors.Is(err, ErrInvalid) {
		t.Errorf("install: %v", err)
	}
	if st := d.Updates(); st.Available || !st.Enabled || st.Server != "https://updates.os.sjbconsulting.ai" {
		t.Errorf("status: %+v", st)
	}
	if d.updatesMetrics() != nil {
		t.Error("metrics without online updates")
	}
}
