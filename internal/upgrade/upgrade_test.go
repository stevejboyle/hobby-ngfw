package upgrade

import (
	"archive/tar"
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stevejboyle/sjb-os/internal/store"
)

func key(t *testing.T) (ed25519.PrivateKey, []PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return priv, []PublicKey{{Name: "test", Key: pub}}
}

func stage(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for p, c := range files {
		full := filepath.Join(dir, p)
		os.MkdirAll(filepath.Dir(full), 0o755)
		if err := os.WriteFile(full, []byte(c), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func build(t *testing.T, priv ed25519.PrivateKey, version string, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	if _, err := Build(&buf, stage(t, files), version, "", priv); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

var v031 = map[string]string{
	"usr/local/sbin/ngfwd":     "ngfwd 0.3.1",
	"usr/local/sbin/fwctl":     "fwctl 0.3.1",
	"usr/share/sjb-os/new.txt": "new file",
	"etc/ngfw-version":         "0.3.1\n",
}

func TestReadValid(t *testing.T) {
	priv, keys := key(t)
	b, err := Read(bytes.NewReader(build(t, priv, "0.3.1", v031)), keys)
	if err != nil {
		t.Fatal(err)
	}
	if b.Manifest.Version != "0.3.1" || len(b.Contents) != 4 || b.KeyName != "test" {
		t.Fatalf("unexpected bundle: %+v", b.Manifest)
	}
	if string(b.Contents["usr/local/sbin/ngfwd"]) != "ngfwd 0.3.1" {
		t.Fatal("wrong contents")
	}
}

func TestReadRejects(t *testing.T) {
	priv, keys := key(t)
	_, otherKeys := key(t)
	good := build(t, priv, "0.3.1", v031)

	// Rebuild the outer tar with a modified member.
	rewrap := func(edit func(map[string][]byte)) []byte {
		m, err := readTar(bytes.NewReader(good), MaxBundleSize)
		if err != nil {
			t.Fatal(err)
		}
		edit(m)
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		for _, n := range []string{"bundle.tar.gz", "bundle.sig", "extra"} {
			if d, ok := m[n]; ok {
				writeMember(tw, n, 0o644, d)
			}
		}
		tw.Close()
		return buf.Bytes()
	}
	tests := []struct {
		name string
		data []byte
		keys []PublicKey
		want string
	}{
		{"untrusted key", good, otherKeys, "signature"},
		{"tampered payload", rewrap(func(m map[string][]byte) { m["bundle.tar.gz"][len(m["bundle.tar.gz"])-5] ^= 1 }), keys, "signature"},
		{"missing signature", rewrap(func(m map[string][]byte) { delete(m, "bundle.sig") }), keys, "expected"},
		{"extra member", rewrap(func(m map[string][]byte) { m["extra"] = []byte("x") }), keys, "expected"},
		{"not a tar", []byte("junk at the border"), keys, "invalid"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Read(bytes.NewReader(tt.data), tt.keys)
			if err == nil || !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("got %v, want ErrInvalid containing %q", err, tt.want)
			}
		})
	}
}

func TestBuildRefusesForbiddenPaths(t *testing.T) {
	priv, _ := key(t)
	for _, p := range []string{"etc/ngfw/api-keys", "var/lib/ngfw/tags.json", "etc/shadow", "usr/bin/sudo", "etc/systemd/network/10-mgmt.network"} {
		var buf bytes.Buffer
		_, err := Build(&buf, stage(t, map[string]string{p: "x"}), "0.3.1", "", priv)
		if err == nil || !strings.Contains(err.Error(), "may not write") {
			t.Errorf("%s: got %v", p, err)
		}
	}
}

func TestAllowed(t *testing.T) {
	for p, want := range map[string]bool{
		"usr/local/sbin/ngfwd":             true,
		"etc/ngfw-version":                 true,
		"etc/systemd/system/ngfwd.service": true,
		"usr/local/sbin/../../etc/shadow":  false,
		"/usr/local/sbin/ngfwd":            false,
		"usr/local/sbin/":                  false,
		"etc/ngfw/tls.key":                 false,
	} {
		if got := Allowed(p); got != want {
			t.Errorf("Allowed(%q) = %v", p, got)
		}
	}
}

func TestCheckVersion(t *testing.T) {
	tests := []struct {
		bundle, min, current string
		same                 bool
		want                 string // "" = ok
	}{
		{"0.3.1", "", "0.3.0", false, ""},
		{"0.3.0", "", "0.3.0", false, "already installed"},
		{"0.3.0", "", "0.3.0", true, ""},
		{"0.2.9", "", "0.3.0", false, "older"},
		{"0.3.1-rc1", "", "0.3.0", false, ""},
		{"0.3.1-rc1", "", "0.3.1", false, "older"},
		{"1.0.0", "0.3.0", "0.2.0", false, "needs 0.3.0"},
		{"0.10.0", "", "0.9.0", false, ""},
		// -rNN revisions come after the release; 0.6.1 is 0.6.1-r00.
		{"0.6.1-r01", "", "0.6.0", false, ""},
		{"0.6.1-r01", "", "0.6.1", false, ""},
		{"0.6.1-r02", "", "0.6.1-r01", false, ""},
		{"0.6.1-r10", "", "0.6.1-r9", false, ""},
		{"0.6.1-r01", "", "0.6.1-r02", false, "older"},
		{"0.6.1", "", "0.6.1-r03", false, "older"},
		{"0.6.1-r00", "", "0.6.1", false, "already installed"},
		{"0.6.2", "", "0.6.1-r99", false, ""},
		{"0.6.1-r01", "", "0.6.1-rc1", false, ""},
	}
	for _, tt := range tests {
		err := CheckVersion(Manifest{Version: tt.bundle, MinFromVersion: tt.min}, tt.current, tt.same)
		if (err == nil) != (tt.want == "") || (err != nil && !strings.Contains(err.Error(), tt.want)) {
			t.Errorf("%s over %s: got %v, want %q", tt.bundle, tt.current, err, tt.want)
		}
	}
}

type fakeSys struct {
	healthy  func() error
	restarts int
	reloaded [][]string
	expect   int
}

func (f *fakeSys) ExpectRevision(n int) { f.expect = n }

func (f *fakeSys) Reload(c []string) error { f.reloaded = append(f.reloaded, c); return nil }
func (f *fakeSys) RestartDaemon() error    { f.restarts++; return nil }
func (f *fakeSys) Healthy() error {
	if f.healthy != nil {
		return f.healthy()
	}
	return nil
}

func installed(t *testing.T) (*Installer, *fakeSys) {
	t.Helper()
	root := stage(t, map[string]string{
		"usr/local/sbin/ngfwd": "ngfwd 0.3.0",
		"usr/local/sbin/fwctl": "fwctl 0.3.0",
		"etc/ngfw-version":     "0.3.0\n",
		"etc/ngfw/api-keys":    "secret",
	})
	sys := &fakeSys{}
	return &Installer{Root: root, Sys: sys}, sys
}

func read(t *testing.T, in *Installer, p string) string {
	t.Helper()
	b, err := os.ReadFile(in.p(p))
	if errors.Is(err, os.ErrNotExist) {
		return "<missing>"
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestApplyAndRollback(t *testing.T) {
	priv, keys := key(t)
	in, sys := installed(t)
	b, err := Read(bytes.NewReader(build(t, priv, "0.3.1", v031)), keys)
	if err != nil {
		t.Fatal(err)
	}
	if err := in.Apply(b, false); err != nil {
		t.Fatal(err)
	}
	if read(t, in, "usr/local/sbin/ngfwd") != "ngfwd 0.3.1" || read(t, in, "usr/share/sjb-os/new.txt") != "new file" {
		t.Fatal("files not installed")
	}
	if read(t, in, "etc/ngfw/api-keys") != "secret" {
		t.Fatal("config touched")
	}
	st, _ := in.Status()
	if st.Version != "0.3.1" || st.RollbackTo != "0.3.0" || st.History[0].Result != "ok" || sys.restarts != 1 {
		t.Fatalf("status after apply: %+v restarts=%d", st, sys.restarts)
	}
	if err := in.Apply(b, false); err == nil {
		t.Fatal("re-applying the same version should need -reinstall")
	}

	hooked := 0
	in.BeforeRollback = func() error { hooked++; return nil }
	if res, err := in.Rollback(); err != nil || res.ConfigRestored {
		t.Fatalf("rollback: %+v, %v (no config store: nothing to restore)", res, err)
	}
	if hooked != 1 {
		t.Fatalf("BeforeRollback ran %d times", hooked)
	}
	if read(t, in, "usr/local/sbin/ngfwd") != "ngfwd 0.3.0" || read(t, in, "usr/share/sjb-os/new.txt") != "<missing>" {
		t.Fatal("rollback did not restore files")
	}
	st, _ = in.Status()
	if st.Version != "0.3.0" || st.RollbackTo != "" || len(st.History) != 2 || st.History[1].Action != "rollback" {
		t.Fatalf("status after rollback: %+v", st)
	}
	if _, err := in.Rollback(); err == nil {
		t.Fatal("second rollback should have nothing to do")
	}
}

func TestApplyRestoresWhenUnhealthy(t *testing.T) {
	priv, keys := key(t)
	in, sys := installed(t)
	calls := 0
	sys.healthy = func() error {
		calls++
		if calls == 1 {
			return errors.New("ngfwd exited")
		}
		return nil
	}
	b, _ := Read(bytes.NewReader(build(t, priv, "0.3.1", v031)), keys)
	err := in.Apply(b, false)
	if err == nil || !strings.Contains(err.Error(), "previous version restored") {
		t.Fatalf("got %v", err)
	}
	if read(t, in, "usr/local/sbin/ngfwd") != "ngfwd 0.3.0" || read(t, in, "etc/ngfw-version") != "0.3.0\n" || read(t, in, "usr/share/sjb-os/new.txt") != "<missing>" {
		t.Fatal("old files not restored")
	}
	st, _ := in.Status()
	if st.History[0].Result != "restored" || st.RollbackTo != "" || st.InProgress || sys.restarts != 2 {
		t.Fatalf("status: %+v restarts=%d", st, sys.restarts)
	}
}

func TestKeyRoundTrip(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	k, err := ParsePublicKey(FormatPublicKey(pub, "steve laptop"))
	if err != nil || !k.Key.Equal(pub) || k.Name != "steve laptop" {
		t.Fatalf("public key: %v %+v", err, k)
	}
	p2, err := ParsePrivateKey([]byte(FormatPrivateKey(priv)))
	if err != nil || !p2.Equal(priv) {
		t.Fatal("private key round trip")
	}
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.pub"), []byte("# comment\n"+FormatPublicKey(pub, "a")), 0o644)
	keys, err := LoadKeys(dir)
	if err != nil || len(keys) != 1 {
		t.Fatalf("LoadKeys: %v %d", err, len(keys))
	}
	if _, err := LoadKeys(t.TempDir()); err == nil {
		t.Fatal("empty key dir should fail")
	}
}

func TestVersionOrder(t *testing.T) {
	order := []string{"0.6.0", "0.6.1-boottest", "0.6.1-rc1", "0.6.1-rc2", "0.6.1", "0.6.1-r01", "0.6.1-r2", "0.6.1-r10", "0.6.2-boottest", "0.6.2", "0.9.9-r10", "0.9.10", "0.9.10-r01"}
	for i := range order {
		for j := range order {
			a, _ := ParseVersion(order[i])
			b, _ := ParseVersion(order[j])
			want := 0
			if i < j {
				want = -1
			} else if i > j {
				want = 1
			}
			if got := a.Compare(b); got != want {
				t.Errorf("%s vs %s: got %d, want %d", order[i], order[j], got, want)
			}
		}
	}
	a, _ := ParseVersion("0.6.1-r00")
	b, _ := ParseVersion("0.6.1")
	if a.Compare(b) != 0 {
		t.Error("0.6.1-r00 should equal 0.6.1")
	}
}

// The config running at the upgrade comes back on rollback when it has
// changed since, as a new revision; the later revisions stay.
func TestRollbackRestoresUpgradeTimeConfig(t *testing.T) {
	priv, keys := key(t)
	in, sys := installed(t)
	cs, err := store.Open(in.p(ConfigDir))
	if err != nil {
		t.Fatal(err)
	}
	old := []byte("zones: [inside]\n")
	if _, err := cs.Save(old, "admin", "before", time.Now()); err != nil {
		t.Fatal(err)
	}
	b, _ := Read(bytes.NewReader(build(t, priv, "0.3.1", v031)), keys)
	if err := in.Apply(b, false); err != nil {
		t.Fatal(err)
	}
	// On the new version: a setting the old one doesn't know, a confirm.
	newer := []byte("zones: [inside]\napplication_groups: [streaming]\n")
	if _, err := cs.Save(newer, "admin", "groups", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := cs.SavePending(store.Pending{Revision: 2, Previous: 1, Deadline: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	res, err := in.Rollback()
	if err != nil {
		t.Fatal(err)
	}
	if !res.ConfigRestored || res.From != 2 || res.UpgradeTime != 1 || res.Revision != 3 || sys.expect != 3 {
		t.Fatalf("result %+v, expected revision %d", res, sys.expect)
	}
	n, run, _ := cs.Running()
	cand, _ := cs.Candidate()
	if n != 3 || !bytes.Equal(run, old) || !bytes.Equal(cand, old) {
		t.Fatalf("running %d %q, candidate %q", n, run, cand)
	}
	if kept, _ := cs.Get(2); !bytes.Equal(kept, newer) {
		t.Fatal("the later revision should stay in the history")
	}
	if p, _ := cs.LoadPending(); p != nil {
		t.Fatalf("pending confirm left: %+v", p)
	}
	revs, _ := cs.List()
	if last := revs[len(revs)-1]; last.Author != "sjb-os rollback" || !strings.Contains(last.Message, "revision 1") {
		t.Fatalf("revision 3: %+v", last)
	}
}

// Unchanged config: the rollback commits nothing.
func TestRollbackKeepsUnchangedConfig(t *testing.T) {
	priv, keys := key(t)
	in, sys := installed(t)
	cs, _ := store.Open(in.p(ConfigDir))
	if _, err := cs.Save([]byte("zones: [inside]\n"), "admin", "before", time.Now()); err != nil {
		t.Fatal(err)
	}
	b, _ := Read(bytes.NewReader(build(t, priv, "0.3.1", v031)), keys)
	if err := in.Apply(b, false); err != nil {
		t.Fatal(err)
	}
	res, err := in.Rollback()
	if err != nil || res.ConfigRestored || sys.expect != 0 {
		t.Fatalf("%+v %v expect=%d", res, err, sys.expect)
	}
	if n, _, _ := cs.Running(); n != 1 {
		t.Fatalf("running %d, want 1", n)
	}
}

// A backup from an fwctl before 0.7.0 records no config: the revision
// running at the upgrade is found from the upgrade's time.
func TestRollbackOldBackupUsesUpgradeTime(t *testing.T) {
	priv, keys := key(t)
	in, _ := installed(t)
	cs, _ := store.Open(in.p(ConfigDir))
	t0 := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	old := []byte("zones: [inside]\n")
	cs.Save([]byte("zones: []\n"), "admin", "first", t0)
	cs.Save(old, "admin", "before", t0.Add(time.Hour))
	in.Now = func() time.Time { return t0.Add(2 * time.Hour) }
	b, _ := Read(bytes.NewReader(build(t, priv, "0.3.1", v031)), keys)
	if err := in.Apply(b, false); err != nil {
		t.Fatal(err)
	}
	// What an older fwctl wrote: no config_revision, no config.yaml.
	bdir := in.p(filepath.Join(StateDir, "releases", "0.3.0"))
	os.Remove(filepath.Join(bdir, "config.yaml"))
	var bk backup
	data, _ := os.ReadFile(filepath.Join(bdir, "backup.json"))
	json.Unmarshal(data, &bk)
	bk.ConfigRevision = 0
	if err := writeJSON(filepath.Join(bdir, "backup.json"), bk); err != nil {
		t.Fatal(err)
	}
	cs.Save([]byte("zones: [inside]\napplication_groups: [x]\n"), "admin", "after", t0.Add(3*time.Hour))
	res, err := in.Rollback()
	if err != nil || !res.ConfigRestored || res.UpgradeTime != 2 || res.Revision != 4 {
		t.Fatalf("%+v %v", res, err)
	}
	if _, run, _ := cs.Running(); !bytes.Equal(run, old) {
		t.Fatalf("running %q", run)
	}
}

// A key directory may hold files an older version left behind, in a format
// this one doesn't read: they're skipped (they add no trust), and only a
// directory with no valid key at all is an error.
func TestLoadKeysSkipsForeignLines(t *testing.T) {
	dir := t.TempDir()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "old.pub"), []byte("some-other-format AAAA old\n"), 0o644)
	if _, err := LoadKeys(dir); err == nil {
		t.Fatal("no valid key: want an error")
	}
	os.WriteFile(filepath.Join(dir, "release.pub"), []byte(FormatPublicKey(pub, "release")), 0o644)
	keys, err := LoadKeys(dir)
	if err != nil || len(keys) != 1 || keys[0].Name != "release" {
		t.Fatalf("keys %v, %v", keys, err)
	}
}
