package ospkg

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestCompareVersions(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0},
		{"1.0", "1.1", -1},
		{"1.10", "1.9", 1},
		{"2.41-12+deb13u4", "2.41-12+deb13u5", -1},
		{"1:4.17.4-2", "1:4.17.4-2+deb13u1", -1},
		{"1:1.0", "2.0", 1}, // epoch wins
		{"3.5.7-1~deb13u3", "3.5.9-1~deb13u1", -1},
		{"1.0~rc1", "1.0", -1}, // tilde sorts before the release
		{"1.0", "1.0+b1", -1},
		{"1.0a", "1.0", 1},
		{"6.12.116-1", "6.12.118-1", -1},
		{"1+2.12+9+deb13u2", "1+2.12+9+deb13u4", -1},
		{"38-3.1+b1", "38-3.1+deb13u1", -1},
		{"1.01", "1.1", 0},
	} {
		got := CompareVersions(c.a, c.b)
		if (got < 0) != (c.want < 0) || (got > 0) != (c.want > 0) {
			t.Errorf("CompareVersions(%q, %q) = %d, want sign %d", c.a, c.b, got, c.want)
		}
		if back := CompareVersions(c.b, c.a); (back < 0) != (c.want > 0) || (back > 0) != (c.want < 0) {
			t.Errorf("CompareVersions(%q, %q) = %d, not the reverse of %d", c.b, c.a, back, got)
		}
	}
}

// --- fakes -----------------------------------------------------------------

type pkgDef struct {
	name, version string
	files         map[string]string // path -> content (owned files)
	conffiles     []string
}

type fakeDpkg struct {
	t        *testing.T
	root     string
	debs     map[string]pkgDef // bundled file path -> what it installs
	failNext error
	refuse   map[string]bool // packages Remove refuses
	installs [][]string
	downs    []bool
	removes  [][]string
	purges   []bool
	conf     int
	allowRun int
	fields   int
}

func (f *fakeDpkg) Fields(deb string) (string, string, string, int64, error) {
	f.fields++
	d, ok := f.debs[deb]
	if !ok {
		// A repacked file: read its control.
		return readDebControl(f.t, deb)
	}
	return d.name, d.version, "amd64", 1024, nil
}

func (f *fakeDpkg) Install(debs []string, downgrade bool) ([]byte, error) {
	f.installs = append(f.installs, debs)
	f.downs = append(f.downs, downgrade)
	if err := f.failNext; err != nil {
		f.failNext = nil
		return []byte("dpkg: error processing archive\nsome detail"), err
	}
	for _, deb := range debs {
		d, ok := f.debs[deb]
		if !ok {
			name, ver, _, _, err := readDebControl(f.t, deb)
			if err != nil {
				return nil, err
			}
			d = pkgDef{name: name, version: ver}
		}
		setPackage(f.t, f.root, d)
	}
	return []byte("ok"), nil
}

func (f *fakeDpkg) Remove(pkgs []string, purge bool) ([]byte, error) {
	f.removes = append(f.removes, pkgs)
	f.purges = append(f.purges, purge)
	for _, p := range pkgs {
		if f.refuse[p] {
			return []byte("dpkg: dependency problems prevent removal of " + p), errors.New("exit status 2")
		}
	}
	for _, p := range pkgs {
		dropPackage(f.t, f.root, p)
	}
	return nil, nil
}

func (f *fakeDpkg) Configure() ([]byte, error) { f.conf++; return nil, nil }
func (f *fakeDpkg) AllowRunningKernelRemoval() error {
	f.allowRun++
	return nil
}

type fakeHost struct {
	kernel string
	boot   time.Time
	free   uint64
}

func (h *fakeHost) RunningKernel() string { return h.kernel }
func (h *fakeHost) BootTime() time.Time   { return h.boot }
func (h *fakeHost) FreeBytes(path string) (uint64, error) {
	if strings.HasSuffix(path, "boot") {
		return 0, os.ErrNotExist // /boot is on /
	}
	return h.free, nil
}

// --- a fake root -------------------------------------------------------------

func writeFile(t *testing.T, path, data string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), mode); err != nil {
		t.Fatal(err)
	}
}

// setPackage installs (or replaces) a package in the fake dpkg database:
// its status entry, file list and files.
func setPackage(t *testing.T, root string, d pkgDef) {
	t.Helper()
	all, _ := readStatus(root)
	var b strings.Builder
	for _, s := range all {
		if s.get("Package") == d.name {
			continue
		}
		b.WriteString(stanzaText(s))
	}
	fmt.Fprintf(&b, "Package: %s\nStatus: install ok installed\nPriority: optional\nInstalled-Size: 12\nMaintainer: Test <t@example.org>\nArchitecture: amd64\nVersion: %s\n", d.name, d.version)
	if len(d.conffiles) > 0 {
		b.WriteString("Conffiles:\n")
		for _, c := range d.conffiles {
			fmt.Fprintf(&b, " %s 0123456789abcdef0123456789abcdef\n", c)
		}
	}
	b.WriteString("Description: test package " + d.name + "\n multi-line description\n\n")
	writeFile(t, filepath.Join(root, dpkgStatus), b.String(), 0o644)
	var list []string
	if len(d.files) > 0 {
		list = append(list, "/.", "/usr")
	}
	paths := make([]string, 0, len(d.files))
	for p := range d.files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		writeFile(t, filepath.Join(root, p), d.files[p], 0o644)
		list = append(list, p)
	}
	writeFile(t, filepath.Join(root, dpkgInfo, d.name+".list"), strings.Join(list, "\n")+"\n", 0o644)
	writeFile(t, filepath.Join(root, dpkgInfo, d.name+".postinst"), "#!/bin/sh\necho "+d.version+"\n", 0o755)
}

func dropPackage(t *testing.T, root, name string) {
	t.Helper()
	all, _ := readStatus(root)
	var b strings.Builder
	for _, s := range all {
		if s.get("Package") != name {
			b.WriteString(stanzaText(s))
		}
	}
	writeFile(t, filepath.Join(root, dpkgStatus), b.String(), 0o644)
}

func stanzaText(s stanza) string {
	var b strings.Builder
	for _, k := range s.keys {
		fmt.Fprintf(&b, "%s: %s\n", k, s.fields[k])
	}
	return b.String() + "\n"
}

func installedVersion(t *testing.T, root, name string) string {
	t.Helper()
	inst, err := installedPackages(root)
	if err != nil {
		t.Fatal(err)
	}
	return inst[name].get("Version")
}

// setUpgrade records an upgrade in the history, as Installer.Apply does.
func setUpgrade(t *testing.T, root, from, to, result string) {
	t.Helper()
	writeFile(t, filepath.Join(root, "etc/ngfw-version"), to+"\n", 0o644)
	st := map[string]any{"history": []map[string]any{{"time": time.Now().UTC(), "action": "upgrade", "from": from, "to": to, "result": result}}}
	b, _ := json.Marshal(st)
	writeFile(t, filepath.Join(root, "var/lib/sjb-os/upgrades.json"), string(b), 0o644)
}

type rig struct {
	root string
	d    *fakeDpkg
	h    *fakeHost
	m    *Manager
}

func newRig(t *testing.T) *rig {
	root := t.TempDir()
	d := &fakeDpkg{t: t, root: root, debs: map[string]pkgDef{}, refuse: map[string]bool{}}
	h := &fakeHost{kernel: "6.12.116+deb13-amd64", boot: time.Now().Add(-time.Hour), free: 4 << 30}
	writeFile(t, filepath.Join(root, dpkgStatus), "", 0o644)
	return &rig{root: root, d: d, h: h, m: &Manager{Root: root, Dpkg: d, Host: h}}
}

// bundle adds a .deb to the bundle's package directory.
func (r *rig) bundle(d pkgDef) {
	f := filepath.Join(r.root, DebDir, debFileName(d.name, d.version, "amd64"))
	writeFile(r.d.t, f, "deb "+d.name, 0o644)
	r.d.debs[f] = d
}

func (r *rig) saved(from string) Saved {
	r.d.t.Helper()
	s, err := readSaved(filepath.Join(r.root, "var/lib/sjb-os/releases", from, SavedDir))
	if err != nil {
		r.d.t.Fatal(err)
	}
	return s
}

// --- tests ---------------------------------------------------------------------

func TestInstallSelectsByVersion(t *testing.T) {
	r := newRig(t)
	setPackage(t, r.root, pkgDef{name: "older", version: "1.0"})
	setPackage(t, r.root, pkgDef{name: "same", version: "2.0"})
	setPackage(t, r.root, pkgDef{name: "newer", version: "3.5"})
	r.bundle(pkgDef{name: "older", version: "1.1"})
	r.bundle(pkgDef{name: "same", version: "2.0"})
	r.bundle(pkgDef{name: "newer", version: "3.0"})
	r.bundle(pkgDef{name: "missing", version: "0.1"})
	changes, err := r.m.Install()
	if err != nil {
		t.Fatal(err)
	}
	got := names(changes)
	if got != "missing older" {
		t.Fatalf("installed %q, want missing and older only", got)
	}
	if len(r.d.installs) != 1 || len(r.d.installs[0]) != 2 || r.d.downs[0] {
		t.Fatalf("dpkg calls %v (downgrade %v): want one install of two files, no downgrade", r.d.installs, r.d.downs)
	}
	if v := installedVersion(t, r.root, "newer"); v != "3.5" {
		t.Errorf("newer is %s: a bundle must never downgrade", v)
	}
	st := r.m.LoadStatus()
	if st.State != StateOK || st.Updated() != 2 {
		t.Errorf("status %+v", st)
	}
	// Nothing left to do: no dpkg run, status unchanged.
	if ch, err := r.m.Install(); err != nil || ch != nil || len(r.d.installs) != 1 {
		t.Errorf("second run: %v %v, installs %d", ch, err, len(r.d.installs))
	}
}

func TestInstallSavesForRollbackOnce(t *testing.T) {
	r := newRig(t)
	setUpgrade(t, r.root, "0.9.13-r03", "0.9.14-r01", "in-progress")
	setPackage(t, r.root, pkgDef{name: "libc6", version: "2.41-12+deb13u4",
		files: map[string]string{"/usr/lib/libc.so.6": "old libc", "/etc/libc.conf": "changed by admin"}, conffiles: []string{"/etc/libc.conf"}})
	writeFile(t, filepath.Join(r.root, "os-release-link-target"), "x", 0o644)
	r.bundle(pkgDef{name: "libc6", version: "2.41-12+deb13u5"})
	r.bundle(pkgDef{name: "linux-image-6.12.118+deb13-amd64", version: "6.12.118-1"})
	writeFile(t, filepath.Join(r.root, UpdatesTxt), "linux-image-6.12.118+deb13-amd64 absent 6.12.118-1 Debian-Security:13/stable-security security\nlibc6 2.41-12+deb13u4 2.41-12+deb13u5 Debian:13.8/stable update\n", 0o644)
	changes, err := r.m.Install()
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 2 {
		t.Fatalf("changes %+v", changes)
	}
	s := r.saved("0.9.13-r03")
	if s.Version != "0.9.14-r01" || len(s.Changes) != 2 {
		t.Fatalf("saved %+v", s)
	}
	for _, c := range s.Changes {
		switch c.Package {
		case "libc6":
			if c.From != "2.41-12+deb13u4" || c.Security {
				t.Errorf("libc6 saved as %+v", c)
			}
		case "linux-image-6.12.118+deb13-amd64":
			if c.From != Absent || !c.Security {
				t.Errorf("kernel saved as %+v", c)
			}
		}
	}
	dir := filepath.Join(r.root, "var/lib/sjb-os/releases/0.9.13-r03", SavedDir)
	debs, _ := filepath.Glob(filepath.Join(dir, "*.deb"))
	if len(debs) != 1 || filepath.Base(debs[0]) != "libc6_2.41-12+deb13u4_amd64.deb" {
		t.Fatalf("repacked %v: want only libc6 at its old version (kernels are never repacked)", debs)
	}
	ctl, data := readDeb(t, debs[0])
	if !strings.Contains(ctl["control"], "Version: 2.41-12+deb13u4\n") || strings.Contains(ctl["control"], "Status:") {
		t.Errorf("control:\n%s", ctl["control"])
	}
	if !strings.Contains(ctl["control"], "Description: test package libc6\n multi-line description\n") {
		t.Errorf("description continuation lost:\n%s", ctl["control"])
	}
	if ctl["conffiles"] != "/etc/libc.conf\n" || !strings.Contains(ctl["postinst"], "2.41-12+deb13u4") {
		t.Errorf("conffiles %q postinst %q", ctl["conffiles"], ctl["postinst"])
	}
	if data["./usr/lib/libc.so.6"] != "old libc" || data["./etc/libc.conf"] != "changed by admin" {
		t.Errorf("data %v: want the files as installed, changed config included", data)
	}

	// A second run (the next ngfwd start) with a newer bundled libc6 must not
	// replace what was saved: rollback returns to the pre-upgrade version.
	r.bundle(pkgDef{name: "libc6", version: "2.41-12+deb13u6"})
	if _, err := r.m.Install(); err != nil {
		t.Fatal(err)
	}
	s = r.saved("0.9.13-r03")
	for _, c := range s.Changes {
		if c.Package == "libc6" && c.From != "2.41-12+deb13u4" {
			t.Errorf("libc6's saved version became %s", c.From)
		}
	}
	debs, _ = filepath.Glob(filepath.Join(dir, "*.deb"))
	if len(debs) != 1 {
		t.Errorf("repacked again: %v", debs)
	}
}

func TestInstallNoSaveWithoutUpgrade(t *testing.T) {
	r := newRig(t)
	setPackage(t, r.root, pkgDef{name: "a", version: "1"})
	r.bundle(pkgDef{name: "a", version: "2"})
	if _, err := r.m.Install(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(r.root, "var/lib/sjb-os/releases")); !os.IsNotExist(err) {
		t.Errorf("saved state with no upgrade to roll back: %v", err)
	}
	// After a rollback the history's last event is a rollback: nothing saved.
	setUpgrade(t, r.root, "0.9.14-r01", "0.9.13-r03", "ok")
	b, _ := json.Marshal(map[string]any{"history": []map[string]any{{"action": "rollback", "from": "0.9.14-r01", "to": "0.9.13-r03", "result": "ok"}}})
	writeFile(t, filepath.Join(r.root, "var/lib/sjb-os/upgrades.json"), string(b), 0o644)
	if dir, _ := r.m.savedDir(); dir != "" {
		t.Errorf("saved dir %s after a rollback", dir)
	}
}

func TestInstallFailureRecorded(t *testing.T) {
	r := newRig(t)
	setPackage(t, r.root, pkgDef{name: "a", version: "1"})
	r.bundle(pkgDef{name: "a", version: "2"})
	r.d.failNext = errors.New("exit status 1")
	if _, err := r.m.Install(); err == nil {
		t.Fatal("want an error")
	}
	st := r.m.LoadStatus()
	if st.State != StateFailed || !strings.Contains(st.Error, "some detail") {
		t.Errorf("status %+v", st)
	}
	if r.d.conf != 1 {
		t.Errorf("dpkg --configure -a ran %d times, want 1", r.d.conf)
	}
	// The next start retries and succeeds.
	if _, err := r.m.Install(); err != nil || r.m.LoadStatus().State != StateOK {
		t.Errorf("retry: %v %+v", err, r.m.LoadStatus())
	}
}

func TestInstallStopsWithoutSpace(t *testing.T) {
	r := newRig(t)
	setUpgrade(t, r.root, "0.9.13-r03", "0.9.14-r01", "in-progress")
	setPackage(t, r.root, pkgDef{name: "a", version: "1", files: map[string]string{"/usr/a": "a"}})
	r.bundle(pkgDef{name: "a", version: "2"})
	r.h.free = 100 << 20
	_, err := r.m.Install()
	if err == nil || !strings.Contains(err.Error(), "not enough disk space") {
		t.Fatalf("err %v", err)
	}
	if len(r.d.installs) != 0 {
		t.Error("dpkg ran without space")
	}
	if _, err := os.Stat(filepath.Join(r.root, "var/lib/sjb-os/releases/0.9.13-r03", SavedDir)); !os.IsNotExist(err) {
		t.Error("saved state written before the space check")
	}
	if st := r.m.LoadStatus(); st.State != StateFailed {
		t.Errorf("status %+v", st)
	}
}

func TestReboot(t *testing.T) {
	r := newRig(t)
	setPackage(t, r.root, pkgDef{name: "linux-image-6.12.116+deb13-amd64", version: "6.12.116-1"})
	if st := r.m.Report(); st.RebootRequired || st.RebootRecommended {
		t.Errorf("one kernel, running: %+v", st)
	}
	setPackage(t, r.root, pkgDef{name: "linux-image-6.12.118+deb13-amd64", version: "6.12.118-1"})
	st := r.m.Report()
	if !st.RebootRequired || len(st.RebootReasons) != 1 || st.RebootReasons[0] != "kernel 6.12.118" || st.NewestKernel != "6.12.118+deb13-amd64" {
		t.Errorf("new kernel installed: %+v", st)
	}
	r.h.kernel = "6.12.118+deb13-amd64"
	if st := r.m.Report(); st.RebootRequired {
		t.Errorf("after the reboot: %+v", st)
	}
	// A rollback removed the running kernel.
	dropPackage(t, r.root, "linux-image-6.12.118+deb13-amd64")
	if st := r.m.Report(); !st.RebootRequired || !strings.Contains(st.RebootReasons[0], "removed") {
		t.Errorf("running kernel removed: %+v", st)
	}
	// Core libraries updated since boot: recommended, not required.
	r.h.kernel = "6.12.116+deb13-amd64"
	r.m.saveStatus(Status{State: StateOK, Time: time.Now(), Changes: []Change{{Package: "libc6", From: "1", To: "2"}}})
	st = r.m.Report()
	if st.RebootRequired || !st.RebootRecommended || !strings.Contains(strings.Join(st.RebootReasons, " "), "libc6") {
		t.Errorf("libc6 updated: %+v", st)
	}
	r.h.boot = time.Now().Add(time.Minute)
	if st := r.m.Report(); st.RebootRecommended {
		t.Errorf("rebooted since: %+v", st)
	}
}

func TestCleanupKernels(t *testing.T) {
	r := newRig(t)
	for _, k := range []string{"6.12.9", "6.12.116", "6.12.117", "6.12.118"} {
		setPackage(t, r.root, pkgDef{name: "linux-image-" + k + "+deb13-amd64", version: k + "-1"})
	}
	r.bundle(pkgDef{name: "x", version: "1"})
	r.h.kernel = "6.12.117+deb13-amd64" // reboot pending: keep everything
	if _, err := r.m.Install(); err != nil {
		t.Fatal(err)
	}
	if len(r.d.removes) != 0 {
		t.Fatalf("removed %v while a reboot is pending", r.d.removes)
	}
	r.h.kernel = "6.12.118+deb13-amd64"
	if _, err := r.m.Install(); err != nil {
		t.Fatal(err)
	}
	if len(r.d.removes) != 1 || strings.Join(r.d.removes[0], " ") != "linux-image-6.12.9+deb13-amd64 linux-image-6.12.116+deb13-amd64" || !r.d.purges[0] {
		t.Fatalf("removed %v (purge %v): want the two oldest (numeric order), purged", r.d.removes, r.d.purges)
	}
}

func TestRestore(t *testing.T) {
	r := newRig(t)
	setUpgrade(t, r.root, "0.9.13-r03", "0.9.14-r01", "in-progress")
	setPackage(t, r.root, pkgDef{name: "libc6", version: "1.0", files: map[string]string{"/usr/lib/libc": "v1"}})
	setPackage(t, r.root, pkgDef{name: "linux-image-amd64", version: "6.12.116-1"})
	setPackage(t, r.root, pkgDef{name: "linux-image-6.12.116+deb13-amd64", version: "6.12.116-1"})
	setPackage(t, r.root, pkgDef{name: "user", version: "1"})
	r.bundle(pkgDef{name: "libc6", version: "1.1", files: map[string]string{"/usr/lib/libc": "v1.1"}})
	r.bundle(pkgDef{name: "linux-image-amd64", version: "6.12.118-1"})
	r.bundle(pkgDef{name: "linux-image-6.12.118+deb13-amd64", version: "6.12.118-1"})
	r.bundle(pkgDef{name: "perl", version: "5.40"})
	r.bundle(pkgDef{name: "needed", version: "1"})
	if _, err := r.m.Install(); err != nil {
		t.Fatal(err)
	}
	r.h.kernel = "6.12.118+deb13-amd64" // rebooted onto the new kernel
	r.d.refuse["needed"] = true         // something else depends on it
	bdir := filepath.Join(r.root, "var/lib/sjb-os/releases/0.9.13-r03")
	res, err := r.m.Restore(bdir)
	if err != nil {
		t.Fatal(err)
	}
	if v := installedVersion(t, r.root, "libc6"); v != "1.0" {
		t.Errorf("libc6 %s after restore, want 1.0", v)
	}
	if v := installedVersion(t, r.root, "linux-image-amd64"); v != "6.12.116-1" {
		t.Errorf("linux-image-amd64 %s after restore", v)
	}
	last := len(r.d.downs) - 1
	if !r.d.downs[last] {
		t.Error("restore did not allow downgrades")
	}
	sort.Strings(res.Removed)
	if strings.Join(res.Removed, " ") != "linux-image-6.12.118+deb13-amd64 perl" || strings.Join(res.Kept, " ") != "needed" {
		t.Errorf("removed %v kept %v", res.Removed, res.Kept)
	}
	if !res.RunningKernel || r.d.allowRun != 1 {
		t.Errorf("running kernel removal: %v (preseeded %d)", res.RunningKernel, r.d.allowRun)
	}
	if v := installedVersion(t, r.root, "user"); v != "1" {
		t.Error("a package the upgrade didn't touch was changed")
	}
	if st := r.m.Report(); !st.RebootRequired {
		t.Errorf("after removing the running kernel: %+v", st)
	}
	// Already restored: running it again changes nothing.
	n := len(r.d.installs)
	if _, err := r.m.Restore(bdir); err != nil || len(r.d.installs) != n {
		t.Errorf("second restore: %v, installs %d -> %d", err, n, len(r.d.installs))
	}
}

func TestRestoreFailureAndSkip(t *testing.T) {
	r := newRig(t)
	res, err := r.m.Restore(filepath.Join(r.root, "var/lib/sjb-os/releases/0.9.12-r02"))
	if err != nil || !res.Skipped {
		t.Fatalf("no saved state: %+v %v", res, err)
	}
	setUpgrade(t, r.root, "0.9.13-r03", "0.9.14-r01", "in-progress")
	setPackage(t, r.root, pkgDef{name: "a", version: "1", files: map[string]string{"/usr/a": "1"}})
	r.bundle(pkgDef{name: "a", version: "2"})
	if _, err := r.m.Install(); err != nil {
		t.Fatal(err)
	}
	r.d.failNext = errors.New("exit status 1")
	conf := r.d.conf
	if _, err := r.m.Restore(filepath.Join(r.root, "var/lib/sjb-os/releases/0.9.13-r03")); err == nil {
		t.Fatal("want an error")
	}
	if r.d.conf != conf+1 {
		t.Error("dpkg --configure -a did not run after the failed restore")
	}
	// A missing saved copy is an error, not a silent skip.
	os.Remove(filepath.Join(r.root, "var/lib/sjb-os/releases/0.9.13-r03", SavedDir, "a_1_amd64.deb"))
	if _, err := r.m.Restore(filepath.Join(r.root, "var/lib/sjb-os/releases/0.9.13-r03")); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("err %v", err)
	}
}

func TestReportPending(t *testing.T) {
	r := newRig(t)
	setPackage(t, r.root, pkgDef{name: "a", version: "1"})
	r.bundle(pkgDef{name: "a", version: "2"})
	r.bundle(pkgDef{name: "b", version: "1"})
	if st := r.m.Report(); st.Pending != 2 || st.State != StateIdle {
		t.Errorf("%+v", st)
	}
	n := r.d.fields
	r.m.Report()
	if r.d.fields != n {
		t.Errorf("bundled files read again (%d -> %d): fields must be cached", n, r.d.fields)
	}
}

// --- reading the .debs repack writes ------------------------------------------

func readAr(t *testing.T, path string) map[string][]byte {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	br := bufio.NewReader(f)
	magic := make([]byte, 8)
	if _, err := io.ReadFull(br, magic); err != nil || string(magic) != "!<arch>\n" {
		t.Fatalf("not an ar archive: %q", magic)
	}
	out := map[string][]byte{}
	var order []string
	for {
		hdr := make([]byte, 60)
		if _, err := io.ReadFull(br, hdr); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		name := strings.TrimSpace(string(hdr[:16]))
		var size int64
		fmt.Sscan(strings.TrimSpace(string(hdr[48:58])), &size)
		data := make([]byte, size)
		if _, err := io.ReadFull(br, data); err != nil {
			t.Fatal(err)
		}
		if size%2 == 1 {
			br.ReadByte()
		}
		out[name] = data
		order = append(order, name)
	}
	if strings.Join(order, ",") != "debian-binary,control.tar.gz,data.tar.gz" || string(out["debian-binary"]) != "2.0\n" {
		t.Fatalf("members %v", order)
	}
	return out
}

func untar(t *testing.T, gz []byte) map[string]string {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(zr)
	out := map[string]string{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(tr)
		out[h.Name] = string(b)
	}
}

func readDeb(t *testing.T, path string) (ctl, data map[string]string) {
	m := readAr(t, path)
	c := untar(t, m["control.tar.gz"])
	ctl = map[string]string{}
	for k, v := range c {
		ctl[strings.TrimPrefix(k, "./")] = v
	}
	return ctl, untar(t, m["data.tar.gz"])
}

func readDebControl(t *testing.T, path string) (string, string, string, int64, error) {
	ctl, _ := readDeb(t, path)
	var name, ver string
	for _, line := range strings.Split(ctl["control"], "\n") {
		if v, ok := strings.CutPrefix(line, "Package: "); ok {
			name = v
		}
		if v, ok := strings.CutPrefix(line, "Version: "); ok {
			ver = v
		}
	}
	return name, ver, "amd64", 1, nil
}

func TestRepackSymlinksAndModes(t *testing.T) {
	root := t.TempDir()
	setPackage(t, root, pkgDef{name: "p", version: "1:2.0-1", files: map[string]string{"/usr/bin/tool": "bin"}})
	if err := os.Chmod(filepath.Join(root, "usr/bin/tool"), 0o755|os.ModeSetuid); err != nil {
		t.Fatal(err)
	}
	os.Symlink("tool", filepath.Join(root, "usr/bin/alias"))
	list := filepath.Join(root, dpkgInfo, "p.list")
	data, _ := os.ReadFile(list)
	os.WriteFile(list, append(data, []byte("/usr/bin/alias\n/usr/bin/deleted-by-admin\n")...), 0o644)
	inst, _ := installedPackages(root)
	out, err := repack(root, inst["p"], filepath.Join(root, "saved"))
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(out) != "p_1%3a2.0-1_amd64.deb" {
		t.Errorf("file name %s", filepath.Base(out))
	}
	m := readAr(t, out)
	zr, _ := gzip.NewReader(bytes.NewReader(m["data.tar.gz"]))
	tr := tar.NewReader(zr)
	seen := map[string]*tar.Header{}
	for {
		h, err := tr.Next()
		if err != nil {
			break
		}
		seen[h.Name] = h
	}
	if h := seen["./usr/bin/tool"]; h == nil || h.Mode&0o4000 == 0 {
		t.Errorf("setuid bit lost: %+v", h)
	}
	if h := seen["./usr/bin/alias"]; h == nil || h.Typeflag != tar.TypeSymlink || h.Linkname != "tool" {
		t.Errorf("symlink: %+v", h)
	}
	if h := seen["./"]; h == nil || h.Typeflag != tar.TypeDir {
		t.Error("root directory entry missing")
	}
	if _, ok := seen["./usr/bin/deleted-by-admin"]; ok {
		t.Error("a missing file was packed")
	}
}

// TestRepackLive repacks real installed packages for a check against real
// dpkg (deploy/appliance builds run it in a Debian container):
// OSPKG_LIVE_PACKAGES="libc6 sudo" OSPKG_LIVE_OUT=/tmp/out.
func TestRepackLive(t *testing.T) {
	pkgs, out := os.Getenv("OSPKG_LIVE_PACKAGES"), os.Getenv("OSPKG_LIVE_OUT")
	if pkgs == "" || out == "" {
		t.Skip("set OSPKG_LIVE_PACKAGES and OSPKG_LIVE_OUT")
	}
	inst, err := installedPackages("/")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range strings.Fields(pkgs) {
		f, err := repack("/", inst[p], out)
		if err != nil {
			t.Fatal(err)
		}
		t.Log(f)
	}
}

func TestNoRecommendationWithoutBootTime(t *testing.T) {
	r := newRig(t)
	r.h.boot = time.Time{}
	r.m.saveStatus(Status{State: StateOK, Time: time.Now(), Changes: []Change{{Package: "libc6", From: "1", To: "2"}}})
	if st := r.m.Report(); st.RebootRecommended {
		t.Errorf("recommended a reboot without knowing the boot time: %+v", st)
	}
}
