// Package ospkg installs the Debian packages an SJB-OS upgrade bundle
// carries (SJB-OS's own dependencies and Debian's security and point-release
// updates, the kernel included), keeps what a rollback needs to put the
// previous versions back, and reports the result and whether a reboot is
// needed.
package ospkg

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/stevejboyle/sjb-os/internal/upgrade"
)

// Paths under the root filesystem.
const (
	DebDir     = "usr/share/sjb-os/packages"
	UpdatesTxt = "usr/share/sjb-os/packages/os-updates.txt"
	StatusFile = "var/lib/sjb-os/packages-status.json"
	lockFile   = "var/lib/sjb-os/packages.lock"
	// SavedDir, inside a release's backup directory, holds the packages an
	// upgrade replaced (repacked) and packages.json.
	SavedDir = "packages"
)

// Absent is the old version of a package the upgrade added.
const Absent = "absent"

// States of the last install.
const (
	StateIdle       = "idle" // nothing has been installed by SJB-OS here
	StateInstalling = "installing"
	StateOK         = "ok"
	StateFailed     = "failed"
)

// rebootLibs are packages whose update leaves running services on the old
// code until they restart, so a reboot is recommended.
var rebootLibs = map[string]bool{"libc6": true, "systemd": true, "libssl3t64": true, "libssl3": true}

var kernelPkg = regexp.MustCompile(`^linux-image-(\d.*)$`)

// Dpkg runs dpkg. Tests fake it.
type Dpkg interface {
	// Fields reads Package, Version, Architecture and Installed-Size (KiB)
	// from a .deb file.
	Fields(deb string) (pkg, version, arch string, sizeKB int64, err error)
	// Install installs the files as one set; downgrade allows older versions.
	Install(debs []string, downgrade bool) ([]byte, error)
	// Remove removes (or with purge, purges) the packages as one set.
	Remove(pkgs []string, purge bool) ([]byte, error)
	// Configure finishes any half-configured packages (dpkg --configure -a).
	Configure() ([]byte, error)
	// AllowRunningKernelRemoval answers yes, in advance, to Debian's question
	// when removing the running kernel.
	AllowRunningKernelRemoval() error
}

// Host is what the manager needs to know about the running system.
type Host interface {
	RunningKernel() string // uname -r
	BootTime() time.Time
	FreeBytes(path string) (uint64, error)
}

// Change is one package an install changed.
type Change struct {
	Package  string `json:"package"`
	From     string `json:"from"` // Absent if newly installed
	To       string `json:"to"`
	Security bool   `json:"security,omitempty"`
}

// Status is the result of the last install, saved in StatusFile.
type Status struct {
	State   string    `json:"state"`
	Time    time.Time `json:"time,omitempty"`
	Error   string    `json:"error,omitempty"`
	Changes []Change  `json:"changes,omitempty"`
	// Pending counts bundled packages not yet installed (newer than what is
	// installed); filled in by Report.
	Pending int `json:"pending"`
	// Reboot, filled in by Report from the live system.
	RebootRequired    bool     `json:"reboot_required"`
	RebootRecommended bool     `json:"reboot_recommended"`
	RebootReasons     []string `json:"reboot_reasons,omitempty"`
	RunningKernel     string   `json:"running_kernel,omitempty"`
	NewestKernel      string   `json:"newest_kernel,omitempty"`
}

// Updated and Security count the changes, for one-line summaries.
func (s Status) Updated() int { return len(s.Changes) }

func (s Status) Security() int {
	n := 0
	for _, c := range s.Changes {
		if c.Security {
			n++
		}
	}
	return n
}

// Saved is packages.json: what an upgrade's install replaced.
type Saved struct {
	Version string   `json:"version"` // the SJB-OS version these belong to
	Changes []Change `json:"changes"`
}

// Manager installs and restores packages on the system under Root.
type Manager struct {
	Root string
	Dpkg Dpkg
	Host Host
	Now  func() time.Time
	// Log receives progress lines.
	Log func(string)

	cacheMu sync.Mutex
	cache   map[string]cachedDeb // bundled .deb fields by path
}

type cachedDeb struct {
	size  int64
	mtime time.Time
	deb   bundled
}

func (m *Manager) p(rel string) string { return filepath.Join(m.Root, filepath.FromSlash(rel)) }

func (m *Manager) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

func (m *Manager) logf(format string, a ...any) {
	if m.Log != nil {
		m.Log(fmt.Sprintf(format, a...))
	}
}

// lock serialises installs and restores (dpkg has its own lock, but the
// saved state must not be read while it is being written). It waits up to
// wait for a running install to finish.
func (m *Manager) lock(wait time.Duration) (func(), error) {
	path := m.p(lockFile)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(wait)
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if !time.Now().Before(deadline) {
			f.Close()
			return nil, fmt.Errorf("an OS package install is still running")
		}
		time.Sleep(time.Second)
	}
	return func() {
		syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}

// bundled is one .deb the bundle carries.
type bundled struct {
	file, pkg, version, arch string
	sizeKB                   int64
}

func (m *Manager) bundledDebs() ([]bundled, error) {
	files, err := filepath.Glob(filepath.Join(m.p(DebDir), "*.deb"))
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	var out []bundled
	m.cacheMu.Lock()
	defer m.cacheMu.Unlock()
	if m.cache == nil {
		m.cache = map[string]cachedDeb{}
	}
	for _, f := range files {
		info, err := os.Stat(f)
		if err != nil {
			return nil, err
		}
		if c, ok := m.cache[f]; ok && c.size == info.Size() && c.mtime.Equal(info.ModTime()) {
			out = append(out, c.deb)
			continue
		}
		pkg, ver, arch, kb, err := m.Dpkg.Fields(f)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", filepath.Base(f), err)
		}
		d := bundled{file: f, pkg: pkg, version: ver, arch: arch, sizeKB: kb}
		m.cache[f] = cachedDeb{size: info.Size(), mtime: info.ModTime(), deb: d}
		out = append(out, d)
	}
	return out, nil
}

// toInstall is the bundled packages that are missing or older than the
// bundle's: never a downgrade.
func toInstall(debs []bundled, inst map[string]stanza) []bundled {
	var out []bundled
	for _, d := range debs {
		if s, ok := inst[d.pkg]; ok && CompareVersions(s.get("Version"), d.version) >= 0 {
			continue
		}
		out = append(out, d)
	}
	return out
}

// securityUpdates reads os-updates.txt: "NAME OLD NEW SUITE security|update".
func (m *Manager) securityUpdates() map[string]bool {
	out := map[string]bool{}
	f, err := os.Open(m.p(UpdatesTxt))
	if err != nil {
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fl := strings.Fields(sc.Text())
		if len(fl) == 5 && fl[4] == "security" {
			out[fl[0]+" "+fl[2]] = true
		}
	}
	return out
}

// savedDir is where this upgrade keeps the replaced packages: the backup
// directory of the version it upgraded from, found from the upgrade
// history (the install runs while the upgrade is still finishing, before
// the rollback target is recorded). Empty when the running version was not
// reached by an upgrade (a fresh appliance, or after a rollback).
func (m *Manager) savedDir() (string, string) {
	in := &upgrade.Installer{Root: m.Root}
	st, err := in.Status()
	if err != nil || len(st.History) == 0 {
		return "", ""
	}
	e := st.History[len(st.History)-1]
	if e.Action != "upgrade" || e.To != st.Version || (e.Result != "ok" && e.Result != "in-progress") {
		return "", ""
	}
	return filepath.Join(m.p(upgrade.StateDir), "releases", e.From, SavedDir), e.To
}

func readSaved(dir string) (Saved, error) {
	var s Saved
	data, err := os.ReadFile(filepath.Join(dir, "packages.json"))
	if err != nil {
		return s, err
	}
	return s, json.Unmarshal(data, &s)
}

func writeJSON(path string, v any, mode os.FileMode) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".new"
	if err := os.WriteFile(tmp, append(b, '\n'), mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// LoadStatus reads the saved status (StateIdle if there is none).
func (m *Manager) LoadStatus() Status {
	st := Status{State: StateIdle}
	if data, err := os.ReadFile(m.p(StatusFile)); err == nil {
		json.Unmarshal(data, &st)
	}
	return st
}

func (m *Manager) saveStatus(st Status) error {
	st.Pending, st.RebootRequired, st.RebootRecommended, st.RebootReasons, st.RunningKernel, st.NewestKernel = 0, false, false, nil, "", ""
	return writeJSON(m.p(StatusFile), st, 0o644)
}

// minFree is the space kept free on top of what an install needs.
const minFree = 200 << 20

// checkSpace refuses an install that would fill the disk: the installed
// size of the new packages, plus the repacked copies, plus a margin.
func (m *Manager) checkSpace(need uint64) error {
	for _, dir := range []string{"/", "/boot"} {
		free, err := m.Host.FreeBytes(m.p(dir))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return err
		}
		if dir == "/boot" {
			// /boot only takes the kernel and initramfs; it is usually on /.
			need = 150 << 20
		}
		if free < need+minFree {
			return fmt.Errorf("not enough disk space on %s: %d MB free, %d MB needed", dir, free>>20, (need+minFree)>>20)
		}
	}
	return nil
}

// Install installs the bundled packages that are missing or newer than the
// installed ones. Before replacing anything it saves the installed versions
// (repacked) for a rollback, once per upgrade: a later run adds packages it
// hasn't saved yet and never replaces what is saved. Then it removes old
// kernels beyond the running one and the one before it, once the newest is
// running. It returns the changes made (nil if there was nothing to do).
func (m *Manager) Install() ([]Change, error) {
	unlock, err := m.lock(0)
	if err != nil {
		return nil, err
	}
	defer unlock()
	debs, err := m.bundledDebs()
	if err != nil {
		return nil, m.fail(nil, err)
	}
	inst, err := installedPackages(m.Root)
	if err != nil {
		return nil, m.fail(nil, fmt.Errorf("reading dpkg's database: %w", err))
	}
	todo := toInstall(debs, inst)
	if len(todo) == 0 {
		m.cleanupKernels(inst)
		return nil, nil
	}
	sec := m.securityUpdates()
	var changes []Change
	var need uint64
	for _, d := range todo {
		c := Change{Package: d.pkg, From: Absent, To: d.version, Security: sec[d.pkg+" "+d.version]}
		if s, ok := inst[d.pkg]; ok {
			c.From = s.get("Version")
			if kb, ok := parseKB(s.get("Installed-Size")); ok {
				need += uint64(kb) << 10 // the repacked copy, at most
			}
		}
		need += uint64(d.sizeKB) << 10
		changes = append(changes, c)
	}
	if err := m.checkSpace(need); err != nil {
		return nil, m.fail(changes, err)
	}
	if err := m.save(changes, inst); err != nil {
		return nil, m.fail(changes, fmt.Errorf("saving the installed versions for a rollback: %w", err))
	}
	m.saveStatus(Status{State: StateInstalling, Time: m.now().UTC(), Changes: changes})
	files := make([]string, len(todo))
	for i, d := range todo {
		files[i] = d.file
	}
	m.logf("installing %d package(s): %s", len(todo), names(changes))
	if out, err := m.Dpkg.Install(files, false); err != nil {
		cout, _ := m.Dpkg.Configure()
		return nil, m.fail(changes, fmt.Errorf("dpkg: %v: %s%s", err, lastLines(out, 5), lastLines(cout, 3)))
	}
	if err := m.saveStatus(Status{State: StateOK, Time: m.now().UTC(), Changes: changes}); err != nil {
		return changes, err
	}
	m.logf("done: %d package(s) updated", len(changes))
	if after, err := installedPackages(m.Root); err == nil {
		m.cleanupKernels(after)
	}
	return changes, nil
}

func (m *Manager) fail(changes []Change, err error) error {
	m.saveStatus(Status{State: StateFailed, Time: m.now().UTC(), Error: err.Error(), Changes: changes})
	return err
}

// save repacks the installed versions of the packages about to be replaced
// into the upgrade's backup directory and records every change. Kernels
// are never replaced in place (each version is its own package), so none
// is repacked.
func (m *Manager) save(changes []Change, inst map[string]stanza) error {
	dir, version := m.savedDir()
	if dir == "" {
		return nil // not reached by an upgrade: nothing to roll back to
	}
	saved, err := readSaved(dir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	saved.Version = version
	have := map[string]bool{}
	for _, c := range saved.Changes {
		have[c.Package] = true
	}
	for _, c := range changes {
		if have[c.Package] {
			continue // saved by an earlier run of this upgrade: keep it
		}
		if c.From != Absent {
			if _, err := repack(m.Root, inst[c.Package], dir); err != nil {
				return err
			}
		}
		saved.Changes = append(saved.Changes, c)
		if err := writeJSON(filepath.Join(dir, "packages.json"), saved, 0o600); err != nil {
			return err
		}
	}
	return nil
}

// kernels lists the installed kernel versions, oldest first.
func kernels(inst map[string]stanza) []string {
	var out []string
	for name := range inst {
		if k := kernelPkg.FindStringSubmatch(name); k != nil {
			out = append(out, k[1])
		}
	}
	sort.Slice(out, func(i, j int) bool { return naturalLess(out[i], out[j]) })
	return out
}

// cleanupKernels purges kernels older than the one before the running
// kernel, once the running kernel is the newest (never while a reboot onto
// a new kernel is pending, so the fallback always stays).
func (m *Manager) cleanupKernels(inst map[string]stanza) {
	ks := kernels(inst)
	if len(ks) <= 2 || ks[len(ks)-1] != m.Host.RunningKernel() {
		return
	}
	var old []string
	for _, k := range ks[:len(ks)-2] {
		old = append(old, "linux-image-"+k)
	}
	m.logf("removing old kernels: %s", strings.Join(old, " "))
	if out, err := m.Dpkg.Remove(old, true); err != nil {
		m.logf("removing old kernels failed: %v: %s", err, lastLines(out, 3))
	}
}

// RestoreResult says what Restore did.
type RestoreResult struct {
	Skipped       bool     // nothing saved for this upgrade (made before 0.9.14)
	Downgraded    []Change // put back to their earlier versions
	Removed       []string // packages the upgrade added, removed
	Kept          []string // added packages dpkg would not remove (still needed)
	RunningKernel bool     // the running kernel was removed: reboot now
}

// Restore puts back the package versions saved in a release's backup
// directory (bdir/packages): the replaced packages are reinstalled, and
// the packages the upgrade added are removed where nothing else needs them.
// It waits for a running install to finish first.
func (m *Manager) Restore(bdir string) (RestoreResult, error) {
	var res RestoreResult
	dir := filepath.Join(bdir, SavedDir)
	saved, err := readSaved(dir)
	if errors.Is(err, os.ErrNotExist) {
		res.Skipped = true
		return res, nil
	}
	if err != nil {
		return res, err
	}
	unlock, err := m.lock(15 * time.Minute)
	if err != nil {
		return res, err
	}
	defer unlock()
	inst, err := installedPackages(m.Root)
	if err != nil {
		return res, err
	}
	var debs []string
	var added []string
	for _, c := range saved.Changes {
		s, ok := inst[c.Package]
		if c.From == Absent {
			if ok {
				added = append(added, c.Package)
			}
			continue
		}
		if ok && s.get("Version") == c.From {
			continue // already at the saved version
		}
		f := filepath.Join(dir, debFileName(c.Package, c.From, archOf(s, inst)))
		if _, err := os.Stat(f); err != nil {
			matches, _ := filepath.Glob(filepath.Join(dir, c.Package+"_"+strings.ReplaceAll(c.From, ":", "%3a")+"_*.deb"))
			if len(matches) == 0 {
				return res, fmt.Errorf("the saved copy of %s %s is missing", c.Package, c.From)
			}
			f = matches[0]
		}
		debs = append(debs, f)
		res.Downgraded = append(res.Downgraded, c)
	}
	if len(debs) > 0 {
		m.logf("restoring %d package(s): %s", len(debs), names(res.Downgraded))
		if out, err := m.Dpkg.Install(debs, true); err != nil {
			cout, _ := m.Dpkg.Configure()
			return res, fmt.Errorf("reinstalling the earlier package versions: %v: %s%s", err, lastLines(out, 5), lastLines(cout, 3))
		}
	}
	if len(added) > 0 {
		running := "linux-image-" + m.Host.RunningKernel()
		for _, p := range added {
			if p == running {
				if err := m.Dpkg.AllowRunningKernelRemoval(); err != nil {
					return res, err
				}
				res.RunningKernel = true
			}
		}
		res.Removed, res.Kept = m.removeAll(added)
		if res.RunningKernel && contains(res.Kept, running) {
			res.RunningKernel = false
		}
	}
	return res, nil
}

// removeAll removes the packages, as one set first (dpkg orders it), then
// one at a time for as long as that makes progress; what dpkg refuses to
// remove (something still depends on it) is returned as kept.
func (m *Manager) removeAll(pkgs []string) (removed, kept []string) {
	purgeKernels := func(set []string) error {
		var k, o []string
		for _, p := range set {
			if kernelPkg.MatchString(p) {
				k = append(k, p)
			} else {
				o = append(o, p)
			}
		}
		if len(o) > 0 {
			if out, err := m.Dpkg.Remove(o, false); err != nil {
				return fmt.Errorf("%v: %s", err, lastLines(out, 3))
			}
		}
		if len(k) > 0 {
			if out, err := m.Dpkg.Remove(k, true); err != nil {
				return fmt.Errorf("%v: %s", err, lastLines(out, 3))
			}
		}
		return nil
	}
	if err := purgeKernels(pkgs); err == nil {
		return pkgs, nil
	}
	left := append([]string(nil), pkgs...)
	for progress := true; progress && len(left) > 0; {
		progress = false
		var next []string
		for _, p := range left {
			if err := purgeKernels([]string{p}); err != nil {
				next = append(next, p)
				continue
			}
			removed = append(removed, p)
			progress = true
		}
		left = next
	}
	return removed, left
}

// Report is the saved status plus what the live system says: pending
// packages and whether a reboot is required (a newer kernel is installed
// than the one running) or recommended (core libraries changed since boot).
func (m *Manager) Report() Status {
	st := m.LoadStatus()
	inst, err := installedPackages(m.Root)
	if err == nil {
		if debs, err := m.bundledDebs(); err == nil {
			st.Pending = len(toInstall(debs, inst))
		}
		ks := kernels(inst)
		st.RunningKernel = m.Host.RunningKernel()
		if len(ks) > 0 && st.RunningKernel != "" {
			st.NewestKernel = ks[len(ks)-1]
			switch {
			case !contains(ks, st.RunningKernel):
				st.RebootRequired = true
				st.RebootReasons = append(st.RebootReasons, "the running kernel was removed; kernel "+kernelShort(st.NewestKernel)+" is installed")
			case naturalLess(st.RunningKernel, st.NewestKernel):
				st.RebootRequired = true
				st.RebootReasons = append(st.RebootReasons, "kernel "+kernelShort(st.NewestKernel))
			}
		}
	}
	if boot := m.Host.BootTime(); st.State == StateOK && !boot.IsZero() && st.Time.After(boot) {
		var libs []string
		for _, c := range st.Changes {
			if rebootLibs[c.Package] {
				libs = append(libs, c.Package)
			}
		}
		if len(libs) > 0 {
			st.RebootRecommended = true
			if !st.RebootRequired {
				st.RebootReasons = append(st.RebootReasons, "updated "+strings.Join(libs, ", "))
			}
		}
	}
	return st
}

// kernelShort is "6.12.118" for "6.12.118+deb13-amd64".
func kernelShort(k string) string {
	if i := strings.IndexAny(k, "+-"); i > 0 {
		return k[:i]
	}
	return k
}

// naturalLess orders kernel versions: digit runs compare as numbers.
func naturalLess(a, b string) bool {
	for a != "" && b != "" {
		ad, bd := isDigit(a[0]), isDigit(b[0])
		if ad && bd {
			i, j := 0, 0
			for i < len(a) && isDigit(a[i]) {
				i++
			}
			for j < len(b) && isDigit(b[j]) {
				j++
			}
			na, nb := strings.TrimLeft(a[:i], "0"), strings.TrimLeft(b[:j], "0")
			if len(na) != len(nb) {
				return len(na) < len(nb)
			}
			if na != nb {
				return na < nb
			}
			a, b = a[i:], b[j:]
			continue
		}
		if a[0] != b[0] {
			return a[0] < b[0]
		}
		a, b = a[1:], b[1:]
	}
	return len(a) < len(b)
}

func archOf(s stanza, inst map[string]stanza) string {
	if a := s.get("Architecture"); a != "" {
		return a
	}
	if d, ok := inst["dpkg"]; ok {
		return d.get("Architecture")
	}
	return "amd64"
}

func parseKB(s string) (int64, bool) {
	var n int64
	if _, err := fmt.Sscan(strings.TrimSpace(s), &n); err != nil {
		return 0, false
	}
	return n, true
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func names(cs []Change) string {
	n := make([]string, len(cs))
	for i, c := range cs {
		n[i] = c.Package
	}
	return strings.Join(n, " ")
}

func lastLines(b []byte, n int) string {
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}
