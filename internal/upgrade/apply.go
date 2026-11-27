package upgrade

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/stevejboyle/sjb-os/internal/store"
)

// Paths under the root filesystem.
const (
	VersionFile = "etc/ngfw-version"
	StateDir    = "var/lib/sjb-os"
	KeysDir     = "usr/share/sjb-os/upgrade-keys"
	// ConfigDir is ngfwd's config store (candidate and revisions).
	ConfigDir = "var/lib/ngfw"
)

// System is what Apply needs from the running appliance. Tests fake it.
type System interface {
	// Reload makes the system pick up changed files (systemd units, sysctl,
	// sshd settings). It is given the paths that changed.
	Reload(changed []string) error
	// RestartDaemon restarts ngfwd.
	RestartDaemon() error
	// Healthy blocks until ngfwd answers with the expected running revision,
	// or fails after its timeout.
	Healthy() error
}

// RevisionExpecter is optionally implemented by a System whose Healthy
// checks the running revision: a rollback that restores the config commits
// a new revision, and tells the System which one to expect.
type RevisionExpecter interface {
	ExpectRevision(n int)
}

// Event is one entry in the upgrade history.
type Event struct {
	Time   time.Time `json:"time"`
	Action string    `json:"action"` // upgrade or rollback
	From   string    `json:"from"`
	To     string    `json:"to"`
	Result string    `json:"result"` // in-progress, ok, failed, restored
	Error  string    `json:"error,omitempty"`
}

// Status is what `fwctl upgrade status` and the Web UI show.
type Status struct {
	Version    string  `json:"version"`
	RollbackTo string  `json:"rollback_to,omitempty"`
	InProgress bool    `json:"in_progress"`
	History    []Event `json:"history"`
}

type state struct {
	RollbackTo string  `json:"rollback_to,omitempty"`
	History    []Event `json:"history"`
}

type backupEntry struct {
	Path    string `json:"path"`
	Existed bool   `json:"existed"`
}

type backup struct {
	Version string        `json:"version"`
	Files   []backupEntry `json:"files"`
	// ConfigRevision is the running config revision when this version was
	// upgraded away from; its config is saved as config.yaml beside
	// backup.json. 0: none recorded (nothing committed, or a backup made
	// before 0.7.0).
	ConfigRevision int `json:"config_revision,omitempty"`
}

// RollbackResult says what a rollback did beyond restoring files.
type RollbackResult struct {
	// Packages summarises what RestorePackages did ("" if not set).
	Packages string
	// ConfigRestored is set when the config had changed since the upgrade
	// and the upgrade-time config was committed again as Revision.
	ConfigRestored bool
	From           int // the running revision before the rollback
	UpgradeTime    int // the revision that was running at the upgrade
	Revision       int // the new revision holding the upgrade-time config
}

// Installer applies bundles to the filesystem under Root ("/" on the
// appliance).
type Installer struct {
	Root string
	Sys  System
	Now  func() time.Time
	// BeforeRollback, if set, runs before a rollback restores files: it
	// undoes system setup (accounts, shells) that the current version made
	// and the older one may not expect. The restored version redoes its own
	// setup when ngfwd starts.
	BeforeRollback func() error
	// RestorePackages, if set, puts back the Debian packages the upgrade
	// replaced (saved in the release's backup directory, bdir). A rollback
	// runs it first, so a failure changes nothing else; a failed upgrade
	// runs it after putting the files back. It returns a summary to show.
	RestorePackages func(bdir string) (string, error)
}

func (in *Installer) p(rel string) string { return filepath.Join(in.Root, filepath.FromSlash(rel)) }

func (in *Installer) now() time.Time {
	if in.Now != nil {
		return in.Now()
	}
	return time.Now()
}

// CurrentVersion reads the installed SJB-OS version.
func (in *Installer) CurrentVersion() (string, error) {
	b, err := os.ReadFile(in.p(VersionFile))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// Keys loads the trusted signing keys from the installed system.
func (in *Installer) Keys() ([]PublicKey, error) { return LoadKeys(in.p(KeysDir)) }

// Status reports the installed version and history.
func (in *Installer) Status() (Status, error) {
	v, err := in.CurrentVersion()
	if err != nil {
		return Status{}, err
	}
	st, err := in.loadState()
	if err != nil {
		return Status{}, err
	}
	s := Status{Version: v, RollbackTo: st.RollbackTo, History: st.History}
	if s.History == nil {
		s.History = []Event{}
	}
	if n := len(st.History); n > 0 && st.History[n-1].Result == "in-progress" {
		s.InProgress = true
	}
	return s, nil
}

// Apply installs a verified bundle. If ngfwd does not come back healthy, the
// previous files are restored and the error says so.
func (in *Installer) Apply(b *Bundle, allowSame bool) (err error) {
	unlock, err := in.lock()
	if err != nil {
		return err
	}
	defer unlock()
	cur, err := in.CurrentVersion()
	if err != nil {
		return err
	}
	if err := CheckVersion(b.Manifest, cur, allowSame); err != nil {
		return err
	}
	ev, err := in.begin("upgrade", cur, b.Manifest.Version)
	if err != nil {
		return err
	}

	bdir := in.p(filepath.Join(StateDir, "releases", cur))
	if err := os.RemoveAll(bdir); err != nil {
		return in.finish(ev, "failed", err)
	}
	bk := backup{Version: cur}
	for _, f := range b.Manifest.Files {
		data, rerr := os.ReadFile(in.p(f.Path))
		switch {
		case rerr == nil:
			info, _ := os.Stat(in.p(f.Path))
			if werr := writeAtomic(filepath.Join(bdir, "files", filepath.FromSlash(f.Path)), data, info.Mode().Perm()); werr != nil {
				return in.finish(ev, "failed", fmt.Errorf("backing up %s: %w", f.Path, werr))
			}
			bk.Files = append(bk.Files, backupEntry{Path: f.Path, Existed: true})
		case errors.Is(rerr, os.ErrNotExist):
			bk.Files = append(bk.Files, backupEntry{Path: f.Path})
		default:
			return in.finish(ev, "failed", rerr)
		}
	}
	// Keep the running config as it is now: an older version may not
	// understand what later versions add, so a rollback brings this back.
	if n, data, cerr := in.configStore(); cerr != nil {
		return in.finish(ev, "failed", fmt.Errorf("reading the running config: %w", cerr))
	} else if n > 0 {
		if werr := writeAtomic(filepath.Join(bdir, "config.yaml"), data, 0o600); werr != nil {
			return in.finish(ev, "failed", fmt.Errorf("saving the running config: %w", werr))
		}
		bk.ConfigRevision = n
	}
	if err := writeJSON(filepath.Join(bdir, "backup.json"), bk); err != nil {
		return in.finish(ev, "failed", err)
	}

	changed := make([]string, 0, len(b.Manifest.Files))
	for _, f := range b.Manifest.Files {
		if err := writeAtomic(in.p(f.Path), b.Contents[f.Path], os.FileMode(f.Mode).Perm()); err != nil {
			return in.restoreAfter(ev, bdir, fmt.Errorf("installing %s: %w", f.Path, err))
		}
		changed = append(changed, f.Path)
	}
	if err := in.activate(changed); err != nil {
		return in.restoreAfter(ev, bdir, err)
	}
	if err := in.setRollback(cur); err != nil {
		return err
	}
	return in.finish(ev, "ok", nil)
}

// Rollback restores the files the last successful upgrade replaced. If the
// config changed after that upgrade, the config that was running at the
// upgrade is committed again as a new revision, since the older version
// may not understand settings added since; the later revisions stay in
// the history.
func (in *Installer) Rollback() (res RollbackResult, err error) {
	unlock, err := in.lock()
	if err != nil {
		return res, err
	}
	defer unlock()
	st, err := in.loadState()
	if err != nil {
		return res, err
	}
	if st.RollbackTo == "" {
		return res, fmt.Errorf("nothing to roll back to: no upgrade has been applied since the last rollback")
	}
	cur, err := in.CurrentVersion()
	if err != nil {
		return res, err
	}
	ev, err := in.begin("rollback", cur, st.RollbackTo)
	if err != nil {
		return res, err
	}
	bdir := in.p(filepath.Join(StateDir, "releases", st.RollbackTo))
	pkgs := ""
	if in.RestorePackages != nil {
		if pkgs, err = in.RestorePackages(bdir); err != nil {
			return res, in.finish(ev, "failed", fmt.Errorf("restoring OS packages: %w", err))
		}
	}
	if in.BeforeRollback != nil {
		if err := in.BeforeRollback(); err != nil {
			return res, in.finish(ev, "failed", fmt.Errorf("preparing rollback: %w", err))
		}
	}
	changed, err := in.restore(bdir)
	if err != nil {
		return res, in.finish(ev, "failed", err)
	}
	if res, err = in.restoreConfig(bdir, st, cur); err != nil {
		return res, in.finish(ev, "failed", fmt.Errorf("restoring the config: %w", err))
	}
	res.Packages = pkgs
	if res.ConfigRestored {
		if e, ok := in.Sys.(RevisionExpecter); ok {
			e.ExpectRevision(res.Revision)
		}
	}
	if err := in.activate(changed); err != nil {
		return res, in.finish(ev, "failed", err)
	}
	if err := in.setRollback(""); err != nil {
		return res, err
	}
	return res, in.finish(ev, "ok", nil)
}

// upgradeTime is when the last successful upgrade from -> to happened (zero
// if the history doesn't say).
func upgradeTime(h []Event, from, to string) time.Time {
	for i := len(h) - 1; i >= 0; i-- {
		if e := h[i]; e.Action == "upgrade" && e.Result == "ok" && e.From == from && e.To == to {
			return e.Time
		}
	}
	return time.Time{}
}

// revisionAt is the newest revision committed at or before t (0: none, or
// t is zero).
func revisionAt(st *store.Store, t time.Time) (int, error) {
	if t.IsZero() {
		return 0, nil
	}
	revs, err := st.List()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, r := range revs {
		if !r.Time.After(t) {
			n = r.N
		}
	}
	return n, nil
}

// configStore returns the running revision and its config (0 and nil when
// there is no config store or nothing committed).
func (in *Installer) configStore() (int, []byte, error) {
	dir := in.p(ConfigDir)
	if _, err := os.Stat(filepath.Join(dir, "running")); errors.Is(err, os.ErrNotExist) {
		return 0, nil, nil
	}
	st, err := store.Open(dir)
	if err != nil {
		return 0, nil, err
	}
	return st.Running()
}

// restoreConfig commits the upgrade-time config again when the running
// config differs from it. It runs before the restart that starts the older
// ngfwd, which then loads this revision. Callers refuse a rollback while a
// commit awaits confirmation; any pending record left is cleared anyway, so
// the older ngfwd doesn't revert to a revision it can't read.
func (in *Installer) restoreConfig(bdir string, state state, from string) (RollbackResult, error) {
	var res RollbackResult
	to := state.RollbackTo
	data, err := os.ReadFile(filepath.Join(bdir, "backup.json"))
	if err != nil {
		return res, err
	}
	var bk backup
	if err := json.Unmarshal(data, &bk); err != nil {
		return res, err
	}
	n, running, err := in.configStore()
	if err != nil || n == 0 {
		return res, err
	}
	st, err := store.Open(in.p(ConfigDir))
	if err != nil {
		return res, err
	}
	var saved []byte
	if bk.ConfigRevision > 0 {
		if saved, err = os.ReadFile(filepath.Join(bdir, "config.yaml")); err != nil {
			return res, err
		}
	} else {
		// A backup made by an older fwctl records no config: take the last
		// revision committed before that upgrade (revisions are kept).
		if bk.ConfigRevision, err = revisionAt(st, upgradeTime(state.History, to, from)); err != nil || bk.ConfigRevision == 0 {
			return res, err
		}
		if saved, err = st.Get(bk.ConfigRevision); err != nil {
			return res, err
		}
	}
	res.From, res.UpgradeTime = n, bk.ConfigRevision
	if bytes.Equal(running, saved) {
		return res, nil
	}
	if err := st.ClearPending(); err != nil {
		return res, err
	}
	msg := fmt.Sprintf("rollback %s -> %s: the config of revision %d, running when %s was upgraded", from, to, bk.ConfigRevision, to)
	rev, err := st.Save(saved, "sjb-os rollback", msg, in.now())
	if err != nil {
		return res, err
	}
	res.ConfigRestored, res.Revision = true, rev.N
	return res, nil
}

func (in *Installer) activate(changed []string) error {
	if err := in.Sys.Reload(changed); err != nil {
		return fmt.Errorf("reloading: %w", err)
	}
	if err := in.Sys.RestartDaemon(); err != nil {
		return fmt.Errorf("restarting ngfwd: %w", err)
	}
	if err := in.Sys.Healthy(); err != nil {
		return fmt.Errorf("ngfwd not healthy after the upgrade: %w", err)
	}
	return nil
}

// restoreAfter puts the backup back after a failed install and records why.
func (in *Installer) restoreAfter(ev int, bdir string, cause error) error {
	changed, err := in.restore(bdir)
	if err == nil {
		err = in.activate(changed)
	}
	if err == nil && in.RestorePackages != nil {
		// The new version's packages may have started installing when its
		// ngfwd started: put the saved versions back too.
		if _, perr := in.RestorePackages(bdir); perr != nil {
			err = fmt.Errorf("restoring OS packages: %w", perr)
		}
	}
	if err != nil {
		return in.finish(ev, "failed", fmt.Errorf("%v; restoring the previous version also failed: %v", cause, err))
	}
	return in.finish(ev, "restored", fmt.Errorf("%v; previous version restored", cause))
}

func (in *Installer) restore(bdir string) ([]string, error) {
	var bk backup
	data, err := os.ReadFile(filepath.Join(bdir, "backup.json"))
	if err != nil {
		return nil, fmt.Errorf("no backup at %s: %w", bdir, err)
	}
	if err := json.Unmarshal(data, &bk); err != nil {
		return nil, err
	}
	var changed []string
	for _, f := range bk.Files {
		if !Allowed(f.Path) {
			return nil, fmt.Errorf("backup lists %s, which is not an upgradable path", f.Path)
		}
		if !f.Existed {
			if err := os.Remove(in.p(f.Path)); err != nil && !errors.Is(err, os.ErrNotExist) {
				return nil, err
			}
			changed = append(changed, f.Path)
			continue
		}
		src := filepath.Join(bdir, "files", filepath.FromSlash(f.Path))
		data, err := os.ReadFile(src)
		if err != nil {
			return nil, err
		}
		info, err := os.Stat(src)
		if err != nil {
			return nil, err
		}
		if err := writeAtomic(in.p(f.Path), data, info.Mode().Perm()); err != nil {
			return nil, err
		}
		changed = append(changed, f.Path)
	}
	sort.Strings(changed)
	return changed, nil
}

func (in *Installer) lock() (func(), error) {
	dir := in.p(StateDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, "upgrade.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("another upgrade or rollback is running")
	}
	return func() {
		syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}

func (in *Installer) statePath() string { return in.p(filepath.Join(StateDir, "upgrades.json")) }

func (in *Installer) loadState() (state, error) {
	var st state
	data, err := os.ReadFile(in.statePath())
	if errors.Is(err, os.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return st, err
	}
	return st, json.Unmarshal(data, &st)
}

func (in *Installer) begin(action, from, to string) (int, error) {
	st, err := in.loadState()
	if err != nil {
		return 0, err
	}
	st.History = append(st.History, Event{Time: in.now().UTC(), Action: action, From: from, To: to, Result: "in-progress"})
	return len(st.History) - 1, writeJSON(in.statePath(), st)
}

// finish records the outcome of event i and returns cause unchanged.
func (in *Installer) finish(i int, result string, cause error) error {
	st, err := in.loadState()
	if err == nil && i < len(st.History) {
		st.History[i].Result = result
		if cause != nil {
			st.History[i].Error = cause.Error()
		}
		err = writeJSON(in.statePath(), st)
	}
	if cause != nil {
		return cause
	}
	return err
}

func (in *Installer) setRollback(v string) error {
	st, err := in.loadState()
	if err != nil {
		return err
	}
	st.RollbackTo = v
	return writeJSON(in.statePath(), st)
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(path, append(b, '\n'), 0o644)
}

// writeAtomic replaces path so readers see either the old or the new file,
// never a partial one (a running binary keeps its old inode).
func writeAtomic(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".sjb-new-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
