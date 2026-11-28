package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/stevejboyle/sjb-os/internal/accounts"
	"github.com/stevejboyle/sjb-os/internal/config"
	"github.com/stevejboyle/sjb-os/internal/metrics"
	"github.com/stevejboyle/sjb-os/internal/upgrade"
)

// Online updates: the appliance checks its update server daily for a newer
// release, downloads and verifies it, and keeps it staged until an admin
// installs it. Nothing here installs on its own.
//
// The server publishes a signed release index (upgrade.Index); the bundle it
// names is downloaded, checked against the index's size and SHA-256, then
// verified like an uploaded bundle. The checks and downloads never hold d.mu.

// UpdateSource is what online updates need from the appliance.
type UpdateSource struct {
	Installer *upgrade.Installer
	Client    *http.Client // nil: a default with timeouts
	// Start runs the install of a staged bundle (fwctl upgrade apply in its
	// own unit). Tests fake it.
	Start func(path string) error
	// FreeBytes reports the space available under dir (nil: statfs).
	FreeBytes func(dir string) (uint64, error)
}

// StagedUpdate is a downloaded, verified release waiting to be installed.
type StagedUpdate struct {
	Version    string    `json:"version"`
	Size       int64     `json:"size"`
	SHA256     string    `json:"sha256"`
	Notes      string    `json:"notes,omitempty"`
	Downloaded time.Time `json:"downloaded"`
}

// UpdateCheck is the outcome of the last check, kept across restarts.
type UpdateCheck struct {
	Time   time.Time        `json:"time,omitempty"`
	OK     bool             `json:"ok"`
	Result string           `json:"result,omitempty"`
	Server string           `json:"server,omitempty"`
	Latest *upgrade.Release `json:"latest,omitempty"`
	// Published is the newest index publish time accepted: an index older
	// than that is refused, so an old signed index can't be replayed.
	Published time.Time     `json:"published,omitempty"`
	Staged    *StagedUpdate `json:"staged,omitempty"`
}

// UpdatesStatus is what `show system updates`, the web UI and the status
// API show.
type UpdatesStatus struct {
	Available bool          `json:"available"` // online updates work here
	Enabled   bool          `json:"enabled"`   // system update-check
	Server    string        `json:"server"`
	Installed string        `json:"installed"`
	Checking  bool          `json:"checking"`
	LastCheck UpdateCheck   `json:"last_check"`
	Staged    *StagedUpdate `json:"staged,omitempty"`
	// UpdateReady: a staged release newer than the installed one.
	UpdateReady bool `json:"update_ready"`
}

type updatesState struct {
	src      UpdateSource
	mu       sync.Mutex // guards check and checking (never held with d.mu)
	check    UpdateCheck
	checking bool
}

const (
	updatesCheckFile = "update-check.json"
	stagedUpdateName = "auto.upgrade"
	// updateDiskMargin is the space left free beyond a download.
	updateDiskMargin = 64 << 20
)

func (u *updatesState) dir() string {
	return filepath.Join(u.src.Installer.Root, upgrade.StateDir)
}
func (u *updatesState) bundlePath() string {
	return filepath.Join(u.dir(), "incoming", stagedUpdateName)
}

// SetUpdates turns on online updates. A staged release the appliance
// already runs (or has passed) is removed.
func (d *Daemon) SetUpdates(src UpdateSource) {
	u := &updatesState{src: src}
	if data, err := os.ReadFile(filepath.Join(u.dir(), updatesCheckFile)); err == nil {
		json.Unmarshal(data, &u.check)
	}
	if cur, err := src.Installer.CurrentVersion(); err == nil && u.check.Staged != nil && !newer(u.check.Staged.Version, cur) {
		d.log.Info("removing the staged update: this version or a newer one is installed", "staged", u.check.Staged.Version, "installed", cur)
		os.Remove(u.bundlePath())
		u.check.Staged = nil
		u.save()
	}
	if u.check.Staged != nil {
		if _, err := os.Stat(u.bundlePath()); err != nil {
			u.check.Staged = nil
			u.save()
		}
	}
	d.updates.Store(u)
}

// newer reports whether version a sorts after b (false if either doesn't
// parse).
func newer(a, b string) bool {
	va, err1 := upgrade.ParseVersion(a)
	vb, err2 := upgrade.ParseVersion(b)
	return err1 == nil && err2 == nil && va.Compare(vb) > 0
}

func (u *updatesState) save() error {
	data, _ := json.MarshalIndent(u.check, "", "  ")
	if err := os.MkdirAll(u.dir(), 0o755); err != nil {
		return err
	}
	tmp := filepath.Join(u.dir(), "."+updatesCheckFile)
	if err := os.WriteFile(tmp, append(data, '\n'), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(u.dir(), updatesCheckFile))
}

// updateSettings reads the update settings from the running config.
func (d *Daemon) updateSettings() (enabled bool, server string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var sys config.System
	if d.running != nil {
		sys = d.running.System
	}
	return sys.UpdateCheckOn(), sys.UpdateServerURL()
}

// Updates reports the online update state.
func (d *Daemon) Updates() UpdatesStatus {
	enabled, server := d.updateSettings()
	u := d.updates.Load()
	if u == nil {
		return UpdatesStatus{Enabled: enabled, Server: server}
	}
	cur, _ := u.src.Installer.CurrentVersion()
	u.mu.Lock()
	defer u.mu.Unlock()
	st := UpdatesStatus{Available: true, Enabled: enabled, Server: server, Installed: cur, Checking: u.checking, LastCheck: u.check, Staged: u.check.Staged}
	st.UpdateReady = st.Staged != nil && newer(st.Staged.Version, cur)
	return st
}

// errCheckRunning: another check is downloading.
var errCheckRunning = fmt.Errorf("%w: an update check is already running", ErrInvalid)

// CheckUpdates asks the update server for its newest release now and, when
// it is newer than the installed one, downloads and verifies it. It runs
// whether or not update-check is on (that switch only stops the daily
// check).
func (d *Daemon) CheckUpdates(ctx context.Context) (UpdatesStatus, error) {
	u := d.updates.Load()
	if u == nil {
		return UpdatesStatus{}, fmt.Errorf("%w: online updates aren't available here", ErrInvalid)
	}
	u.mu.Lock()
	if u.checking {
		u.mu.Unlock()
		return d.Updates(), errCheckRunning
	}
	u.checking = true
	prev := u.check
	u.mu.Unlock()

	_, server := d.updateSettings()
	res, err := d.runUpdateCheck(ctx, u, server, prev)
	res.Time = d.Now().UTC()
	res.Server = server
	res.OK = err == nil
	if err != nil {
		res.Result = err.Error()
		d.log.Warn("update check failed", "server", server, "err", err)
	} else {
		d.log.Info("update check", "server", server, "result", res.Result)
	}
	u.mu.Lock()
	u.check = res
	u.checking = false
	if serr := u.save(); serr != nil {
		d.log.Warn("could not save the update check", "err", serr)
	}
	u.mu.Unlock()
	return d.Updates(), err
}

// runUpdateCheck does one check. The result carries the previous staged
// release and accepted publish time unless this check replaces them; on an
// error, whatever was staged stays staged.
func (d *Daemon) runUpdateCheck(ctx context.Context, u *updatesState, server string, prev UpdateCheck) (UpdateCheck, error) {
	res := UpdateCheck{Latest: prev.Latest, Published: prev.Published, Staged: prev.Staged}
	cur, err := u.src.Installer.CurrentVersion()
	if err != nil {
		return res, fmt.Errorf("installed version: %w", err)
	}
	keys, err := u.src.Installer.Keys()
	if err != nil {
		return res, err
	}
	client := u.src.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Minute}
	}
	base := strings.TrimRight(server, "/") + "/"
	data, err := updateGet(ctx, client, base+upgrade.IndexPath, upgrade.MaxIndexSize, d.version)
	if err != nil {
		return res, err
	}
	sig, err := updateGet(ctx, client, base+upgrade.IndexSigPath, 4<<10, d.version)
	if err != nil {
		return res, err
	}
	ix, signer, err := upgrade.VerifyIndex(data, sig, keys)
	if err != nil {
		return res, err
	}
	// A server switch starts the replay watermark again: another server
	// keeps its own publish times.
	if prev.Server == server && ix.Published.Before(prev.Published) {
		return res, fmt.Errorf("release index: published %s, older than the %s one already seen; refusing it", ix.Published.Format(time.RFC3339), prev.Published.Format(time.RFC3339))
	}
	rel := ix.Latest
	res.Latest = &rel
	res.Published = ix.Published
	if !newer(rel.Version, cur) {
		if res.Staged != nil && !newer(res.Staged.Version, cur) {
			os.Remove(u.bundlePath())
			res.Staged = nil
		}
		res.Result = fmt.Sprintf("up to date (%s; the server's latest is %s)", cur, rel.Version)
		return res, nil
	}
	if err := upgrade.CheckVersion(upgrade.Manifest{Version: rel.Version, MinFromVersion: rel.MinFromVersion}, cur, false); err != nil {
		return res, fmt.Errorf("SJB-OS %s is available but can't install here: %w", rel.Version, err)
	}
	if s := res.Staged; s != nil && s.Version == rel.Version && s.SHA256 == rel.SHA256 {
		if _, err := os.Stat(u.bundlePath()); err == nil {
			res.Result = fmt.Sprintf("SJB-OS %s is downloaded and ready to install", rel.Version)
			return res, nil
		}
	}
	if err := d.downloadUpdate(ctx, u, client, rel, keys); err != nil {
		return res, err
	}
	res.Staged = &StagedUpdate{Version: rel.Version, Size: rel.Size, SHA256: rel.SHA256, Notes: rel.Notes, Downloaded: d.Now().UTC()}
	res.Result = fmt.Sprintf("downloaded SJB-OS %s (signed by %s); ready to install", rel.Version, signer)
	return res, nil
}

// downloadUpdate fetches rel's bundle to a .part file, checks its size,
// SHA-256 and signature, then puts it in place of any staged bundle.
func (d *Daemon) downloadUpdate(ctx context.Context, u *updatesState, client *http.Client, rel upgrade.Release, keys []upgrade.PublicKey) error {
	dir := filepath.Dir(u.bundlePath())
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	part := u.bundlePath() + ".part"
	os.Remove(part)
	free := u.src.FreeBytes
	if free == nil {
		free = statfsFree
	}
	// The space a staged bundle holds is freed when this one replaces it.
	var reclaim uint64
	if fi, err := os.Stat(u.bundlePath()); err == nil {
		reclaim = uint64(fi.Size())
	}
	if avail, err := free(dir); err == nil && avail+reclaim < uint64(rel.Size)+updateDiskMargin {
		return fmt.Errorf("not enough disk space for SJB-OS %s: %d MB needed, %d MB free", rel.Version, (uint64(rel.Size)+updateDiskMargin)>>20, (avail+reclaim)>>20)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rel.URL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "SJB-OS/"+d.version)
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("download %s: %w", rel.Version, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download %s: %s", rel.Version, resp.Status)
	}
	f, err := os.OpenFile(part, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, rel.Size+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	fail := func(e error) error { os.Remove(part); return e }
	switch {
	case err != nil:
		return fail(fmt.Errorf("download %s: %w", rel.Version, err))
	case n != rel.Size:
		return fail(fmt.Errorf("download %s: got %d bytes, the index says %d", rel.Version, n, rel.Size))
	case hex.EncodeToString(h.Sum(nil)) != rel.SHA256:
		return fail(fmt.Errorf("download %s: SHA-256 doesn't match the release index", rel.Version))
	}
	b, err := upgrade.ReadFile(part, keys)
	if err != nil {
		return fail(fmt.Errorf("download %s: %w", rel.Version, err))
	}
	if b.Manifest.Version != rel.Version {
		return fail(fmt.Errorf("download %s: the bundle is SJB-OS %s", rel.Version, b.Manifest.Version))
	}
	if err := os.Rename(part, u.bundlePath()); err != nil {
		return fail(err)
	}
	return nil
}

func statfsFree(dir string) (uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, err
	}
	return st.Bavail * uint64(st.Bsize), nil
}

// updateGet fetches a small file, refusing anything over limit.
func updateGet(ctx context.Context, client *http.Client, url string, limit int64, version string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "SJB-OS/"+version)
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("update server: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("update server: %s: %s", url, resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("update server: %w", err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("update server: %s is larger than %d bytes", url, limit)
	}
	return data, nil
}

// InstallUpdate starts installing the staged release. It is refused while
// a commit awaits confirmation, during a check, or with nothing staged.
func (d *Daemon) InstallUpdate(c accounts.Caller) (UpdatesStatus, error) {
	u := d.updates.Load()
	if u == nil {
		return UpdatesStatus{}, fmt.Errorf("%w: online updates aren't available here", ErrInvalid)
	}
	d.mu.Lock()
	confirming := d.pending != nil
	d.mu.Unlock()
	if confirming {
		return d.Updates(), fmt.Errorf("%w: a commit is waiting for confirmation; confirm it (or let it roll back) first", ErrInvalid)
	}
	u.mu.Lock()
	staged, checking := u.check.Staged, u.checking
	u.mu.Unlock()
	if checking {
		return d.Updates(), errCheckRunning
	}
	if staged == nil {
		return d.Updates(), fmt.Errorf("%w: no update is downloaded; run an update check first", ErrInvalid)
	}
	cur, err := u.src.Installer.CurrentVersion()
	if err != nil {
		return d.Updates(), err
	}
	if !newer(staged.Version, cur) {
		return d.Updates(), fmt.Errorf("%w: SJB-OS %s is already installed", ErrInvalid, cur)
	}
	if st, err := u.src.Installer.Status(); err == nil && st.InProgress {
		return d.Updates(), fmt.Errorf("%w: an upgrade is already in progress", ErrInvalid)
	}
	// The file may have changed since it was checked: check it again (fwctl
	// verifies the signature once more before installing anything).
	if sum, err := fileSHA256(u.bundlePath()); err != nil || sum != staged.SHA256 {
		return d.Updates(), fmt.Errorf("%w: the downloaded bundle changed or is missing; run an update check again", ErrInvalid)
	}
	d.log.Warn("SJB-OS upgrade started from the online update", "by", c.Author(), "from", cur, "to", staged.Version)
	if u.src.Start == nil {
		return d.Updates(), errors.New("no installer")
	}
	if err := u.src.Start(u.bundlePath()); err != nil {
		return d.Updates(), err
	}
	return d.Updates(), nil
}

func fileSHA256(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// RunUpdateChecks checks the update server daily while update-check is on.
func (d *Daemon) RunUpdateChecks(ctx context.Context) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if !d.updateCheckDue() {
			continue
		}
		d.CheckUpdates(ctx) // logged inside
	}
}

// updateCheckDue: update-check is on, the last check was 23 hours ago or
// more, and no upgrade is under way.
func (d *Daemon) updateCheckDue() bool {
	u := d.updates.Load()
	if u == nil {
		return false
	}
	if enabled, _ := d.updateSettings(); !enabled {
		return false
	}
	if st, err := u.src.Installer.Status(); err == nil && st.InProgress {
		return false
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	return !u.checking && d.Now().Sub(u.check.Time) >= 23*time.Hour
}

// StartUpdateCheck runs a check in the background and waits up to wait for
// it: a download can take minutes, longer than a CLI or browser request
// should. A check still running reports Checking; its outcome shows in the
// status when it ends.
func (d *Daemon) StartUpdateCheck(c accounts.Caller, wait time.Duration) (UpdatesStatus, error) {
	if d.updates.Load() == nil {
		return UpdatesStatus{}, fmt.Errorf("%w: online updates aren't available here", ErrInvalid)
	}
	d.log.Info("update check requested", "by", c.Author())
	type result struct {
		st  UpdatesStatus
		err error
	}
	done := make(chan result, 1)
	go func() {
		st, err := d.CheckUpdates(context.Background())
		done <- result{st, err}
	}()
	select {
	case r := <-done:
		if errors.Is(r.err, errCheckRunning) {
			return r.st, nil // the running check's outcome will show
		}
		if r.err != nil && !errors.Is(r.err, ErrInvalid) {
			r.err = fmt.Errorf("%w: %v", ErrInvalid, r.err)
		}
		return r.st, r.err
	case <-time.After(wait):
		return d.Updates(), nil
	}
}

// updatesMetrics is the update state for monitoring (nil without online
// updates).
func (d *Daemon) updatesMetrics() *metrics.Updates {
	u := d.updates.Load()
	if u == nil {
		return nil
	}
	cur, _ := u.src.Installer.CurrentVersion()
	u.mu.Lock()
	defer u.mu.Unlock()
	m := &metrics.Updates{LastCheckOK: u.check.Time.IsZero() || u.check.OK}
	m.Available = u.check.Staged != nil && newer(u.check.Staged.Version, cur)
	if !u.check.Time.IsZero() {
		a := d.Now().Sub(u.check.Time).Seconds()
		m.CheckAgeSeconds = &a
	}
	return m
}
