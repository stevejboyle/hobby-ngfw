package webui

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/stevejboyle/hobby-ngfw/internal/upgrade"
)

// SystemdUpgrader verifies uploads in ngfwd and runs the install itself as
// `fwctl upgrade apply` in a transient systemd unit, so it survives ngfwd
// being restarted halfway through.
type SystemdUpgrader struct {
	Installer *upgrade.Installer
	Fwctl     string // path to fwctl
}

const stagedName = "staged.upgrade"

func (u *SystemdUpgrader) staged() string {
	return filepath.Join(u.Installer.Root, upgrade.StateDir, "incoming", stagedName)
}

// Status reports the installed version and history.
func (u *SystemdUpgrader) Status() (upgrade.Status, error) { return u.Installer.Status() }

// Stage saves and verifies an uploaded bundle.
func (u *SystemdUpgrader) Stage(r io.Reader) (*upgrade.Manifest, error) {
	path := u.staged()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	os.Remove(path)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	_, err = io.Copy(f, r)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(path)
		return nil, fmt.Errorf("upload: %w", err)
	}
	keys, err := u.Installer.Keys()
	if err != nil {
		os.Remove(path)
		return nil, err
	}
	b, err := upgrade.ReadFile(path, keys)
	if err != nil {
		os.Remove(path)
		return nil, err
	}
	cur, err := u.Installer.CurrentVersion()
	if err == nil {
		err = upgrade.CheckVersion(b.Manifest, cur, false)
	}
	if err != nil {
		os.Remove(path)
		return nil, err
	}
	return &b.Manifest, nil
}

// Start runs `fwctl upgrade apply` on the staged bundle.
func (u *SystemdUpgrader) Start() error {
	if _, err := os.Stat(u.staged()); err != nil {
		return fmt.Errorf("no bundle uploaded")
	}
	return u.run("apply", u.staged())
}

// Rollback runs `fwctl upgrade rollback`.
func (u *SystemdUpgrader) Rollback() error {
	st, err := u.Installer.Status()
	if err != nil {
		return err
	}
	if st.RollbackTo == "" {
		return fmt.Errorf("nothing to roll back to")
	}
	return u.run("rollback")
}

func (u *SystemdUpgrader) run(args ...string) error {
	cmd := append([]string{"--unit=sjb-upgrade", "--collect", "--quiet", "--description=SJB-OS upgrade", u.Fwctl, "upgrade"}, args...)
	out, err := exec.Command("systemd-run", cmd...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("could not start the upgrade (%v): %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
