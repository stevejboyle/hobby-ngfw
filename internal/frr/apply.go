package frr

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
)

// Runner applies FRR configuration and runs read-only vtysh commands.
type Runner interface {
	// Available reports whether FRR is installed.
	Available() bool
	// Check validates a config without applying it (vtysh -C).
	Check(conf string) error
	// Apply writes frr.conf and the daemons file and reloads FRR, or
	// restarts it when the set of daemons changed. It never blocks on
	// systemd (ngfwd starts before networking; FRR after it).
	Apply(r *Result) error
	// Show runs one vtysh show command.
	Show(cmd string) ([]byte, error)
}

// Noop is used where FRR isn't managed (development machines).
type Noop struct{}

func (Noop) Available() bool     { return false }
func (Noop) Check(string) error  { return nil }
func (Noop) Apply(*Result) error { return fmt.Errorf("FRR is not managed on this system") }
func (Noop) Show(cmd string) ([]byte, error) {
	return nil, fmt.Errorf("FRR is not managed on this system")
}

// Exec drives the installed FRR.
type Exec struct {
	Vtysh   string // default /usr/bin/vtysh
	Dir     string // default /etc/frr
	Systemd func(args ...string) error
}

func (e Exec) vtysh() string {
	if e.Vtysh == "" {
		return "/usr/bin/vtysh"
	}
	return e.Vtysh
}

func (e Exec) dir() string {
	if e.Dir == "" {
		return "/etc/frr"
	}
	return e.Dir
}

func (e Exec) systemctl(args ...string) error {
	if e.Systemd != nil {
		return e.Systemd(args...)
	}
	out, err := exec.Command("systemctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Available reports whether vtysh and /etc/frr/daemons exist.
func (e Exec) Available() bool {
	if _, err := os.Stat(e.vtysh()); err != nil {
		return false
	}
	_, err := os.Stat(filepath.Join(e.dir(), "daemons"))
	return err == nil
}

// Check runs vtysh -C on the config.
func (e Exec) Check(conf string) error {
	f, err := os.CreateTemp("", "sjb-frr-*.conf")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	f.WriteString(conf)
	f.Close()
	out, err := exec.Command(e.vtysh(), "-C", "-f", f.Name()).CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if i := strings.Index(msg, "\nConfiguration file["); i > 0 {
			msg = strings.TrimSpace(msg[:i])
		}
		return fmt.Errorf("%s", msg)
	}
	return nil
}

// Apply writes the files and asks systemd to reload or restart FRR.
func (e Exec) Apply(r *Result) error {
	dpath := filepath.Join(e.dir(), "daemons")
	cur, err := os.ReadFile(dpath)
	if err != nil {
		return err
	}
	daemons, changed := SetDaemons(string(cur), r.Daemons)
	if changed {
		if err := writeFRR(dpath, daemons); err != nil {
			return err
		}
	}
	if err := writeFRR(filepath.Join(e.dir(), "frr.conf"), r.Conf); err != nil {
		return err
	}
	if changed || e.systemctl("is-active", "--quiet", "frr") != nil {
		return e.systemctl("--no-block", "restart", "frr")
	}
	return e.systemctl("--no-block", "reload", "frr")
}

// Show runs vtysh -c CMD.
func (e Exec) Show(cmd string) ([]byte, error) {
	out, err := exec.Command(e.vtysh(), "-c", cmd).CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("vtysh: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

// writeFRR replaces a file under /etc/frr, readable by the frr group.
func writeFRR(path, data string) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".sjb-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(data); err != nil {
		tmp.Close()
		return err
	}
	tmp.Chmod(0o640)
	if g, err := user.LookupGroup("frr"); err == nil {
		if gid, err := strconv.Atoi(g.Gid); err == nil {
			tmp.Chown(0, gid)
		}
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
