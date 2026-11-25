package snmp

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
)

// ConfPath is snmpd's configuration on the appliance.
const ConfPath = "/etc/snmp/snmpd.conf"

// Group is the account snmpd runs as (Debian's package); it reads
// snmpd.conf and the monitoring snapshot.
const Group = "Debian-snmp"

const unit = "snmpd.service"

// Runner applies snmpd.conf and runs or stops the agent.
type Runner interface {
	// Available reports whether snmpd is installed.
	Available() bool
	// Apply writes conf and (re)starts snmpd when it changed or isn't
	// running; conf "" stops snmpd and removes its file, so it can't
	// start at boot (the unit needs the file).
	Apply(conf string) error
	// Running reports whether snmpd is active.
	Running() bool
}

// Noop manages nothing (development machines, tests).
type Noop struct{}

func (Noop) Available() bool { return false }
func (Noop) Apply(conf string) error {
	if conf == "" {
		return nil
	}
	return errors.New("snmpd isn't managed on this system")
}
func (Noop) Running() bool { return false }

// Exec is the appliance's snmpd, driven through systemd.
type Exec struct {
	Binary string // default /usr/sbin/snmpd
	Conf   string // default ConfPath
}

func (e Exec) binary() string {
	if e.Binary != "" {
		return e.Binary
	}
	return "/usr/sbin/snmpd"
}

func (e Exec) conf() string {
	if e.Conf != "" {
		return e.Conf
	}
	return ConfPath
}

func systemctl(args ...string) error {
	out, err := exec.Command("systemctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Available reports whether snmpd is installed (upgrades install it in the
// background after the bundle, so it can appear a little later).
func (e Exec) Available() bool {
	_, err := os.Stat(e.binary())
	return err == nil
}

// Running reports whether snmpd is active.
func (e Exec) Running() bool { return systemctl("is-active", "--quiet", unit) == nil }

// Apply writes conf and starts or restarts snmpd, or stops it.
func (e Exec) Apply(conf string) error {
	path := e.conf()
	if conf == "" {
		if e.Running() {
			if err := systemctl("stop", unit); err != nil {
				return err
			}
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	if !e.Available() {
		return errors.New("snmpd isn't installed yet (an upgrade installs it in the background; commit again in a minute)")
	}
	old, _ := os.ReadFile(path)
	changed := !bytes.Equal(old, []byte(conf))
	if changed {
		if err := writeConf(path, []byte(conf)); err != nil {
			return err
		}
	}
	if changed || !e.Running() {
		// --no-block: ngfwd may be starting before the network; snmpd
		// starts when systemd gets to it.
		if err := systemctl("--no-block", "restart", unit); err != nil {
			return err
		}
	}
	return nil
}

// writeConf writes snmpd.conf: root, group Debian-snmp, 0640 (it holds the
// credentials' passphrases).
func writeConf(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".snmpd.conf-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o640); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if gid := GroupID(); gid >= 0 {
		os.Chown(tmp.Name(), 0, gid)
	}
	return os.Rename(tmp.Name(), path)
}

// GroupID is snmpd's group, -1 when it doesn't exist.
func GroupID() int {
	g, err := user.LookupGroup(Group)
	if err != nil {
		return -1
	}
	n, err := strconv.Atoi(g.Gid)
	if err != nil {
		return -1
	}
	return n
}
