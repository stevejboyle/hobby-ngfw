package snmp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/stevejboyle/sjb-os/internal/sysd"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ConfPath is snmpd's configuration on the appliance.
const ConfPath = "/etc/snmp/snmpd.conf"

// Group is the account snmpd runs as (Debian's package); it reads
// snmpd.conf and the monitoring snapshot.
const Group = "Debian-snmp"

const unit = "snmpd.service"

// Runner applies snmpd.conf and runs or stops the agent. Apply and Restart
// only ask systemd to act (they don't wait for snmpd to start): the
// daemon checks Running afterwards before it calls the agent up.
type Runner interface {
	// Available reports whether snmpd is installed.
	Available() bool
	// Apply writes conf and asks for a restart; conf "" asks for a stop
	// and removes the file, so snmpd can't start at boot (the unit needs
	// it).
	Apply(conf string) error
	// Restart asks for snmpd to be started again with the file as it is,
	// clearing systemd's failed state first.
	Restart() error
	// Running reports whether snmpd is active.
	Running() bool
	// ConfPresent reports whether snmpd's config file exists (the package
	// installs one; ngfwd removes it while SNMP is off).
	ConfPresent() bool
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
func (Noop) Running() bool     { return false }
func (Noop) Restart() error    { return errors.New("snmpd isn't managed on this system") }
func (Noop) ConfPresent() bool { return false }

// ConfPresent reports whether snmpd.conf exists.
func (e Exec) ConfPresent() bool {
	_, err := os.Stat(e.conf())
	return err == nil
}

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
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "systemctl", args...).CombinedOutput()
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
func (e Exec) Running() bool { return sysd.Active(unit) }

// Apply writes conf and starts or restarts snmpd, or stops it.
func (e Exec) Apply(conf string) error {
	path := e.conf()
	if conf == "" {
		// --no-block: a final inform to an unreachable receiver can hold
		// up a stop (the unit allows 10 s); no commit waits for that.
		if e.Running() {
			if err := systemctl("--no-block", "stop", unit); err != nil {
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
		return e.Restart()
	}
	return nil
}

// Restart clears a failed state (systemd stops retrying a unit that failed
// too often) and asks for a restart without waiting: ngfwd may be starting
// before the network, and snmpd starts when systemd gets to it.
func (e Exec) Restart() error {
	systemctl("reset-failed", unit) // nothing to reset is not an error worth reporting
	return systemctl("--no-block", "restart", unit)
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
