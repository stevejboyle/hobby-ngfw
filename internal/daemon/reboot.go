package daemon

import (
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/stevejboyle/sjb-os/internal/accounts"
)

// rebootDelay lets the reply reach the caller before the appliance goes
// down.
var rebootDelay = 2 * time.Second

// SetReboot replaces how the appliance reboots (tests).
func (d *Daemon) SetReboot(f func() error) { d.reboot = f }

func systemReboot() error {
	out, err := exec.Command("systemctl", "reboot").CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl reboot: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Reboot restarts the appliance, for example onto a kernel an upgrade
// installed. Traffic stops until it is back (about a minute). The caller
// must be allowed to change upgrades.
func (d *Daemon) Reboot(c accounts.Caller) error {
	f := d.reboot
	if f == nil {
		f = systemReboot
	}
	d.log.Warn("appliance reboot requested", "by", c.Author())
	go func() {
		time.Sleep(rebootDelay)
		if err := f(); err != nil {
			d.log.Error("reboot failed", "err", err)
		}
	}()
	return nil
}
