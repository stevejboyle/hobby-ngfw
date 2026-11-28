package upgrade

import (
	"fmt"
	"os/exec"
	"strings"
)

// StartFwctl runs `fwctl upgrade ARGS...` in a transient systemd unit
// (sjb-upgrade), so the install or rollback survives ngfwd being restarted
// halfway through. The web UI's uploads and the online update's installs both
// start it this way.
func StartFwctl(fwctl string, args ...string) error {
	cmd := append([]string{"--unit=sjb-upgrade", "--collect", "--quiet", "--description=SJB-OS upgrade", fwctl, "upgrade"}, args...)
	out, err := exec.Command("systemd-run", cmd...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("could not start the upgrade (%v): %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
