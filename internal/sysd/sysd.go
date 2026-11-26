// Package sysd asks systemd about units, with a time limit: a hung
// systemctl must never hold up a status page, monitoring or a commit.
package sysd

import (
	"context"
	"os/exec"
	"time"
)

// Timeout bounds one systemctl query.
var Timeout = 5 * time.Second

// Active reports whether unit is active. A query that fails or times out
// counts as not active.
func Active(unit string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), Timeout)
	defer cancel()
	return exec.CommandContext(ctx, "systemctl", "is-active", "--quiet", unit).Run() == nil
}
