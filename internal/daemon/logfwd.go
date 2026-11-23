package daemon

import (
	"fmt"

	"github.com/stevejboyle/sjb-os/internal/accounts"
	"github.com/stevejboyle/sjb-os/internal/config"
	"github.com/stevejboyle/sjb-os/internal/logfwd"
)

// LogForwarder sends logs to the running config's log servers
// (logfwd.Forwarder; tests use a fake).
type LogForwarder interface {
	Configure(servers []config.LogServer) []string
	Status() logfwd.Status
	Test(name, by string) error
}

// SetLogForwarder sets the log forwarder (nil: logs aren't forwarded).
func (d *Daemon) SetLogForwarder(f LogForwarder) { d.logfwd = f }

// syncLogFwdLocked points the forwarder at the running config's servers.
// Like the other services that converge after a commit, problems are
// warnings: delivery is retried in the background.
func (d *Daemon) syncLogFwdLocked() []string {
	if d.logfwd == nil {
		if d.running != nil && len(d.running.LogServers) > 0 {
			return []string{"log servers configured but log forwarding isn't available here"}
		}
		return nil
	}
	var servers []config.LogServer
	if d.running != nil {
		servers = d.running.LogServers
	}
	return d.logfwd.Configure(servers)
}

// LogForwarding reports the forwarder and each log server.
func (d *Daemon) LogForwarding() logfwd.Status {
	if d.logfwd == nil {
		return logfwd.Status{Servers: []logfwd.ServerStatus{}}
	}
	return d.logfwd.Status()
}

// TestLogServer sends a test message to a running log server.
func (d *Daemon) TestLogServer(c accounts.Caller, name string) error {
	if d.logfwd == nil {
		return fmt.Errorf("%w: log forwarding isn't available here", ErrInvalid)
	}
	if err := d.logfwd.Test(name, c.Author()); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	d.log.Info("log forwarding test sent", "server", name, "by", c.Author())
	return nil
}
