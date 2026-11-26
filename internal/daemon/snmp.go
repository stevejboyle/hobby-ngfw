package daemon

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/stevejboyle/sjb-os/internal/accounts"
	"github.com/stevejboyle/sjb-os/internal/config"
	"github.com/stevejboyle/sjb-os/internal/metrics"
	"github.com/stevejboyle/sjb-os/internal/snmp"
)

// Lock order: d.mu, then d.snmp.credsMu, never the other way. Every change
// to the credentials (add, change, delete, restore) holds d.mu from its
// reference check to its write, as commits and candidate edits do, so a
// commit can't add a reference to a credential being deleted or changed
// in between. credsMu alone guards the file for readers that don't hold
// d.mu (show snmp).
//
// The agent's state, kept apart so no step is mistaken for another:
//
//	desired   the snmpd.conf the running config compiles to ("" = off)
//	written   the snmpd.conf last written to disk
//	accepted  when systemd last accepted a (re)start request
//	verified  when snmpd was last seen running after it
//
// A restart request is not proof snmpd runs: the agent is "starting" until
// Running says so, "failed" when it isn't running startGrace after a
// request (retried with backoff), and "gave-up" after snmpRetryMax tries,
// until the config or a credential changes, or the next commit.

// snmpState is the SNMP agent's part of the daemon.
type snmpState struct {
	run       snmp.Runner
	credsPath string // "" : SNMP not managed
	snapshot  string // where the monitoring snapshot is saved for the agent
	credsMu   sync.Mutex

	desired, written string
	phase            string // off, waiting-install, starting, running, failed, gave-up, error
	accepted         time.Time
	verified         time.Time
	attempts         int // restart requests for the current config
	nextTry          time.Time
	lastErr          string
}

// Agent phases (SNMPStatus.State).
const (
	snmpOff       = "off"
	snmpWaiting   = "waiting-install"
	snmpStarting  = "starting"
	snmpRunning   = "running"
	snmpFailed    = "failed"
	snmpGaveUp    = "gave-up"
	snmpConfigErr = "error"
)

// Recovery limits: how long a requested start may take before it counts
// as failed, the backoff between retries (doubling up to the cap), and how
// many requests per config before giving up.
var (
	snmpStartGrace = 20 * time.Second
	snmpBackoff    = 10 * time.Second
	snmpBackoffMax = 5 * time.Minute
	snmpRetryMax   = 6
)

// SetSNMP sets how the SNMP agent runs, where its credentials live and
// where the monitoring snapshot it reads is saved. Call before Start.
func (d *Daemon) SetSNMP(r snmp.Runner, credsPath, snapshotPath string) {
	d.snmp.run, d.snmp.credsPath, d.snmp.snapshot = r, credsPath, snapshotPath
	d.metrics.snmpRunning = r.Running
}

func (d *Daemon) snmpRunner() snmp.Runner {
	if d.snmp.run == nil {
		return snmp.Noop{}
	}
	return d.snmp.run
}

// loadSNMPCreds reads and validates the credentials (empty when SNMP isn't
// managed). A file that fails validation is an error, and nothing writes
// over it.
func (d *Daemon) loadSNMPCreds() (*snmp.Credentials, error) {
	if d.snmp.credsPath == "" {
		return &snmp.Credentials{}, nil
	}
	d.snmp.credsMu.Lock()
	defer d.snmp.credsMu.Unlock()
	return snmp.Load(d.snmp.credsPath)
}

// saveSNMPCredsLocked writes the credentials (d.mu held). Save validates
// and writes atomically, so on error the file is as it was.
func (d *Daemon) saveSNMPCredsLocked(cs *snmp.Credentials) error {
	d.snmp.credsMu.Lock()
	defer d.snmp.credsMu.Unlock()
	return snmp.Save(d.snmp.credsPath, cs)
}

// checkSNMP refuses a config naming credentials that don't exist (or of
// the wrong kind): nothing is applied. Commits call it with d.mu held.
func (d *Daemon) checkSNMP(cfg *config.Config) error {
	if !cfg.SNMP.On() {
		return nil
	}
	if d.snmp.credsPath == "" {
		return fmt.Errorf("%w: snmp: the SNMP agent isn't available on this system", ErrInvalid)
	}
	cs, err := d.loadSNMPCreds()
	if err != nil {
		return fmt.Errorf("snmp credentials: %w", err)
	}
	if err := snmp.CheckRefs(cfg, cs); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	return nil
}

// snmpFail records a problem and returns it as a warning.
func (d *Daemon) snmpFail(phase, msg string) []string {
	d.snmp.phase, d.snmp.lastErr = phase, msg
	return []string{"snmp: " + msg}
}

// syncSNMPLocked makes snmpd match the running config (d.mu held). It
// runs after commits (retry: a gave-up agent gets a fresh set of tries),
// when credentials change, at start and every 10 s. It never waits for
// snmpd to start; the next pass checks.
func (d *Daemon) syncSNMPLocked(retry bool) []string {
	if d.snmp.credsPath == "" {
		if d.running != nil && d.running.SNMP.On() {
			return []string{"snmp: the SNMP agent isn't available here"}
		}
		return nil
	}
	r := d.snmpRunner()
	now := d.Now()
	want := ""
	if d.running != nil && d.running.SNMP.On() {
		cs, err := d.loadSNMPCreds()
		if err == nil && cs.InternalPass == "" {
			if err = cs.EnsureInternal(); err == nil {
				err = d.saveSNMPCredsLocked(cs)
			}
		}
		if err == nil {
			want, err = snmp.Compile(d.running, cs)
		}
		if err != nil {
			// Leave snmpd as it is: no change on a config we can't build.
			return d.snmpFail(snmpConfigErr, err.Error())
		}
	}
	d.snmp.desired = want

	if want == "" {
		if d.snmp.snapshot != "" {
			os.Remove(d.snmp.snapshot) // the agent's values go with it
		}
		if d.snmp.written != "" || r.Running() || (r.Available() && r.ConfPresent()) {
			// Stop it if it runs (the package starts it on install) and
			// keep its file away so it can't start at boot.
			if err := r.Apply(""); err != nil {
				return d.snmpFail(snmpFailed, "stopping snmpd: "+err.Error())
			}
		}
		d.snmp.written, d.snmp.attempts, d.snmp.lastErr, d.snmp.phase = "", 0, "", snmpOff
		return nil
	}
	if !r.Available() {
		// An upgrade installs snmpd in the background: wait for it, no
		// retries counted.
		d.snmp.phase, d.snmp.lastErr = snmpWaiting, "snmpd isn't installed yet (an upgrade installs it in the background)"
		return []string{"snmp: " + d.snmp.lastErr}
	}
	if want != d.snmp.written || retry && d.snmp.phase == snmpGaveUp {
		// New config (or credentials), or a commit after giving up: write
		// it and ask for a restart, with a fresh set of tries.
		if err := r.Apply(want); err != nil {
			d.snmp.attempts++
			d.snmp.nextTry = now.Add(snmpRetryDelay(d.snmp.attempts))
			return d.snmpFail(snmpFailed, "applying snmpd.conf: "+err.Error())
		}
		d.snmp.written, d.snmp.accepted, d.snmp.attempts, d.snmp.lastErr, d.snmp.phase = want, now, 1, "", snmpStarting
		d.snmp.nextTry = now.Add(snmpRetryDelay(1))
		d.kickSnapshot() // values ready by the time snmpd comes up
		return nil
	}
	if r.Running() {
		if d.snmp.phase != snmpRunning {
			d.snmp.verified = now
			d.kickSnapshot()
		}
		d.snmp.phase, d.snmp.attempts, d.snmp.lastErr = snmpRunning, 0, ""
		return nil
	}
	// Not running with the right config written.
	switch {
	case d.snmp.phase == snmpStarting && now.Sub(d.snmp.accepted) < snmpStartGrace:
		return nil // give it time
	case d.snmp.phase == snmpGaveUp:
		return nil
	case d.snmp.attempts >= snmpRetryMax:
		return d.snmpFail(snmpGaveUp, fmt.Sprintf("snmpd didn't stay up after %d starts; it is left stopped until the config or a credential changes, or the next commit (journalctl -u snmpd as root says why)", d.snmp.attempts))
	case now.Before(d.snmp.nextTry):
		d.snmp.phase = snmpFailed
		if d.snmp.lastErr == "" {
			d.snmp.lastErr = "snmpd isn't running"
		}
		return nil
	}
	d.snmp.attempts++
	d.snmp.nextTry = now.Add(snmpRetryDelay(d.snmp.attempts))
	if err := r.Restart(); err != nil {
		return d.snmpFail(snmpFailed, "restarting snmpd: "+err.Error())
	}
	d.snmp.accepted, d.snmp.phase = now, snmpStarting
	d.snmp.lastErr = fmt.Sprintf("snmpd wasn't running: start %d of %d requested", d.snmp.attempts, snmpRetryMax)
	return nil
}

// kickSnapshot asks the snapshot saver for a snapshot now, not at the next
// 15 s tick.
func (d *Daemon) kickSnapshot() {
	select {
	case d.kickChan() <- struct{}{}:
	default:
	}
}

// snmpRetryDelay is the wait before restart request n+1: doubling from
// snmpBackoff, capped.
func snmpRetryDelay(n int) time.Duration {
	d := snmpBackoff
	for i := 1; i < n && d < snmpBackoffMax; i++ {
		d *= 2
	}
	return min(d, snmpBackoffMax)
}

// SNMPStatus is the agent's state and configuration, without secrets.
type SNMPStatus struct {
	Enabled   bool `json:"enabled"`
	Installed bool `json:"installed"`
	Running   bool `json:"running"`
	// State: off, waiting-install, starting, running, failed, gave-up or
	// error (the config or credentials can't be built into snmpd.conf).
	State string `json:"state"`
	// ConfigCurrent: the snmpd.conf on disk is what the running config and
	// credentials compile to.
	ConfigCurrent bool       `json:"config_current"`
	RequestedAt   *time.Time `json:"requested_at,omitempty"` // last (re)start request
	VerifiedAt    *time.Time `json:"verified_at,omitempty"`  // last seen running after one
	Attempts      int        `json:"attempts,omitempty"`
	NextRetry     *time.Time `json:"next_retry,omitempty"`
	Error         string     `json:"error,omitempty"`

	Location    string                    `json:"location"`
	Contact     string                    `json:"contact"`
	V3Users     []string                  `json:"v3_users"`
	Communities []string                  `json:"v2c_communities"`
	Managers    []string                  `json:"managers"`
	Receivers   []config.SNMPTrapReceiver `json:"trap_receivers"`
	Credentials []snmp.Info               `json:"credentials"` // names and kinds only
	CredsError  string                    `json:"credentials_error,omitempty"`
	MIBBase     string                    `json:"mib_base"`
}

func timePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	u := t.UTC()
	return &u
}

// SNMP reports the agent's state.
func (d *Daemon) SNMP() SNMPStatus {
	d.mu.Lock()
	cfg := d.running
	st := SNMPStatus{State: d.snmp.phase, ConfigCurrent: d.snmp.desired != "" && d.snmp.desired == d.snmp.written,
		RequestedAt: timePtr(d.snmp.accepted), VerifiedAt: timePtr(d.snmp.verified), Attempts: d.snmp.attempts, Error: d.snmp.lastErr}
	if d.snmp.phase == snmpFailed {
		st.NextRetry = timePtr(d.snmp.nextTry)
	}
	d.mu.Unlock()
	r := d.snmpRunner()
	st.Installed, st.Running, st.MIBBase = r.Available(), r.Running(), snmp.Base
	if st.State == "" {
		st.State = snmpOff
	}
	st.V3Users, st.Communities, st.Managers = []string{}, []string{}, []string{}
	st.Receivers, st.Credentials = []config.SNMPTrapReceiver{}, []snmp.Info{}
	if cfg != nil {
		s := cfg.SNMP
		st.Enabled, st.Location, st.Contact = s.On(), s.Location, s.Contact
		st.V3Users = append(st.V3Users, s.V3Users...)
		st.Communities = append(st.Communities, s.Communities...)
		st.Managers = append(st.Managers, s.Managers...)
		st.Receivers = append(st.Receivers, cfg.SNMPTrapReceivers...)
	}
	if cs, err := d.loadSNMPCreds(); err == nil {
		for _, c := range cs.List {
			st.Credentials = append(st.Credentials, c.Info())
		}
	} else {
		st.CredsError = err.Error()
	}
	return st
}

// candidateLocked parses the candidate (d.mu held; nil if there is none or
// it doesn't parse).
func (d *Daemon) candidateLocked() *config.Config {
	data, err := d.store.Candidate()
	if err != nil {
		return nil
	}
	cand, err := parse(data)
	if err != nil {
		return nil
	}
	return cand
}

// AddSNMPCredential adds a v3 user or v2c community (superusers), or with
// replace changes an existing one's secrets (the way to rotate them: a
// running config that names it uses the new ones at once). It returns the
// agent's warnings: a rotation whose restart fails is reported, not hidden.
func (d *Daemon) AddSNMPCredential(c accounts.Caller, cred snmp.Credential, replace bool) ([]string, error) {
	if _, err := d.Authorize(c, accounts.SuperuserOnly); err != nil {
		return nil, err
	}
	if d.snmp.credsPath == "" {
		return nil, fmt.Errorf("%w: the SNMP agent isn't available on this system", ErrInvalid)
	}
	cred.Auth, cred.Priv = snmp.NormalizeAuth(cred.Auth), snmp.NormalizePriv(cred.Priv)
	if err := cred.Check(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	cs, err := d.loadSNMPCreds()
	if err != nil {
		return nil, err
	}
	old, exists := cs.Get(cred.Name)
	switch {
	case exists && !replace:
		return nil, fmt.Errorf("%w: an SNMP credential named %q exists (request snmp credential change to replace its secrets)", ErrInvalid, cred.Name)
	case !exists && replace:
		return nil, fmt.Errorf("%w: no SNMP credential named %q", accounts.ErrNotFound, cred.Name)
	}
	if exists && old.Kind != cred.Kind {
		for _, cfg := range []*config.Config{d.running, d.candidateLocked()} {
			if where := snmp.UsedBy(cfg, cred.Name); where != "" {
				return nil, fmt.Errorf("%w: %s uses %q as a %s credential: it can't become %s", ErrInvalid, where, cred.Name, old.Kind, cred.Kind)
			}
		}
	}
	cs.List = slices.DeleteFunc(cs.List, func(x snmp.Credential) bool { return x.Name == cred.Name })
	cs.List = append(cs.List, cred)
	if err := cs.EnsureInternal(); err != nil {
		return nil, err
	}
	if err := d.saveSNMPCredsLocked(cs); err != nil {
		return nil, err
	}
	d.log.Info("snmp credential saved", "name", cred.Name, "kind", cred.Kind, "replaced", replace, "by", c.Author())
	return d.syncSNMPLocked(false), nil
}

// DeleteSNMPCredential removes a credential the running and candidate
// configs don't name (superusers).
func (d *Daemon) DeleteSNMPCredential(c accounts.Caller, name string) error {
	if _, err := d.Authorize(c, accounts.SuperuserOnly); err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if where := snmp.UsedBy(d.running, name); where != "" {
		return fmt.Errorf("%w: %s uses SNMP credential %q: change the config and commit first", ErrInvalid, where, name)
	}
	if where := snmp.UsedBy(d.candidateLocked(), name); where != "" {
		return fmt.Errorf("%w: the candidate's %s uses SNMP credential %q: change it first", ErrInvalid, where, name)
	}
	cs, err := d.loadSNMPCreds()
	if err != nil {
		return err
	}
	i := slices.IndexFunc(cs.List, func(x snmp.Credential) bool { return x.Name == name })
	if i < 0 {
		return fmt.Errorf("%w: no SNMP credential named %q", accounts.ErrNotFound, name)
	}
	cs.List = slices.Delete(cs.List, i, i+1)
	if err := d.saveSNMPCredsLocked(cs); err != nil {
		return err
	}
	d.log.Info("snmp credential deleted", "name", name, "by", c.Author())
	return nil
}

// restoreSNMPCredsLocked merges a backup's credentials into the store (d.mu
// held): the backup's add or replace those of the same name, none is
// removed, and the internal passphrase stays unless there is none. The
// result must still satisfy the running and candidate configs, and also
// the configs given (a backup's config about to become the candidate);
// otherwise nothing is written.
func (d *Daemon) restoreSNMPCredsLocked(from *snmp.Credentials, also ...*config.Config) (int, error) {
	cs, err := d.loadSNMPCreds()
	if err != nil {
		return 0, err
	}
	for _, c := range from.List {
		cs.List = slices.DeleteFunc(cs.List, func(x snmp.Credential) bool { return x.Name == c.Name })
		cs.List = append(cs.List, c)
	}
	if cs.InternalPass == "" {
		cs.InternalPass = from.InternalPass
	}
	if err := cs.EnsureInternal(); err != nil {
		return 0, err
	}
	for _, cfg := range append([]*config.Config{d.running, d.candidateLocked()}, also...) {
		if cfg != nil && cfg.SNMP.On() {
			if err := snmp.CheckRefs(cfg, cs); err != nil {
				return 0, fmt.Errorf("%w: the backup's SNMP credentials don't fit the config: %v", ErrInvalid, err)
			}
		}
	}
	if err := d.saveSNMPCredsLocked(cs); err != nil {
		return 0, err
	}
	return len(from.List), nil
}

// SaveMetricsSnapshot writes the monitoring snapshot for the SNMP helper
// while SNMP is on (removing it when off). ngfwd calls it every 15 s.
func (d *Daemon) SaveMetricsSnapshot(path string) error {
	cfg := d.metrics.running.Load()
	if cfg == nil || !cfg.SNMP.On() {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	return metrics.Save(path, d.Metrics(), 0o640, snmp.GroupID())
}
