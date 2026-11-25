package daemon

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"sync"

	"github.com/stevejboyle/sjb-os/internal/accounts"
	"github.com/stevejboyle/sjb-os/internal/config"
	"github.com/stevejboyle/sjb-os/internal/metrics"
	"github.com/stevejboyle/sjb-os/internal/snmp"
)

// snmpState is the SNMP agent's part of the daemon.
type snmpState struct {
	run       snmp.Runner
	credsPath string // "" : SNMP not managed
	snapshot  string // where the monitoring snapshot is saved for the agent
	applied   string // snmpd.conf last applied without error
	lastErr   string // the last apply's error
	credsMu   sync.Mutex
}

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

// loadSNMPCreds reads the credentials (empty when SNMP isn't managed).
func (d *Daemon) loadSNMPCreds() (*snmp.Credentials, error) {
	if d.snmp.credsPath == "" {
		return &snmp.Credentials{}, nil
	}
	return snmp.Load(d.snmp.credsPath)
}

// checkSNMP refuses a config naming credentials that don't exist (or of
// the wrong kind): nothing is applied.
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

// syncSNMPLocked makes snmpd match the running config: written and
// (re)started when it changed, stopped and its file removed when SNMP is
// off. It runs at commit, at start and every 10 s (snmpd may be installed
// after the upgrade that brings it, and its package starts it with its own
// config).
func (d *Daemon) syncSNMPLocked() []string {
	if d.snmp.credsPath == "" {
		if d.running != nil && d.running.SNMP.On() {
			return []string{"snmp: the SNMP agent isn't available here"}
		}
		return nil
	}
	r := d.snmpRunner()
	want := ""
	if d.running != nil && d.running.SNMP.On() {
		d.snmp.credsMu.Lock()
		cs, err := d.loadSNMPCreds()
		if err == nil && cs.InternalPass == "" {
			if err = cs.EnsureInternal(); err == nil {
				err = snmp.Save(d.snmp.credsPath, cs)
			}
		}
		d.snmp.credsMu.Unlock()
		if err == nil {
			want, err = snmp.Compile(d.running, cs)
		}
		if err != nil {
			d.snmp.lastErr = err.Error()
			return []string{"snmp: " + err.Error()}
		}
	}
	if want == "" && d.snmp.snapshot != "" {
		// The agent's values go with it.
		os.Remove(d.snmp.snapshot)
	}
	if want == "" {
		// Off: stop it if it runs (the package starts it on install) and
		// keep its file away so it can't start at boot.
		_, statErr := os.Stat(snmp.ConfPath)
		if d.snmp.applied == "" && !r.Running() && errors.Is(statErr, os.ErrNotExist) {
			return nil
		}
		if !r.Available() && d.snmp.applied == "" {
			return nil
		}
	} else if want == d.snmp.applied {
		return nil
	}
	if err := r.Apply(want); err != nil {
		d.snmp.lastErr = err.Error()
		return []string{"snmp: " + err.Error()}
	}
	d.snmp.applied, d.snmp.lastErr = want, ""
	if want != "" {
		// Its first values now, not at the next 15 s tick.
		select {
		case d.kickChan() <- struct{}{}:
		default:
		}
	}
	return nil
}

// SNMPStatus is the agent's state and configuration, without secrets.
type SNMPStatus struct {
	Enabled     bool                      `json:"enabled"`
	Installed   bool                      `json:"installed"`
	Running     bool                      `json:"running"`
	Error       string                    `json:"error,omitempty"`
	Location    string                    `json:"location"`
	Contact     string                    `json:"contact"`
	V3Users     []string                  `json:"v3_users"`
	Communities []string                  `json:"v2c_communities"`
	Managers    []string                  `json:"managers"`
	Receivers   []config.SNMPTrapReceiver `json:"trap_receivers"`
	Credentials []snmp.Info               `json:"credentials"` // names and kinds only
	MIBBase     string                    `json:"mib_base"`
}

// SNMP reports the agent's state.
func (d *Daemon) SNMP() SNMPStatus {
	d.mu.Lock()
	cfg := d.running
	lastErr := d.snmp.lastErr
	d.mu.Unlock()
	r := d.snmpRunner()
	st := SNMPStatus{Installed: r.Available(), Running: r.Running(), Error: lastErr, MIBBase: snmp.Base,
		V3Users: []string{}, Communities: []string{}, Managers: []string{}, Receivers: []config.SNMPTrapReceiver{}, Credentials: []snmp.Info{}}
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
	}
	return st
}

// AddSNMPCredential adds a v3 user or v2c community (superusers), or with
// replace changes an existing one's secrets (the way to rotate them: a
// running config that names it uses the new ones at once).
func (d *Daemon) AddSNMPCredential(c accounts.Caller, cred snmp.Credential, replace bool) error {
	if _, err := d.Authorize(c, accounts.SuperuserOnly); err != nil {
		return err
	}
	if d.snmp.credsPath == "" {
		return fmt.Errorf("%w: the SNMP agent isn't available on this system", ErrInvalid)
	}
	cred.Auth, cred.Priv = snmp.NormalizeAuth(cred.Auth), snmp.NormalizePriv(cred.Priv)
	if err := cred.Check(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	d.mu.Lock()
	running := d.running
	d.mu.Unlock()
	d.snmp.credsMu.Lock()
	cs, err := d.loadSNMPCreds()
	if err == nil {
		old, exists := cs.Get(cred.Name)
		switch {
		case exists && !replace:
			err = fmt.Errorf("%w: an SNMP credential named %q exists (request snmp credential change to replace its secrets)", ErrInvalid, cred.Name)
		case !exists && replace:
			err = fmt.Errorf("%w: no SNMP credential named %q", accounts.ErrNotFound, cred.Name)
		case exists && old.Kind != cred.Kind && snmp.UsedBy(running, cred.Name) != "":
			err = fmt.Errorf("%w: %s uses %q as a %s credential: it can't become %s", ErrInvalid, snmp.UsedBy(running, cred.Name), cred.Name, old.Kind, cred.Kind)
		default:
			cs.List = slices.DeleteFunc(cs.List, func(x snmp.Credential) bool { return x.Name == cred.Name })
			cs.List = append(cs.List, cred)
			if err = cs.EnsureInternal(); err == nil {
				err = snmp.Save(d.snmp.credsPath, cs)
			}
		}
	}
	d.snmp.credsMu.Unlock()
	if err != nil {
		return err
	}
	d.log.Info("snmp credential saved", "name", cred.Name, "kind", cred.Kind, "replaced", replace, "by", c.Author())
	d.mu.Lock()
	d.syncSNMPLocked()
	d.mu.Unlock()
	return nil
}

// DeleteSNMPCredential removes a credential the running and candidate
// configs don't name (superusers).
func (d *Daemon) DeleteSNMPCredential(c accounts.Caller, name string) error {
	if _, err := d.Authorize(c, accounts.SuperuserOnly); err != nil {
		return err
	}
	d.mu.Lock()
	running := d.running
	d.mu.Unlock()
	if where := snmp.UsedBy(running, name); where != "" {
		return fmt.Errorf("%w: %s uses SNMP credential %q: change the config and commit first", ErrInvalid, where, name)
	}
	if data, err := d.store.Candidate(); err == nil {
		if cand, err := parse(data); err == nil {
			if where := snmp.UsedBy(cand, name); where != "" {
				return fmt.Errorf("%w: the candidate's %s uses SNMP credential %q: change it first", ErrInvalid, where, name)
			}
		}
	}
	d.snmp.credsMu.Lock()
	defer d.snmp.credsMu.Unlock()
	cs, err := d.loadSNMPCreds()
	if err != nil {
		return err
	}
	i := slices.IndexFunc(cs.List, func(x snmp.Credential) bool { return x.Name == name })
	if i < 0 {
		return fmt.Errorf("%w: no SNMP credential named %q", accounts.ErrNotFound, name)
	}
	cs.List = slices.Delete(cs.List, i, i+1)
	if err := snmp.Save(d.snmp.credsPath, cs); err != nil {
		return err
	}
	d.log.Info("snmp credential deleted", "name", name, "by", c.Author())
	return nil
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
