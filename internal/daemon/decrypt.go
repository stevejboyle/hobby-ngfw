package daemon

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"time"

	"github.com/stevejboyle/hobby-ngfw/internal/compiler"
	"github.com/stevejboyle/hobby-ngfw/internal/config"
	"github.com/stevejboyle/hobby-ngfw/internal/decrypt"
)

// ObserveOnly makes decryption observe (log what it would decrypt, pass
// everything through), whatever system decryption says. 0.9.9-r04 shipped
// with it on; from 0.9.9-r05 decryption decrypts.
var ObserveOnly = false

// modeOf is tlsd's mode for a config.
func modeOf(cfg *config.Config) string {
	if ObserveOnly || cfg.System.DecryptionObserve() {
		return decrypt.ModeObserve
	}
	return decrypt.ModeDecrypt
}

// MinDecryptCPUs is the vCPU count below which a commit that decrypts warns.
const MinDecryptCPUs = 4

// decryptState is the daemon's TLS decryption bookkeeping.
type decryptState struct {
	run        decrypt.Runner
	caDir      string
	policyPath string
	policy     string // policy file content last written
	on         bool   // tlsd started by the last sync
	ready      bool   // decrypt_ready holds its element
	cpus       func() int
}

// SetDecrypt sets how tlsd runs and where its CA and policy live. Call
// before Start.
func (d *Daemon) SetDecrypt(r decrypt.Runner, caDir, policyPath string) {
	d.dec.run, d.dec.caDir, d.dec.policyPath = r, caDir, policyPath
}

func (d *Daemon) cpus() int {
	if d.dec.cpus != nil {
		return d.dec.cpus()
	}
	return runtime.NumCPU()
}

// policyFor is tlsd's policy for a config.
func policyFor(cfg *config.Config) decrypt.Policy {
	p := decrypt.Policy{Mode: modeOf(cfg), Builtin: cfg.System.BuiltinExclusionsOn(), Rules: []decrypt.PolicyRule{}, Exclusions: []decrypt.Exclusion{}}
	for _, r := range cfg.DecryptionRules {
		prof, _ := cfg.DecryptionProfile(r.ProfileOf())
		p.Rules = append(p.Rules, decrypt.PolicyRule{Name: r.Name, Profile: r.ProfileOf(), BadCertificate: prof.BadCertificate,
			Unsupported: prof.Unsupported, Pinned: prof.Pinned})
	}
	for _, e := range cfg.DecryptionExclusions {
		p.Exclusions = append(p.Exclusions, decrypt.Exclusion{Name: e.Name, Domains: e.Domains})
	}
	return p
}

// syncDecryptLocked writes tlsd's policy and starts, reloads or stops it
// for the running config. A ruleset load (loaded) empties decrypt_ready,
// so it is filled again here once tlsd answers. Callers hold d.mu.
func (d *Daemon) syncDecryptLocked(loaded bool) []string {
	if loaded {
		d.dec.ready = false
	}
	if d.running == nil || d.dec.run == nil {
		return nil
	}
	cfg := d.running
	if !cfg.DecryptionActive() {
		if d.dec.on || d.dec.run.Running() {
			if err := d.dec.run.Stop(); err != nil {
				d.log.Warn("stopping tlsd", "err", err)
			}
		}
		d.dec.on = false
		return nil
	}
	var warns []string
	if !d.dec.run.Available() {
		return []string{"decryption rules configured but tlsd isn't installed: traffic passes undecrypted"}
	}
	if n := d.cpus(); n < MinDecryptCPUs {
		warns = append(warns, fmt.Sprintf("TLS decryption on a VM with %d vCPU: give it %d (each decrypted byte is decrypted and encrypted again, and inspected)", n, MinDecryptCPUs))
	}
	if !d.DecryptionCA().Present {
		warns = append(warns, "no decryption CA yet: `request decryption ca generate` (or import one); until then connections pass through undecrypted")
	}
	switch {
	case ObserveOnly:
		warns = append(warns, "TLS decryption observes only in this release: it logs what it would decrypt (show log decryption) and passes everything through")
	case cfg.System.DecryptionObserve():
		warns = append(warns, "TLS decryption is set to observe: it logs what it would decrypt (show log decryption) and passes everything through")
	}
	pol := policyFor(cfg)
	data := fmt.Sprintf("%+v", pol)
	changed := data != d.dec.policy
	if changed {
		if err := decrypt.WritePolicy(d.dec.policyPath, pol); err != nil {
			return append(warns, fmt.Sprintf("decryption policy not written: %v; tlsd keeps its old one", err))
		}
		d.dec.policy = data
	}
	switch {
	case !d.tlsdUp():
		if err := d.dec.run.Start(); err != nil {
			return append(warns, fmt.Sprintf("tlsd not started: %v; traffic passes undecrypted", err))
		}
	case changed:
		// A running tlsd (also one an earlier ngfwd started) takes the
		// policy now; a starting one reads it when it starts.
		if err := d.dec.run.Reload(); err != nil {
			warns = append(warns, fmt.Sprintf("tlsd didn't take the new policy yet: %v", err))
		}
	}
	d.dec.on = true
	d.checkDecryptLocked()
	return warns
}

// tlsdUp: systemd runs tlsd, or it answers on its socket.
func (d *Daemon) tlsdUp() bool {
	if d.dec.run.Running() {
		return true
	}
	_, err := d.dec.run.Status()
	return err == nil
}

// checkDecryptLocked puts decrypt_ready in step with tlsd: filled while it
// answers (connections are handed to it), empty while it doesn't (they take
// the normal path: fail open). Callers hold d.mu.
func (d *Daemon) checkDecryptLocked() {
	active := d.running != nil && d.running.DecryptionActive() && d.dec.run != nil
	healthy, busy := false, false
	if active {
		s, err := d.dec.run.Status()
		healthy, busy = err == nil && !s.Busy, err == nil && s.Busy
	}
	set := compiler.Table + " " + compiler.DecryptReadySet
	switch {
	case healthy:
		// Idempotent; also refills the set if a ruleset load emptied it.
		if err := d.nft.Apply(fmt.Sprintf("add element %s { 0.0.0.0/0 }\n", set)); err != nil {
			d.log.Warn("could not hand connections to tlsd", "err", err)
			return
		}
		if !d.dec.ready {
			d.log.Info("tlsd is up: connections are handed to it")
		}
		d.dec.ready = true
	case d.dec.ready && busy:
		if err := d.nft.Apply(fmt.Sprintf("flush set %s\n", set)); err != nil {
			d.log.Warn("could not stop handing connections to tlsd", "err", err)
			return
		}
		d.log.Warn("tlsd is at its connection limit: new connections take the normal path, undecrypted, until it has room")
		d.dec.ready = false
	case d.dec.ready:
		if active {
			if err := d.nft.Apply(fmt.Sprintf("flush set %s\n", set)); err != nil {
				d.log.Warn("could not stop handing connections to tlsd", "err", err)
				return
			}
		}
		d.log.Warn("tlsd isn't answering: connections take the normal path, undecrypted")
		d.dec.ready = false
	}
}

// RunDecryptHealth checks tlsd every two seconds until ctx ends.
func (d *Daemon) RunDecryptHealth(ctx context.Context) {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		d.mu.Lock()
		d.checkDecryptLocked()
		d.mu.Unlock()
	}
}

// DecryptionStatus is what `show decryption` and the web UI show.
type DecryptionStatus struct {
	Enabled   bool             `json:"enabled"`   // system decryption on
	InUse     bool             `json:"in_use"`    // some rule decrypts
	Installed bool             `json:"installed"` // tlsd installed
	Running   bool             `json:"running"`
	Ready     bool             `json:"ready"` // connections are handed to tlsd
	Mode      string           `json:"mode"`
	CA        decrypt.CAInfo   `json:"ca"`
	Rules     []string         `json:"rules"`
	Counts    map[string]int64 `json:"counts"`
	Active    int64            `json:"active"`
	Learned   int              `json:"learned"`
	Busy      bool             `json:"busy"`
	MaxActive int64            `json:"max_active"`
	Builtin   bool             `json:"builtin_exclusions"`
	CPUs      int              `json:"cpus"`
	// State is what decryption does to traffic now: "off", "no-ca"
	// (passes through), "unavailable" (passes through), "observing" or
	// "decrypting".
	State  string `json:"state"`
	Detail string `json:"state_detail"`
}

// Decryption reports TLS decryption's state.
func (d *Daemon) Decryption() DecryptionStatus {
	d.mu.Lock()
	cfg, ready := d.running, d.dec.ready
	d.mu.Unlock()
	st := DecryptionStatus{Rules: []string{}, Counts: map[string]int64{}, Mode: decrypt.ModeObserve, CPUs: d.cpus(), Ready: ready}
	if cfg != nil {
		st.Mode = modeOf(cfg)
		st.Enabled, st.InUse, st.Builtin = cfg.System.DecryptionOn(), cfg.DecryptionActive(), cfg.System.BuiltinExclusionsOn()
		for _, r := range cfg.DecryptionRules {
			st.Rules = append(st.Rules, fmt.Sprintf("%s (%s)", r.Name, r.Action))
		}
	}
	st.CA = d.DecryptionCA()
	st.CA.PEM = ""
	if d.dec.run != nil {
		st.Installed, st.Running = d.dec.run.Available(), d.dec.run.Running()
		if s, err := d.dec.run.Status(); err == nil {
			st.Running = true // it answers, whatever systemd says
			st.Counts, st.Active, st.Learned, st.Busy, st.MaxActive = s.Counts, s.Active, s.Learned, s.Busy, s.MaxActive
			if s.Counts == nil {
				st.Counts = map[string]int64{}
			}
		}
	}
	st.State, st.Detail = decryptionState(st)
	return st
}

func decryptionState(st DecryptionStatus) (string, string) {
	const open = "connections pass through undecrypted"
	switch {
	case !st.Enabled:
		return "off", "TLS decryption is off (set system decryption off)"
	case !st.InUse:
		return "off", "no decryption rule decrypts"
	case !st.Installed:
		return "unavailable", "tlsd isn't installed: " + open
	case !st.CA.Present:
		return "no-ca", "no decryption CA: request decryption ca generate (or import one); until then " + open
	case st.Running && st.Busy:
		return "busy", fmt.Sprintf("tlsd holds its limit of %d connections: new ones pass through undecrypted until it has room", st.MaxActive)
	case !st.Running || !st.Ready:
		return "unavailable", "tlsd isn't running or not answering: " + open + " (fail-open)"
	case st.Mode == decrypt.ModeObserve:
		return "observing", "logging what the rules would decrypt; everything passes through (show log decryption)"
	}
	return "decrypting", fmt.Sprintf("decrypting what %d rule(s) cover, %d connection(s) now", len(st.Rules), st.Active)
}

// DecryptionCA describes the CA, with its certificate (PEM) to install on
// clients. Never the key.
func (d *Daemon) DecryptionCA() decrypt.CAInfo {
	if d.dec.caDir == "" {
		return decrypt.CAInfo{}
	}
	return decrypt.ReadCAInfo(d.dec.caDir)
}

var errNoDecryption = fmt.Errorf("%w: TLS decryption isn't available on this system", ErrInvalid)

func (d *Daemon) caOwner() decrypt.Owner {
	if d.dec.run == nil {
		return decrypt.NoOwner
	}
	return d.dec.run.Owner()
}

// GenerateDecryptionCA makes a new decryption CA, replacing any. Clients
// need the new certificate.
func (d *Daemon) GenerateDecryptionCA(author string) (decrypt.CAInfo, error) {
	if d.dec.caDir == "" {
		return decrypt.CAInfo{}, errNoDecryption
	}
	d.mu.Lock()
	host := "sjb-fw"
	if d.running != nil && d.running.System.Hostname != "" {
		host = d.running.System.Hostname
	}
	d.mu.Unlock()
	info, err := decrypt.GenerateCA(d.dec.caDir, host, d.Now(), d.caOwner())
	if err != nil {
		return decrypt.CAInfo{}, err
	}
	d.log.Info("decryption CA generated", "author", author, "fingerprint", info.Fingerprint)
	d.reloadTLSD()
	return info, nil
}

// ImportDecryptionCA installs the operator's CA certificate and key.
func (d *Daemon) ImportDecryptionCA(author string, cert, key []byte) (decrypt.CAInfo, error) {
	if d.dec.caDir == "" {
		return decrypt.CAInfo{}, errNoDecryption
	}
	info, err := decrypt.ImportCA(d.dec.caDir, cert, key, d.Now(), d.caOwner())
	if err != nil {
		return decrypt.CAInfo{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	d.log.Info("decryption CA imported", "author", author, "subject", info.Subject, "fingerprint", info.Fingerprint)
	d.reloadTLSD()
	return info, nil
}

// reloadTLSD has a running tlsd load the new CA. Asked directly rather
// than only when systemd says tlsd runs; a tlsd that isn't running loads
// the CA when it starts.
func (d *Daemon) reloadTLSD() {
	if d.dec.run == nil {
		return
	}
	if err := d.dec.run.Reload(); err != nil && d.tlsdUp() {
		d.log.Warn("tlsd didn't reload the CA", "err", err)
	}
}

// DecryptionLearned lists the servers passed through because their
// clients rejected the firewall's certificate.
func (d *Daemon) DecryptionLearned() ([]decrypt.LearnedEntry, error) {
	if d.dec.run == nil {
		return []decrypt.LearnedEntry{}, nil
	}
	l, err := d.dec.run.Learned()
	if err != nil {
		return nil, errNotRunning(err)
	}
	return l, nil
}

// ClearDecryptionLearned forgets them, so they are decrypted again.
func (d *Daemon) ClearDecryptionLearned(author string) (int, error) {
	if d.dec.run == nil {
		return 0, errNotRunning(errors.New("no tlsd"))
	}
	n, err := d.dec.run.ClearLearned()
	if err != nil {
		return 0, errNotRunning(err)
	}
	d.log.Info("decryption learned list cleared", "author", author, "entries", n)
	return n, nil
}

func errNotRunning(err error) error {
	return fmt.Errorf("%w: tlsd isn't running (decryption rules decrypt nothing, or it is starting): %v", ErrInvalid, err)
}
