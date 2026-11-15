package daemon

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/stevejboyle/hobby-ngfw/internal/appid"
	"github.com/stevejboyle/hobby-ngfw/internal/compiler"
	"github.com/stevejboyle/hobby-ngfw/internal/config"
	"github.com/stevejboyle/hobby-ngfw/internal/ips"
	"github.com/stevejboyle/hobby-ngfw/internal/logs"
)

// ipsState is the daemon's IPS bookkeeping.
type ipsState struct {
	run      ips.Runner
	engine   *ips.Engine
	on       bool   // engine started by the last sync
	built    string // disabled-signature key the rules file was last built with
	updating sync.Mutex
	lastTry  time.Time
	// emit writes a threat line (default: ngfwd's stdout, the journal).
	emit func(string)
}

// MinIPSMemory is the RAM below which a commit with IPS rules warns.
const MinIPSMemory = 3584 << 20 // 3.5 GiB: what a "4 GB" VM reports

// SetIPS sets how the IPS runs and where its signatures live. Call before
// Start.
func (d *Daemon) SetIPS(r ips.Runner, e *ips.Engine) {
	d.ips.run, d.ips.engine = r, e
	if e != nil && e.Reload == nil {
		e.Reload = r.Reload
	}
}

func disabledKey(c *config.Config) string {
	s := slices.Clone(c.System.IPSDisabledSignatures)
	slices.Sort(s)
	return strings.Join(s, ",")
}

// syncIPSLocked starts, stops or rebuilds the IPS for the running config.
// Callers hold d.mu.
func (d *Daemon) syncIPSLocked() []string {
	if d.running == nil || d.ips.run == nil || d.ips.engine == nil {
		return nil
	}
	cfg := d.running
	if !cfg.IPSActive() {
		if d.ips.on || d.ips.run.Running() {
			if err := d.ips.run.Stop(); err != nil {
				d.log.Warn("stopping the IPS", "err", err)
			}
		}
		d.ips.on = false
		return nil
	}
	var warns []string
	if !d.ips.run.Available() {
		return []string{"IPS rules configured but Suricata isn't installed yet (an upgrade installs it in the background); inspection starts once it is"}
	}
	if m := d.ips.run.MemTotal(); m > 0 && m < MinIPSMemory {
		warns = append(warns, fmt.Sprintf("IPS on a VM with %.1f GB of RAM: give it 4 GB (Suricata with the full signature set uses about 1 GB)", float64(m)/(1<<30)))
	}
	if key := disabledKey(cfg); !d.ips.engine.Installed() || key != d.ips.built {
		if _, err := d.ips.engine.Build(ips.Disabled(cfg.System.IPSDisabledSignatures)); err != nil {
			warns = append(warns, fmt.Sprintf("IPS rules not rebuilt: %v", err))
		} else {
			d.ips.built = key
		}
	}
	if st := d.ips.engine.Status(); st.Updated.IsZero() {
		warns = append(warns, "IPS signatures are being downloaded (ET Open); until then only SJB-OS's test signatures are active. `request ips update` retries")
		d.updateIPSAsync()
	}
	if !d.ips.on || !d.ips.run.Running() {
		if err := d.ips.run.Start(); err != nil {
			return append(warns, fmt.Sprintf("IPS engine not started: %v", err))
		}
		d.ips.on = true
	}
	return warns
}

// updateIPSAsync downloads signatures in the background, at most once a
// minute (the first download often meets DNS or the outside link still
// coming up). Callers hold d.mu.
func (d *Daemon) updateIPSAsync() {
	if d.Now().Sub(d.ips.lastTry) < time.Minute {
		return
	}
	d.ips.lastTry = d.Now()
	go func() {
		if _, err := d.UpdateIPS(context.Background()); err != nil {
			d.log.Warn("IPS signature update failed", "err", err)
		}
	}()
}

// UpdateIPS downloads the signatures now and reloads the engine.
func (d *Daemon) UpdateIPS(ctx context.Context) (ips.Status, error) {
	if d.ips.engine == nil {
		return ips.Status{}, fmt.Errorf("IPS not available on this system")
	}
	if !d.ips.updating.TryLock() {
		return d.ips.engine.Status(), fmt.Errorf("an IPS update is already running")
	}
	defer d.ips.updating.Unlock()
	d.mu.Lock()
	var disabled []string
	if d.running != nil {
		disabled = d.running.System.IPSDisabledSignatures
	}
	key := ""
	if d.running != nil {
		key = disabledKey(d.running)
	}
	d.mu.Unlock()
	st, err := d.ips.engine.Update(ctx, ips.Disabled(disabled))
	if err == nil {
		d.mu.Lock()
		d.ips.built = key
		d.mu.Unlock()
		d.log.Info("IPS signatures updated", "version", st.Version, "signatures", st.Signatures)
	}
	return st, err
}

// RunIPSUpdates refreshes the signatures daily while the IPS is in use,
// until ctx ends. ngfwd runs it in the background.
func (d *Daemon) RunIPSUpdates(ctx context.Context) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		d.mu.Lock()
		active := d.running != nil && d.running.IPSActive() && d.ips.engine != nil
		d.mu.Unlock()
		if !active {
			continue
		}
		if st := d.ips.engine.Status(); d.Now().Sub(st.Updated) < 23*time.Hour {
			continue
		}
		if _, err := d.UpdateIPS(ctx); err != nil {
			d.log.Warn("IPS signature update failed", "err", err)
		}
	}
}

// IPSStatus is what `show ips` and the web UI show.
type IPSStatus struct {
	Enabled   bool `json:"enabled"`   // system ips on
	InUse     bool `json:"in_use"`    // some allow rule names a profile
	Installed bool `json:"installed"` // Suricata installed
	Running   bool `json:"running"`
	// Loaded is how many signatures the running engine has active; less
	// than Engine.Signatures while it loads a new set.
	Loaded   int        `json:"loaded"`
	Loading  bool       `json:"loading"`
	MemTotal uint64     `json:"mem_total"`
	Rules    []string   `json:"rules"` // rules with a profile: "name (profile)"
	Engine   ips.Status `json:"signatures"`
}

// IPS reports the IPS state.
func (d *Daemon) IPS() IPSStatus {
	d.mu.Lock()
	cfg := d.running
	d.mu.Unlock()
	st := IPSStatus{Rules: []string{}}
	if cfg != nil {
		st.Enabled, st.InUse = cfg.System.IPSOn(), cfg.IPSRules()
		for _, r := range cfg.Rules {
			if r.Action == "allow" && r.IPSProfile != "" {
				st.Rules = append(st.Rules, fmt.Sprintf("%s (%s)", r.Name, r.IPSProfile))
			}
		}
	}
	if d.ips.run != nil {
		st.Installed, st.Running, st.MemTotal = d.ips.run.Available(), d.ips.run.Running(), d.ips.run.MemTotal()
	}
	if d.ips.engine != nil {
		st.Engine = d.ips.engine.Status()
	}
	if st.Running {
		n, ok := d.ips.run.LoadedRules()
		st.Loaded = n
		// Starting (no answer yet), or loading a new set: some rules may
		// fail to load, so "loading" means well short of the file's count.
		st.Loading = !ok || n < st.Engine.Signatures*9/10
	}
	return st
}

// IPSAlert turns a Suricata alert into a threat log entry: the rule whose
// traffic it was (from the connection's ct mark), the action the rule's
// profile takes for the signature's severity, and the application.
// Alerts the profile ignores aren't logged.
func (d *Daemon) IPSAlert(a ips.Alert) {
	var mark uint32
	if d.ips.run != nil {
		mark, _ = d.ips.run.ConnMark(a.Proto, a.Src, a.SPort, a.Dst, a.DPort)
	}
	t := logs.Threat{Time: a.Time, Action: config.IPSAlert, Severity: a.Severity, SID: a.SID, Signature: a.Message,
		Category: a.Category, Proto: a.Proto, Src: a.Src, SPort: a.SPort, Dst: a.Dst, DPort: a.DPort}
	if t.Time.IsZero() {
		t.Time = d.Now().UTC()
	}
	if id := int(mark & compiler.AppMask); id != 0 {
		if app, ok := appid.ByID(id); ok {
			t.App = app.Name
		}
	}
	d.mu.Lock()
	cfg := d.running
	d.mu.Unlock()
	if idx := int(mark>>compiler.RuleShift) - 1; cfg != nil && idx >= 0 && idx < len(cfg.Rules) {
		r := cfg.Rules[idx]
		t.Rule, t.Profile = r.Name, r.IPSProfile
		if p, ok := cfg.IPSProfile(r.IPSProfile); ok {
			t.Action = p.Action(a.Severity)
		}
	}
	if t.Action == config.IPSIgnore {
		return
	}
	emit := d.ips.emit
	if emit == nil {
		emit = func(s string) { fmt.Println(s) }
	}
	emit(t.Line())
	if d.stats != nil {
		d.stats.AddThreat(t.Severity, t.Action, t.SID, t.Signature, t.Src)
	}
}
