package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/stevejboyle/sjb-os/internal/appid"
	"github.com/stevejboyle/sjb-os/internal/compiler"
	"github.com/stevejboyle/sjb-os/internal/config"
	"github.com/stevejboyle/sjb-os/internal/ips"
	"github.com/stevejboyle/sjb-os/internal/logs"
	"github.com/stevejboyle/sjb-os/internal/nft"
)

// ipsState is the daemon's IPS bookkeeping.
type ipsState struct {
	run      ips.Runner
	engine   *ips.Engine
	on       bool   // engine started by the last sync
	built    string // disabled-signature key the rules file was last built with
	updating sync.Mutex
	lastTry  time.Time
	// files are the exception-code mappings of the rules files Suricata
	// may still be running, oldest first: each is recorded before its file
	// is written, and the older ones are released only once Suricata
	// confirms it finished loading a newer file (confirmIPS). Code
	// assignment never gives a code a different signature while any of
	// them uses it.
	files      []ipsFile
	nextGen    uint64
	confirming bool  // a confirmIPS is running
	inactive   []int // signatures whose exceptions wait for a code
	// emit writes a threat line (default: ngfwd's stdout, the journal).
	emit func(string)
}

// MinIPSMemory is the RAM below which a commit with IPS rules warns.
const MinIPSMemory = 3584 << 20 // 3.5 GiB: what a "4 GB" VM reports

// SetIPS sets how the IPS runs and where its signatures live. Call before
// Start.
func (d *Daemon) SetIPS(r ips.Runner, e *ips.Engine) {
	d.ips.run, d.ips.engine = r, e
	// ngfwd reloads Suricata itself, over the command socket, and waits for
	// the answer (confirmIPS): a reload signal alone says nothing about
	// when the new rules, and their exception codes, are in use.
	if e != nil {
		e.Reload = nil
	}
}

// ipsFile is the exception-code mapping of a rules file. Gen orders them.
type ipsFile struct {
	Gen   uint64         `json:"gen"`
	Codes map[int]uint32 `json:"codes"`
}

// ipsFilesFile, in the state directory, keeps the mappings Suricata may
// still be running, so a restart of ngfwd doesn't forget them.
const ipsFilesFile = "ips-files.json"

// unknownSID owns, in the mapping assumed when no record exists (an
// upgrade from a version that kept none), every code the running config
// doesn't use: what Suricata runs then is unknown until it confirms a
// reload.
const unknownSID = -1

// ipsCodesFile, in the state directory, keeps the running config's IPS
// exception codes, so they survive restarts.
const ipsCodesFile = "ips-codes.json"

// compileOpts are the compile options for cfg: its IPS exception codes,
// kept stable against the running config's and never reusing a code a
// rules file Suricata may still run gives another signature
// (compiler.AssignIPSCodes). Callers hold d.mu.
func (d *Daemon) compileOpts(cfg *config.Config) compiler.Options {
	codes, none := compiler.AssignIPSCodes(d.ipsCodes, d.liveIPSCodesLocked(), cfg)
	return compiler.Options{IPSCodes: codes, IPSInactive: none}
}

// liveIPSCodesLocked are the mappings of the rules files Suricata may
// still be running. Callers hold d.mu.
func (d *Daemon) liveIPSCodesLocked() []map[int]uint32 {
	out := make([]map[int]uint32, len(d.ips.files))
	for i, f := range d.ips.files {
		out[i] = f.Codes
	}
	return out
}

// loadIPSCodes reads the codes the last running config used, and the
// mappings of the rules files Suricata may still run.
func (d *Daemon) loadIPSCodes() {
	if b, err := os.ReadFile(filepath.Join(d.store.Dir(), ipsCodesFile)); err == nil {
		var m map[string]uint32
		if json.Unmarshal(b, &m) == nil {
			d.ipsCodes = map[int]uint32{}
			for k, v := range m {
				if n, err := strconv.Atoi(k); err == nil {
					d.ipsCodes[n] = v
				}
			}
		}
	}
	var rec struct {
		Next  uint64    `json:"next"`
		Files []ipsFile `json:"files"`
	}
	b, err := os.ReadFile(filepath.Join(d.store.Dir(), ipsFilesFile))
	if err == nil && json.Unmarshal(b, &rec) == nil {
		d.ips.files, d.ips.nextGen = rec.Files, rec.Next
		return
	}
	// No record (a first start, or an upgrade from a version that kept
	// none). The rules file on disk was built with the running codes. If
	// Suricata is running, it may still run an earlier file whose codes are
	// unknown: reserve every other code until it confirms a reload.
	d.ips.files = []ipsFile{{Gen: 1, Codes: maps.Clone(d.ipsCodes)}}
	d.ips.nextGen = 2
	if d.ips.run != nil && d.ips.run.Running() {
		unknown := map[int]uint32{}
		taken := map[uint32]bool{}
		for _, c := range d.ipsCodes {
			taken[c] = true
		}
		i := 0
		for _, c := range compiler.IPSCodeValues() {
			if !taken[c] {
				unknown[unknownSID-i] = c // distinct keys, all unknown signatures
				i++
			}
		}
		d.ips.files = append([]ipsFile{{Gen: 0, Codes: unknown}}, d.ips.files...)
	}
	d.saveIPSFilesLocked()
}

// saveIPSFilesLocked writes the rules-file mappings. Callers hold d.mu.
func (d *Daemon) saveIPSFilesLocked() {
	b, _ := json.Marshal(struct {
		Next  uint64    `json:"next"`
		Files []ipsFile `json:"files"`
	}{d.ips.nextGen, d.ips.files})
	if err := os.WriteFile(filepath.Join(d.store.Dir(), ipsFilesFile), append(b, '\n'), 0o600); err != nil {
		d.log.Warn("could not save the IPS rules-file codes", "err", err)
	}
}

// recordRulesFileLocked notes, before a rules file with codes is written,
// that Suricata may run it from now on. Callers hold d.mu.
func (d *Daemon) recordRulesFileLocked(codes map[int]uint32) uint64 {
	g := d.ips.nextGen
	d.ips.nextGen++
	d.ips.files = append(d.ips.files, ipsFile{Gen: g, Codes: maps.Clone(codes)})
	d.saveIPSFilesLocked()
	return g
}

// buildIPSLocked rebuilds the rules file with the running codes, recorded
// first (see ipsState.files). Callers hold d.mu.
func (d *Daemon) buildIPSLocked() error {
	tu := d.tuningLocked()
	gen := d.recordRulesFileLocked(tu.Codes)
	before := d.ips.engine.Status().Built
	st, err := d.ips.engine.Build(tu)
	if err == nil && st.Built.Equal(before) {
		// The file came out the same as the one on disk: Suricata marks
		// alike under either record, so keep the newer one only.
		d.dropRecordBeforeLocked(gen)
	}
	return err
}

// dropRecordBeforeLocked drops the record just before gen: the file written
// last, which gen's file turned out identical to (never the record of
// unknown codes, which no file on disk stands for). Callers hold d.mu.
func (d *Daemon) dropRecordBeforeLocked(gen uint64) {
	i := slices.IndexFunc(d.ips.files, func(f ipsFile) bool { return f.Gen == gen })
	if i > 0 && !slices.ContainsFunc(slices.Collect(maps.Keys(d.ips.files[i-1].Codes)), func(sid int) bool { return sid < 0 }) {
		d.ips.files = slices.Delete(d.ips.files, i-1, i)
		d.saveIPSFilesLocked()
	}
}

// kickIPSConfirmLocked starts confirmIPS when older rules files are still
// recorded. syncIPSLocked calls it, so a failed attempt is retried on the
// periodic pass. Callers hold d.mu.
func (d *Daemon) kickIPSConfirmLocked() {
	if d.ips.confirming || len(d.ips.files) < 2 || d.ips.run == nil || !d.ips.run.Running() {
		return
	}
	d.ips.confirming = true
	go d.confirmIPS()
}

// confirmIPS has Suricata reload the rules file and wait until it has
// (ips.Runner.ReloadRules); only then are the files recorded before that
// request released: Suricata is running the newest one or a newer one. A
// failure (not answering yet, loading at start, a reload error) releases
// nothing; the next periodic pass tries again.
func (d *Daemon) confirmIPS() {
	for {
		d.mu.Lock()
		if len(d.ips.files) < 2 {
			d.ips.confirming = false
			d.mu.Unlock()
			return
		}
		top := d.ips.files[len(d.ips.files)-1].Gen
		d.mu.Unlock()
		err := d.ips.run.ReloadRules()
		d.mu.Lock()
		if err != nil {
			d.ips.confirming = false
			d.mu.Unlock()
			d.log.Info("IPS rules reload not confirmed yet; retrying", "err", err)
			return
		}
		n := len(d.ips.files)
		d.ips.files = slices.DeleteFunc(d.ips.files, func(f ipsFile) bool { return f.Gen < top })
		if len(d.ips.files) != n {
			d.saveIPSFilesLocked()
		}
		d.mu.Unlock()
	}
}

// setIPSCodesLocked records cfg's codes as the running ones. Callers hold d.mu.
func (d *Daemon) setIPSCodesLocked(cfg *config.Config) {
	codes, none := compiler.AssignIPSCodes(d.ipsCodes, d.liveIPSCodesLocked(), cfg)
	d.ips.inactive = none
	if maps.Equal(codes, d.ipsCodes) {
		return
	}
	d.ipsCodes = codes
	m := map[string]uint32{}
	for k, v := range codes {
		m[strconv.Itoa(k)] = v
	}
	b, _ := json.Marshal(m)
	if err := os.WriteFile(filepath.Join(d.store.Dir(), ipsCodesFile), append(b, '\n'), 0o600); err != nil {
		d.log.Warn("could not save the IPS exception codes", "err", err)
	}
}

// tuningLocked is what the running config changes in the rules file.
// Callers hold d.mu.
func (d *Daemon) tuningLocked() ips.Tuning {
	return ips.Tuning{Disabled: ips.Disabled(d.running.System.IPSDisabledSignatures), Codes: maps.Clone(d.ipsCodes)}
}

// disabledKey identifies a rules file's tuning: when it changes (a
// signature disabled, an exception's signature or code), the file is
// rebuilt. Callers hold d.mu.
func (d *Daemon) disabledKey(c *config.Config) string {
	s := slices.Clone(c.System.IPSDisabledSignatures)
	slices.Sort(s)
	var ex []string
	for sid, code := range d.ipsCodes {
		ex = append(ex, fmt.Sprintf("%d=%x", sid, code))
	}
	slices.Sort(ex)
	return strings.Join(s, ",") + "|" + strings.Join(ex, ",")
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
	if key := d.disabledKey(cfg); !d.ips.engine.Installed() || key != d.ips.built {
		if err := d.buildIPSLocked(); err != nil {
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
	d.kickIPSConfirmLocked()
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
	st, err := d.ips.engine.Fetch(ctx)
	if err != nil {
		return st, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.running == nil {
		return d.ips.engine.Status(), nil
	}
	if err := d.buildIPSLocked(); err != nil {
		return d.ips.engine.Status(), err
	}
	d.ips.built = d.disabledKey(d.running)
	d.kickIPSConfirmLocked()
	st = d.ips.engine.Status()
	d.log.Info("IPS signatures updated", "version", st.Version, "signatures", st.Signatures)
	return st, nil
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
	// Queue says whether the engine is bound to its queues (2-3), i.e.
	// actually receiving the traffic of rules with a profile, and how many
	// packets passed uninspected or were dropped because a queue was full.
	QueueBound   bool   `json:"queue_bound"`
	QueueDropped uint64 `json:"queue_dropped"`
	// State is what the IPS does to traffic now: "off", "unavailable"
	// (passes uninspected), "starting" (passes uninspected), "loading"
	// (inspecting with the signatures loaded so far) or "inspecting".
	State  string `json:"state"`
	Detail string `json:"state_detail"`
	// Exceptions are the running config's IPS exceptions.
	Exceptions []IPSExceptionStatus `json:"exceptions"`
}

// IPSExceptionStatus is an IPS exception with how many packets it let
// through (nil when the counters can't be read or it has no ruleset line,
// e.g. none of its rules is inspected).
type IPSExceptionStatus struct {
	config.IPSException
	Action string  `json:"action"` // alert or ignore, the default filled in
	Hits   *uint64 `json:"hits"`
	// Inactive: no exception code was free for its signature at the last
	// commit (codes earlier rules files use are held until Suricata has
	// loaded a newer one), so it doesn't apply yet; commit again later.
	Inactive bool `json:"inactive,omitempty"`
}

// IPS reports the IPS state.
func (d *Daemon) IPS() IPSStatus {
	d.mu.Lock()
	cfg := d.running
	reader, _ := d.nft.(counterReader)
	d.mu.Unlock()
	st := IPSStatus{Rules: []string{}, Exceptions: []IPSExceptionStatus{}}
	if cfg != nil {
		var counters map[string]nft.Counter
		if reader != nil && len(cfg.IPSExceptions) > 0 {
			if all, err := reader.Counters(compiler.Table, "ips_enforce"); err == nil {
				counters = all["ips_enforce"]
			}
		}
		for _, e := range cfg.IPSExceptions {
			es := IPSExceptionStatus{IPSException: e, Action: e.ActionOf(), Inactive: slices.Contains(d.ips.inactive, e.SIDNumber())}
			if c, ok := counters["ips-exception:"+e.Name]; ok {
				n := c.Packets
				es.Hits = &n
			}
			st.Exceptions = append(st.Exceptions, es)
		}
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
		q := d.Queues(2, 3)
		st.QueueBound, st.QueueDropped = q.Bound, q.Dropped
	}
	st.State, st.Detail = inspectionState(st)
	return st
}

// inspectionState says plainly what the IPS does to traffic. When it isn't
// inspecting, traffic of rules with a profile still flows (fail-open): the
// ruleset hands it to the engine with bypass.
func inspectionState(st IPSStatus) (string, string) {
	const open = "traffic of rules with an IPS profile passes uninspected"
	var state, detail string
	switch {
	case !st.Enabled:
		return "off", "the IPS is off (set system ips off): rules' IPS profiles are skipped"
	case !st.InUse:
		return "off", "no allow rule has an IPS profile"
	case !st.Installed:
		state, detail = "unavailable", "Suricata isn't installed yet: "+open
	case !st.Running:
		state, detail = "unavailable", "the IPS engine isn't running: "+open
	case !st.QueueBound || st.Loaded == 0:
		state, detail = "starting", "the engine is starting and not yet receiving traffic: "+open+" until it is"
	case st.Loading:
		state, detail = "loading", fmt.Sprintf("inspecting with the %d signatures loaded so far while the full set loads", st.Loaded)
	default:
		state, detail = "inspecting", fmt.Sprintf("inspecting the traffic of %d rule(s) with %d signatures", len(st.Rules), st.Loaded)
	}
	if st.QueueDropped > 0 {
		detail += fmt.Sprintf("; %d packets passed uninspected or were dropped because the engine's queue was full", st.QueueDropped)
	}
	return state, detail
}

// IPSAlert turns a Suricata alert into a threat log entry: the rule whose
// traffic it was (from the connection's ct mark), the action the rule's
// profile takes for the signature's severity, and the application.
// Alerts the profile ignores aren't logged.
func (d *Daemon) IPSAlert(a ips.Alert) {
	var mark uint32
	var decrypted bool
	if d.ips.run != nil {
		mark, decrypted, _ = d.ips.run.ConnMark(a.Proto, a.Src, a.SPort, a.Dst, a.DPort)
	}
	t := logs.Threat{Time: a.Time, Action: config.IPSAlert, Severity: a.Severity, SID: a.SID, Signature: a.Message,
		Category: a.Category, Proto: a.Proto, Src: a.Src, SPort: a.SPort, Dst: a.Dst, DPort: a.DPort, Decrypted: decrypted}
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
	if t.Action != config.IPSIgnore && t.Rule != "" && cfg != nil {
		if e, ok := d.ipsExceptionFor(cfg, a.SID, t.Rule, a.Client, a.Server); ok {
			t.Action, t.Exception = e.ActionOf(), e.Name
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

// ipsExceptionFor is the IPS exception that let a match through: the same
// test as the ruleset's (chain ips_enforce): the signature, the rule
// whose traffic it was, the connection's client and its server's inside
// address. The first matching exception in the config's order names it.
func (d *Daemon) ipsExceptionFor(cfg *config.Config, sid int, rule, client, server string) (config.IPSException, bool) {
	cl, _ := netip.ParseAddr(client)
	sv, _ := netip.ParseAddr(server)
	for _, e := range cfg.IPSExceptions {
		if e.SIDNumber() != sid {
			continue
		}
		if len(e.Rules) > 0 && !slices.Contains(e.Rules, rule) {
			continue
		}
		if len(e.Source) > 0 && !d.addrNamesCover(cfg, e.Source, cl) {
			continue
		}
		if len(e.Destination) > 0 && !d.addrNamesCover(cfg, e.Destination, sv) {
			continue
		}
		return e, true
	}
	return config.IPSException{}, false
}

// addrNamesCover reports whether ip is in any of the named addresses or
// groups (a tag group: registered with the tag now).
func (d *Daemon) addrNamesCover(cfg *config.Config, names []string, ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	inAddr := func(name string) bool {
		for _, a := range cfg.Addresses {
			if a.Name != name {
				continue
			}
			if p, err := netip.ParsePrefix(a.CIDR); err == nil {
				return p.Contains(ip)
			}
			if x, err := netip.ParseAddr(a.CIDR); err == nil {
				return x == ip
			}
		}
		return false
	}
	for _, n := range names {
		if inAddr(n) {
			return true
		}
		for _, g := range cfg.AddressGroups {
			if g.Name != n {
				continue
			}
			if g.Tag != "" {
				for _, e := range d.tags.List(g.Tag, d.Now()) {
					if e.IP == ip {
						return true
					}
				}
			}
			for _, m := range g.Static {
				if inAddr(m) {
					return true
				}
			}
		}
	}
	return false
}
