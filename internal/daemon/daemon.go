// Package daemon is ngfwd's core: it owns the commit pipeline (candidate →
// validate → compile → check → atomic apply → store) and the tag registry.
// One mutex serialises every change to the kernel ruleset, so a commit and
// a tag registration can never interleave.
package daemon

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/stevejboyle/sjb-os/internal/accounts"
	"github.com/stevejboyle/sjb-os/internal/appid"
	"github.com/stevejboyle/sjb-os/internal/compiler"
	"github.com/stevejboyle/sjb-os/internal/config"
	"github.com/stevejboyle/sjb-os/internal/conntrack"
	"github.com/stevejboyle/sjb-os/internal/dhcp"
	"github.com/stevejboyle/sjb-os/internal/diff"
	"github.com/stevejboyle/sjb-os/internal/frr"
	"github.com/stevejboyle/sjb-os/internal/logs"
	"github.com/stevejboyle/sjb-os/internal/mgmtcert"
	"github.com/stevejboyle/sjb-os/internal/natips"
	"github.com/stevejboyle/sjb-os/internal/netdev"
	"github.com/stevejboyle/sjb-os/internal/nfqueue"
	"github.com/stevejboyle/sjb-os/internal/nft"
	"github.com/stevejboyle/sjb-os/internal/nicaddr"
	"github.com/stevejboyle/sjb-os/internal/routes"
	"github.com/stevejboyle/sjb-os/internal/stats"
	"github.com/stevejboyle/sjb-os/internal/store"
	"github.com/stevejboyle/sjb-os/internal/sysname"
	"github.com/stevejboyle/sjb-os/internal/tags"
)

// ErrInvalid marks errors caused by bad input (HTTP 400), as opposed to
// failures applying it.
var ErrInvalid = errors.New("invalid")

// Daemon is the commit and tag engine.
type Daemon struct {
	mu      sync.Mutex
	store   *store.Store
	tags    *tags.Registry
	nft     nft.Runner
	ct      conntrack.Flusher
	log     *slog.Logger
	Now     func() time.Time
	sets    map[string]string // tag -> nft set name in the running ruleset
	pending *pending          // commit awaiting confirmation

	appid       appid.Source
	dhcp        dhcp.Runner
	running     *config.Config // the running config (DHCP servers, log zones)
	dhcpApplied string         // Kea config last applied without error
	dhcpSubnets map[int]string // Kea subnet ID -> interface
	started     time.Time      // when Start ran
	frr         frr.Runner
	wantFRR     *frr.Result
	frrApplied  string // frr.conf + daemons last applied without error
	nics        nicaddr.Syncer
	host        sysname.Syncer
	wantHost    string            // system.hostname of the running config
	wantNICs    map[string]string // physical NIC -> configured address
	nicStates   []nicaddr.State
	netdev      netdev.Syncer
	wantNet     netdev.Want
	netStates   []netdev.State
	router      routes.Syncer
	wantRoutes  []routes.Route // static routes of the running config
	routeStates []routes.State // result of the last sync
	natIPs      natips.Syncer
	wantNATIPs  []natips.Addr  // published servers' public addresses
	natIPStates []natips.State // result of the last sync
	// ifaddrSets are the running ruleset's interface-address sets (hairpin
	// NAT); ifaddrFilled what each was last filled with.
	ifaddrSets   map[string]string
	ifaddrFilled map[string]string
	ips          ipsState
	dec          decryptState
	logfwd       LogForwarder
	stats        *stats.Store
	statsRoot    string
	// policy is the running config's ruleset without tag set elements: a
	// commit that changes it flushes conntrack (see flushIfPolicyChanged).
	policy string
	// Queues reports whether NFQUEUE queues have a listener (App
	// Identification 0-1, IPS 2-3). Tests replace it.
	Queues func(queues ...int) nfqueue.State
	// statsIfaces is the running config's zoned interfaces, for the
	// statistics sampler, which must not wait for d.mu: a commit can hold it
	// for minutes (rebuilding the IPS signatures), and a sampler stuck
	// behind it skips minutes.
	statsIfaces atomic.Pointer[[]string]
	// mgmtCert serves the web UI's and tag API's certificate; certNames is
	// what it should name, kept apart from d.mu for the same reason.
	mgmtCert  *mgmtcert.Manager
	certNames atomic.Pointer[certNames]
	// ipsCodes are the running config's IPS exception codes (ips.go).
	ipsCodes map[int]uint32
	// recovery, when set, says live enforcement may not match the recorded
	// running revision (a failed commit could not restore the previous
	// ruleset, or an auto-rollback failed). Status reports it; the next
	// successful commit or rollback clears it.
	recovery string

	accounts    *accounts.Store // nil: no access control (tests, development)
	logs        logs.Reader
	apiKeysFile string
	apiKeys     atomic.Pointer[[]APIKey] // what the tag API accepts
	version     string                   // SJB-OS version
	metrics     metricsState             // monitoring (metrics.go)
	snmp        snmpState                // the SNMP agent (snmp.go)
}

type pending struct {
	timer    *time.Timer
	prev     int // revision to restore if not confirmed (0 = no config)
	rev      int
	deadline time.Time
}

// CommitResult reports a successful commit.
type CommitResult struct {
	Revision  store.Revision `json:"revision"`
	Warnings  []string       `json:"warnings,omitempty"`
	ConfirmBy *time.Time     `json:"confirm_by,omitempty"`
}

// Status is a summary of the daemon's state.
type Status struct {
	Running   int        `json:"running_revision"`
	ConfirmBy *time.Time `json:"confirm_by,omitempty"`
	Pending   bool       `json:"uncommitted_changes"`
	// Recovery is set when live enforcement may not match the running
	// revision; it says what failed and what to do.
	Recovery string `json:"recovery,omitempty"`
}

// New builds a daemon. Call Start before serving.
func New(st *store.Store, reg *tags.Registry, runner nft.Runner, ct conntrack.Flusher, log *slog.Logger) *Daemon {
	return &Daemon{store: st, tags: reg, nft: runner, ct: ct, log: log, Now: time.Now, sets: map[string]string{},
		Queues: func(q ...int) nfqueue.State { return nfqueue.Read("", q...) }, router: routes.Noop{}, natIPs: natips.Noop{}, nics: nicaddr.Noop{}, host: sysname.Noop{}, netdev: netdev.Noop{}, frr: frr.Noop{}, dhcp: dhcp.Noop{}}
}

// SetRouter sets how static routes reach the kernel. Call before Start.
func (d *Daemon) SetRouter(r routes.Syncer) { d.router = r }

// wantedRoutes turns the config's routes into kernel routes.
func wantedRoutes(cfg *config.Config) []routes.Route {
	var out []routes.Route
	tables := cfg.VRFTables()
	for _, r := range cfg.Routes {
		vrf := r.VRFOf()
		rt := routes.Route{Name: r.Name, Dest: r.Destination, Gateway: r.Gateway, Dev: r.Interface, Table: tables[vrf], VRF: vrf}
		switch {
		case vrf == config.VRFMgmt:
			if rt.Dev == "" {
				rt.Dev = cfg.System.MgmtInterface
			}
		case vrf != config.VRFDefault:
			rt.VRFDev = config.VRFDevice(vrf)
		}
		if r.NextVRF != "" {
			rt.Dev = config.VRFDevice(r.NextVRF) // leak: hand the packet to the other VRF
		}
		out = append(out, rt)
	}
	return out
}

// wantedNICs returns the addresses the config sets on physical NICs other
// than the management interface (whose address stays with the deployment);
// a trunk gets nicaddr.TrunkOnly (no address).
func wantedNICs(cfg *config.Config) map[string]string {
	out := map[string]string{}
	for _, in := range cfg.Interfaces {
		if _, _, vlan := config.ParseVLAN(in.Name); vlan || in.Name == cfg.System.MgmtInterface {
			continue
		}
		switch {
		case cfg.IsTrunk(in.Name):
			out[in.Name] = nicaddr.TrunkOnly
		case in.Address != "":
			out[in.Name] = in.Address
		}
	}
	return out
}

// SetNICs sets how physical NIC addresses are applied. Call before Start.
func (d *Daemon) SetNICs(n nicaddr.Syncer) { d.nics = n }

// SetHostname sets how the configured hostname is applied to the system.
// Call before Start.
func (d *Daemon) SetHostname(h sysname.Syncer) { d.host = h }

// NICs reports the configured physical NIC addresses and whether each is applied.
func (d *Daemon) NICs() []nicaddr.State {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.nicStates)
}

// Neighbors reads the ARP table, when the netdev syncer can (not in
// development).
func (d *Daemon) Neighbors() ([]netdev.Neighbor, error) {
	d.mu.Lock()
	n := d.netdev
	d.mu.Unlock()
	r, ok := n.(interface {
		Neighbors() ([]netdev.Neighbor, error)
	})
	if !ok {
		return []netdev.Neighbor{}, nil
	}
	return r.Neighbors()
}

// wantedNet turns the config's VRFs and VLAN subinterfaces into devices.
func wantedNet(cfg *config.Config) netdev.Want {
	var w netdev.Want
	tables := cfg.VRFTables()
	for _, v := range cfg.VRFs {
		w.VRFs = append(w.VRFs, netdev.VRF{Dev: config.VRFDevice(v.Name), Table: tables[v.Name]})
	}
	for _, in := range cfg.Interfaces {
		parent, id, ok := config.ParseVLAN(in.Name)
		if !ok {
			continue
		}
		w.VLANs = append(w.VLANs, netdev.VLAN{Name: in.Name, Parent: parent, ID: id, VRF: config.VRFDevice(in.VRFOf()), Addr: in.Address})
	}
	return w
}

// syncNetLocked puts VRF devices and VLAN subinterfaces in place and returns
// a warning per device that isn't yet. Callers hold d.mu.
func (d *Daemon) syncNetLocked(mode nicaddr.Mode) []string {
	var warn []string
	if d.wantHost != "" {
		if changed, err := d.host.Sync(d.wantHost); err != nil {
			warn = append(warn, fmt.Sprintf("hostname not applied: %v", err))
		} else if changed {
			d.log.Info("hostname applied", "hostname", d.wantHost)
		}
	}
	// Physical NIC addresses first: VLANs sit on those NICs, and routes need
	// their networks.
	if ns, err := d.nics.Sync(d.wantNICs, mode); err != nil {
		warn = append(warn, fmt.Sprintf("interface addresses not synced: %v (ngfwd keeps trying)", err))
	} else {
		for _, s := range ns {
			if !s.Applied {
				warn = append(warn, fmt.Sprintf("interface %s address %s not applied yet: %s", s.Name, s.Address, s.Error))
			}
		}
		d.nicStates = ns
	}
	states, err := d.netdev.Sync(d.wantNet)
	if err != nil {
		return append(warn, fmt.Sprintf("VRFs and VLANs not synced: %v (ngfwd keeps trying)", err))
	}
	for _, s := range states {
		if !s.OK {
			warn = append(warn, fmt.Sprintf("%s %s not in place yet: %s; ngfwd keeps trying", s.Kind, s.Name, s.Error))
		}
	}
	d.netStates = states
	return warn
}

// NetDevices reports the wanted VRF devices and VLAN subinterfaces.
func (d *Daemon) NetDevices() []netdev.State {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.netStates)
}

// SetFRR sets how routing protocols are applied. Call before Start.
func (d *Daemon) SetFRR(r frr.Runner) { d.frr = r }

// FRR returns the runner, for read-only status (vtysh show commands).
func (d *Daemon) FRR() frr.Runner { return d.frr }

func frrKey(r *frr.Result) string {
	return fmt.Sprintf("%s|bgpd=%v|ospfd=%v", r.Conf, r.Daemons["bgpd"], r.Daemons["ospfd"])
}

// syncFRRLocked applies the routing config to FRR if it changed or failed
// last time, and returns a warning while routing can't run yet. Callers
// hold d.mu.
func (d *Daemon) syncFRRLocked() []string {
	if d.wantFRR == nil {
		return nil
	}
	if !d.frr.Available() {
		if d.wantFRR.Enabled() {
			return []string{"BGP/OSPF configured but FRR isn't installed yet (an upgrade installs it in the background); routing starts once it is"}
		}
		return nil
	}
	key := frrKey(d.wantFRR)
	if key == d.frrApplied {
		return nil
	}
	if err := d.frr.Apply(d.wantFRR); err != nil {
		return []string{fmt.Sprintf("routing config not applied to FRR yet: %v; ngfwd keeps trying", err)}
	}
	d.frrApplied = key
	return nil
}

// SetNetdev sets how VRFs and VLANs reach the kernel. Call before Start.
func (d *Daemon) SetNetdev(n netdev.Syncer) { d.netdev = n }

// SetNATIPs sets how published servers' public addresses reach their
// interfaces. Call before Start.
func (d *Daemon) SetNATIPs(n natips.Syncer) { d.natIPs = n }

// wantedNATIPs lists the public addresses the config's port forwards and
// static NAT entries publish, one per interface and address.
func wantedNATIPs(cfg *config.Config) []natips.Addr {
	var out []natips.Addr
	seen := map[string]bool{}
	for _, n := range cfg.NAT {
		if !n.Published() || n.PublicAddress == "" {
			continue
		}
		ip, ok := cfg.HostAddress(n.PublicAddress)
		if !ok || seen[n.Interface+" "+ip.String()] {
			continue
		}
		seen[n.Interface+" "+ip.String()] = true
		out = append(out, natips.Addr{Dev: n.Interface, IP: ip, Name: n.Name})
	}
	return out
}

// NATAddresses reports the published public addresses and whether each is
// on its interface.
func (d *Daemon) NATAddresses() []natips.State {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.natIPStates)
}

// syncIfAddrsLocked fills the ruleset's interface-address sets (hairpin
// NAT of port forwards on an interface's own address) with the live
// addresses, at commit and every 10 s, so a DHCP change follows within
// seconds. A ruleset load empties them (ifaddrFilled is reset then).
// Callers hold d.mu.
func (d *Daemon) syncIfAddrsLocked() {
	r, ok := d.natIPs.(natips.AddrReader)
	if !ok || len(d.ifaddrSets) == 0 {
		return
	}
	if d.ifaddrFilled == nil {
		d.ifaddrFilled = map[string]string{}
	}
	for iface, name := range d.ifaddrSets {
		ips, err := r.Addrs(iface)
		if err != nil {
			d.log.Warn("hairpin NAT: reading the interface's address", "interface", iface, "err", err)
			continue
		}
		var els []string
		for _, ip := range ips {
			if ip.Is4() {
				els = append(els, ip.String())
			}
		}
		slices.Sort(els)
		key := strings.Join(els, ",")
		if have, done := d.ifaddrFilled[iface]; done && have == key {
			continue
		}
		set := compiler.Table + " " + name
		script := fmt.Sprintf("flush set %s\n", set)
		if len(els) > 0 {
			script += fmt.Sprintf("add element %s { %s }\n", set, strings.Join(els, ", "))
		}
		if err := d.nft.Apply(script); err != nil {
			d.log.Warn("hairpin NAT: filling the interface's address set", "interface", iface, "err", err)
			continue
		}
		d.ifaddrFilled[iface] = key
	}
}

// syncNATIPsLocked puts wantNATIPs on their interfaces and returns a
// warning per address that isn't yet. Callers hold d.mu.
func (d *Daemon) syncNATIPsLocked() []string {
	states, err := d.natIPs.Sync(d.wantNATIPs)
	if err != nil {
		return []string{fmt.Sprintf("NAT public addresses not synced: %v (ngfwd keeps trying)", err)}
	}
	var warn []string
	for _, s := range states {
		if !s.Applied {
			warn = append(warn, fmt.Sprintf("nat %q: public address %s not on %s yet: %s; ngfwd keeps trying", s.Name, s.IP, s.Dev, s.Error))
		}
	}
	d.natIPStates = states
	return warn
}

// syncRoutesLocked installs wantRoutes (and the NAT public addresses, which
// sit on the same interfaces) and returns a warning per route or address
// that could not be installed yet. Callers hold d.mu.
func (d *Daemon) syncRoutesLocked() []string {
	warn := d.syncNATIPsLocked()
	d.syncIfAddrsLocked()
	states, err := d.router.Sync(d.wantRoutes)
	if err != nil {
		return append(warn, fmt.Sprintf("static routes not synced: %v (ngfwd keeps trying)", err))
	}
	for _, s := range states {
		if !s.Installed {
			hop := "via " + s.Gateway
			if s.Gateway == "" {
				hop = "to " + strings.TrimPrefix(s.Dev, "vrf-")
				if strings.HasPrefix(s.Dev, "vrf-") {
					hop = "to vrf " + strings.TrimPrefix(s.Dev, "vrf-")
				}
			}
			warn = append(warn, fmt.Sprintf("route %q (%s %s) not installed yet: %s; ngfwd keeps trying", s.Name, s.Dest, hop, s.Error))
		}
	}
	d.routeStates = states
	return warn
}

// ReconcileRoutes re-installs static routes that went missing (for example
// after an interface came up or networkd reconfigured it). ngfwd calls it
// periodically.
func (d *Daemon) ReconcileRoutes() {
	d.mu.Lock()
	defer d.mu.Unlock()
	before := installedCount(d.routeStates)
	d.syncNetLocked(nicaddr.Background)
	warn := d.syncRoutesLocked()
	if w := d.syncFRRLocked(); len(w) > 0 && d.frr.Available() {
		d.log.Warn(w[0])
	}
	d.syncDHCPLocked(false)
	d.syncIPSLocked()
	d.syncDecryptLocked(false)
	d.syncSNMPLocked(false)
	if after := installedCount(d.routeStates); after != before {
		d.log.Info("static routes", "installed", after, "configured", len(d.wantRoutes), "problems", warn)
	}
}

func installedCount(s []routes.State) int {
	n := 0
	for _, st := range s {
		if st.Installed {
			n++
		}
	}
	return n
}

// Routes reports the running config's static routes and whether each is
// in the kernel.
func (d *Daemon) Routes() []routes.State {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]routes.State, len(d.routeStates))
	copy(out, d.routeStates)
	return out
}

// Start applies the running revision, or a forward default-deny ruleset if
// nothing has been committed, together with all live tag registrations.
func (d *Daemon) Start() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.loadIPSCodes()
	n, data, err := d.store.Running()
	if err != nil {
		return err
	}
	cfg := &config.Config{}
	if n > 0 {
		if cfg, err = parse(data); err != nil {
			return fmt.Errorf("running revision %d: %w", n, err)
		}
	}
	res, err := compiler.CompileWith(cfg, d.snapshot(), d.compileOpts(cfg))
	if err != nil {
		return err
	}
	if err := d.nft.Apply(res.Ruleset); err != nil {
		return err
	}
	d.sets = res.Sets
	d.ifaddrSets, d.ifaddrFilled = res.IfAddrSets, nil
	d.policy = policyOf(cfg)
	d.wantNICs = wantedNICs(cfg)
	d.wantHost = strings.TrimSpace(cfg.System.Hostname)
	d.wantNet = wantedNet(cfg)
	d.wantRoutes = wantedRoutes(cfg)
	d.wantNATIPs = wantedNATIPs(cfg)
	d.wantFRR = frr.Compile(cfg)
	// DHCP: Kea starts at boot from the file the last run wrote; the
	// periodic pass applies any change once networking (and the firewall's
	// DNS servers) are up.
	d.setRunningLocked(cfg)
	d.started = d.Now()
	warns := append(d.syncNetLocked(nicaddr.Deferred), d.syncRoutesLocked()...)
	// IPS: rebuild the rules file once per start (a new SJB-OS version
	// may prepare signatures differently), then start or stop the engine.
	d.ips.built = "\x00"
	warns = append(warns, d.syncFRRLocked()...)
	warns = append(warns, d.syncIPSLocked()...)
	warns = append(warns, d.syncDecryptLocked(true)...)
	// Flows set up while ngfwd was down (possibly with no ruleset) must be
	// re-evaluated against the restored policy.
	if err := d.ct.FlushAll(); err != nil {
		d.log.Warn("could not flush conntrack; existing flows keep old verdicts", "err", err)
	}
	// Log forwarding after the flush: a connection to a log server made
	// before it would lose its conntrack entry, and the input chain drops
	// the server's packets of a connection it doesn't know.
	for _, w := range append(append(warns, d.syncLogFwdLocked()...), d.syncSNMPLocked(false)...) {
		d.log.Warn(w)
	}
	d.log.Info("ruleset applied at start", "revision", n, "warnings", len(res.Warnings))
	d.restorePendingLocked(n)
	d.log.Info("standing guard at the border", "revision", n)
	return nil
}

// restorePendingLocked picks up a commit that was waiting for confirmation
// when ngfwd stopped: the timer runs on for the time that was left, or the
// rollback happens now if the deadline has passed.
func (d *Daemon) restorePendingLocked(running int) {
	sp, err := d.store.LoadPending()
	if err != nil {
		d.log.Error("cannot read the pending confirmation; it is ignored", "err", err)
		return
	}
	if sp == nil {
		return
	}
	if sp.Revision != running {
		d.log.Warn("stale pending confirmation dropped", "pending", sp.Revision, "running", running)
		d.store.ClearPending()
		return
	}
	p := &pending{prev: sp.Previous, rev: sp.Revision, deadline: sp.Deadline}
	left := sp.Deadline.Sub(d.Now())
	if left <= 0 {
		d.log.Warn("commit was not confirmed before its deadline passed while ngfwd was stopped; rolling back", "revision", sp.Revision)
		d.pending = p
		d.rollbackUnconfirmedLocked(p, fmt.Sprintf("auto-rollback: revision %d not confirmed (deadline passed while ngfwd was stopped)", p.rev))
		return
	}
	p.timer = time.AfterFunc(left, func() { d.autoRollback(p) })
	d.pending = p
	d.log.Warn("commit still waiting for confirmation after restart", "revision", sp.Revision, "rolls_back_in", left.Round(time.Second))
}

// persistPendingLocked keeps the on-disk pending confirmation in step with
// d.pending. Callers hold d.mu.
func (d *Daemon) persistPendingLocked() {
	var err error
	if d.pending == nil {
		err = d.store.ClearPending()
	} else {
		err = d.store.SavePending(store.Pending{Revision: d.pending.rev, Previous: d.pending.prev, Deadline: d.pending.deadline})
	}
	if err != nil {
		d.log.Error("cannot record the pending confirmation; a restart would forget it", "err", err)
	}
}

func parse(data []byte) (*config.Config, error) {
	cfg, err := config.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	return cfg, nil
}

func (d *Daemon) snapshot() map[string][]compiler.TagEntry {
	now := d.Now()
	out := map[string][]compiler.TagEntry{}
	for _, e := range d.tags.List("", now) {
		out[e.Tag] = append(out[e.Tag], compiler.TagEntry{IP: e.IP, Remaining: e.Remaining(now)})
	}
	return out
}

// Candidate returns the candidate config.
func (d *Daemon) Candidate() ([]byte, error) { return d.store.Candidate() }

// Running returns the running revision number and config.
func (d *Daemon) Running() (int, []byte, error) { return d.store.Running() }

// Revisions lists commits, oldest first.
func (d *Daemon) Revisions() ([]store.Revision, error) { return d.store.List() }

// Revision returns the config committed as revision n.
func (d *Daemon) Revision(n int) ([]byte, error) { return d.store.Get(n) }

// RevertCandidate discards uncommitted changes.
func (d *Daemon) RevertCandidate() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, run, err := d.store.Running()
	if err != nil {
		return err
	}
	return d.store.SetCandidate(run)
}

// SetCandidate replaces the candidate after checking it parses and validates.
func (d *Daemon) SetCandidate(data []byte) error {
	if _, err := parse(data); err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.store.SetCandidate(data)
}

// Diff compares running (a) to candidate (b).
func (d *Daemon) Diff() (string, error) {
	_, run, err := d.store.Running()
	if err != nil {
		return "", err
	}
	cand, err := d.store.Candidate()
	if err != nil {
		return "", err
	}
	return diff.Lines(string(run), string(cand)), nil
}

// Preview compiles the candidate without applying it.
func (d *Daemon) Preview() (*compiler.Result, error) {
	cand, err := d.store.Candidate()
	if err != nil {
		return nil, err
	}
	cfg, err := parse(cand)
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return compiler.CompileWith(cfg, d.snapshot(), d.compileOpts(cfg))
}

// Status reports the running revision and any pending confirmation.
func (d *Daemon) Status() (Status, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	n, run, err := d.store.Running()
	if err != nil {
		return Status{}, err
	}
	cand, err := d.store.Candidate()
	if err != nil {
		return Status{}, err
	}
	s := Status{Running: n, Pending: string(cand) != string(run), Recovery: d.recovery}
	if d.pending != nil {
		t := d.pending.deadline
		s.ConfirmBy = &t
	}
	return s, nil
}

// Commit applies the candidate. With confirm > 0, the commit is rolled back
// automatically unless Confirm is called before the deadline.
func (d *Daemon) Commit(author, message string, confirm time.Duration) (*CommitResult, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	cand, err := d.store.Candidate()
	if err != nil {
		return nil, err
	}
	if len(strings.TrimSpace(string(cand))) == 0 {
		return nil, fmt.Errorf("%w: candidate config is empty", ErrInvalid)
	}
	res, err := d.commitLocked(cand, author, message, confirm)
	d.noteCommit(err)
	return res, err
}

// noteCommit records a commit's outcome for monitoring. A config refused
// as invalid changed nothing, so it isn't a failed commit.
func (d *Daemon) noteCommit(err error) {
	switch {
	case err == nil:
		d.recordCommit(true, "")
	case !errors.Is(err, ErrInvalid):
		d.recordCommit(false, err.Error())
	}
}

func (d *Daemon) commitLocked(data []byte, author, message string, confirm time.Duration) (*CommitResult, error) {
	cfg, err := parse(data)
	if err != nil {
		return nil, err
	}
	res, err := compiler.CompileWith(cfg, d.snapshot(), d.compileOpts(cfg))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	frrRes := frr.Compile(cfg)
	if d.frr.Available() {
		if err := d.frr.Check(frrRes.Conf); err != nil {
			return nil, fmt.Errorf("%w: routing config rejected by FRR, nothing applied: %v", ErrInvalid, err)
		}
	}
	if err := d.checkDHCP(cfg); err != nil {
		return nil, err
	}
	if err := d.checkSNMP(cfg); err != nil {
		return nil, err
	}
	if err := d.nft.Check(res.Ruleset); err != nil {
		return nil, fmt.Errorf("ruleset check failed, nothing applied: %w", err)
	}
	prev, _, err := d.store.Running()
	if err != nil {
		return nil, err
	}
	// A pending confirmation this commit supersedes: its rollback target
	// stays the last confirmed revision, and if this commit fails it stays
	// pending, on disk as in memory.
	var old *store.Pending
	if d.pending != nil {
		prev = d.pending.prev
		old = &store.Pending{Revision: d.pending.rev, Previous: d.pending.prev, Deadline: d.pending.deadline}
	}

	// 1. Record the revision (not yet running) and, for a confirmed commit,
	// its rollback target and deadline, before anything changes: a commit
	// reports success only once what would undo it is on disk.
	rev, err := d.store.SaveRevision(data, author, message, d.Now())
	if err != nil {
		return nil, fmt.Errorf("could not record the revision, nothing applied: %w", err)
	}
	var deadline time.Time
	if confirm > 0 {
		deadline = d.Now().Add(confirm)
		if err := d.store.SavePending(store.Pending{Revision: rev.N, Previous: prev, Deadline: deadline}); err != nil {
			d.store.DeleteRevision(rev.N)
			return nil, fmt.Errorf("could not record the confirmation deadline, nothing applied: %w", err)
		}
	}
	undo := func() {
		d.restorePendingRecordLocked(old)
		d.store.DeleteRevision(rev.N)
	}

	// 2. Apply. nft -f is atomic: on failure the previous ruleset stays.
	if err := d.nft.Apply(res.Ruleset); err != nil {
		undo()
		return nil, fmt.Errorf("apply failed, previous ruleset still active: %w", err)
	}

	// 3. Make it the running revision. If that can't be recorded, put the
	// previous ruleset back so enforcement matches what is recorded.
	if err := d.store.SetRunning(rev.N); err != nil {
		undo()
		if rerr := d.reapplyRunningLocked(); rerr != nil {
			d.recovery = fmt.Sprintf("revision %d was applied but could not be recorded (%v), and the previous ruleset could not be restored (%v): "+
				"enforcement may not match running revision %d. Commit again, or restart ngfwd to re-apply the recorded revision", rev.N, err, rerr, prev)
			d.log.Error("commit failed and the previous ruleset could not be restored", "revision", rev.N, "err", err, "restore_err", rerr)
			return nil, fmt.Errorf("applied but could not record revision %d (%v), and restoring the previous ruleset failed (%v): see show status", rev.N, err, rerr)
		}
		return nil, fmt.Errorf("could not record revision %d as running (%v); the previous ruleset was restored", rev.N, err)
	}
	var warnings []string
	if err := d.store.SetCandidate(data); err != nil {
		warnings = append(warnings, fmt.Sprintf("the candidate could not be updated to the committed config: %v", err))
	}

	// Committed. Policy (nftables) is now in force; routing, DHCP, the IPS
	// and interface changes converge below and report problems as warnings.
	d.recovery = ""
	if d.pending != nil {
		if d.pending.timer != nil {
			d.pending.timer.Stop()
		}
		d.pending = nil
	}
	if confirm > 0 {
		p := &pending{prev: prev, rev: rev.N, deadline: deadline}
		p.timer = time.AfterFunc(confirm, func() { d.autoRollback(p) })
		d.pending = p
	} else if err := d.store.ClearPending(); err != nil {
		warnings = append(warnings, fmt.Sprintf("could not clear the old confirmation record (it is ignored after a restart): %v", err))
	}
	warnings = append(warnings, d.flushIfPolicyChangedLocked(cfg)...)
	d.sets = res.Sets
	d.ifaddrSets, d.ifaddrFilled = res.IfAddrSets, nil
	d.wantNICs = wantedNICs(cfg)
	d.wantHost = strings.TrimSpace(cfg.System.Hostname)
	d.wantNet = wantedNet(cfg)
	d.wantRoutes = wantedRoutes(cfg)
	d.wantNATIPs = wantedNATIPs(cfg)
	d.wantFRR = frrRes
	d.setRunningLocked(cfg)
	routeWarnings := append(d.syncNetLocked(nicaddr.Commit), d.syncRoutesLocked()...)
	routeWarnings = append(routeWarnings, d.syncFRRLocked()...)
	routeWarnings = append(routeWarnings, d.syncDHCPLocked(true)...)
	routeWarnings = append(routeWarnings, d.syncIPSLocked()...)
	routeWarnings = append(routeWarnings, d.syncDecryptLocked(true)...)
	routeWarnings = append(routeWarnings, d.syncLogFwdLocked()...)
	routeWarnings = append(routeWarnings, d.syncSNMPLocked(true)...)

	out := &CommitResult{Revision: rev, Warnings: append(append(res.Warnings, warnings...), routeWarnings...)}
	if confirm > 0 {
		out.ConfirmBy = &deadline
	}
	d.log.Info("commit", "revision", rev.N, "author", author, "message", message, "confirm", confirm)
	return out, nil
}

// setRunningLocked makes cfg the running config.
func (d *Daemon) setRunningLocked(cfg *config.Config) {
	d.running = cfg
	d.metrics.running.Store(cfg)
	var names []string
	for _, i := range cfg.Interfaces {
		if i.Zone != "" {
			names = append(names, i.Name)
		}
	}
	d.statsIfaces.Store(&names)
	d.certNames.Store(&certNames{hostname: cfg.System.Hostname, mgmt: cfg.System.MgmtInterface})
	d.setIPSCodesLocked(cfg)
}

// restorePendingRecordLocked puts the on-disk confirmation record back to
// old (nil: none) after a failed commit.
func (d *Daemon) restorePendingRecordLocked(old *store.Pending) {
	var err error
	if old == nil {
		err = d.store.ClearPending()
	} else {
		err = d.store.SavePending(*old)
	}
	if err != nil {
		d.log.Error("could not restore the confirmation record after a failed commit", "err", err)
	}
}

// reapplyRunningLocked applies the ruleset of the config that is running
// (d.running), after a failed commit replaced it.
func (d *Daemon) reapplyRunningLocked() error {
	cfg := d.running
	if cfg == nil {
		cfg = &config.Config{}
	}
	res, err := compiler.CompileWith(cfg, d.snapshot(), d.compileOpts(cfg))
	if err != nil {
		return err
	}
	return d.nft.Apply(res.Ruleset)
}

// policyOf is a config's ruleset without tag set elements (they change
// with every tag registration and TTL, not with policy).
func policyOf(cfg *config.Config) string {
	res, err := compiler.Compile(cfg, nil)
	if err != nil {
		return ""
	}
	return res.Ruleset
}

// flushIfPolicyChangedLocked clears conntrack when the policy changed, so
// no existing connection keeps the old policy's verdict or the ct mark it
// wrote: the rule position the IPS and appidd's log go by, and the
// classified, final and denied bits. Every flow is re-evaluated against the
// new policy on its next packet (the kernel picks mid-stream TCP up again).
// Management traffic is unaffected: mgmt is never filtered. Flows the new
// policy denies stop; NATed flows may need to reconnect.
func (d *Daemon) flushIfPolicyChangedLocked(cfg *config.Config) []string {
	pol := policyOf(cfg)
	if pol == d.policy {
		return nil
	}
	d.policy = pol
	if err := d.ct.FlushAll(); err != nil {
		d.log.Warn("could not flush conntrack after a policy change", "err", err)
		return []string{fmt.Sprintf("existing connections could not be reset (%v): they keep the old policy's verdict until they close", err)}
	}
	return nil
}

// Confirm accepts a pending commit.
func (d *Daemon) Confirm() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.pending == nil {
		return fmt.Errorf("%w: no commit is waiting for confirmation", ErrInvalid)
	}
	d.pending.timer.Stop()
	d.log.Info("commit confirmed", "revision", d.pending.rev)
	d.pending = nil
	d.persistPendingLocked()
	return nil
}

func (d *Daemon) autoRollback(p *pending) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.pending != p {
		return // confirmed or superseded meanwhile
	}
	d.rollbackUnconfirmedLocked(p, fmt.Sprintf("auto-rollback: revision %d not confirmed", p.rev))
}

// rollbackUnconfirmedLocked restores what was running before the
// unconfirmed revision p.rev; d.pending is p. On success the confirmation is
// gone. On failure p stays pending (in memory and on disk, so a restart
// tries again), Status reports the failure, and it is retried in a minute.
func (d *Daemon) rollbackUnconfirmedLocked(p *pending, msg string) {
	var err error
	if p.prev == 0 {
		err = d.rollbackToNothingLocked()
	} else {
		var data []byte
		data, err = d.store.Get(p.prev)
		if err == nil {
			_, err = d.commitLocked(data, "system", fmt.Sprintf("%s; restored %d", msg, p.prev), 0)
		}
	}
	// An unconfirmed commit rolled back is a failed change either way.
	if err != nil {
		d.recordCommit(false, fmt.Sprintf("%s; the rollback failed: %v", msg, err))
	} else {
		d.recordCommit(false, msg)
	}
	if err != nil {
		d.recovery = fmt.Sprintf("%s, but the rollback failed (%v): revision %d is still in force; retrying every minute", msg, err, p.rev)
		d.log.Error("auto-rollback failed", "revision", p.rev, "err", err)
		d.pending = p
		p.timer = time.AfterFunc(time.Minute, func() { d.autoRollback(p) })
		return
	}
	if p.prev == 0 {
		d.log.Warn(msg+"; no earlier revision, forward default-deny applied", "revision", p.rev)
		return
	}
	d.log.Warn(msg, "restored", p.prev)
}

// rollbackToNothingLocked undoes the first commit: no config, forward
// default-deny.
func (d *Daemon) rollbackToNothingLocked() error {
	empty := &config.Config{}
	res, err := compiler.CompileWith(empty, d.snapshot(), d.compileOpts(empty))
	if err != nil {
		return err
	}
	if err := d.nft.Apply(res.Ruleset); err != nil {
		return err
	}
	if err := d.store.SetRunning(0); err != nil {
		if rerr := d.reapplyRunningLocked(); rerr != nil {
			return fmt.Errorf("%v; and re-applying the unconfirmed revision failed: %v", err, rerr)
		}
		return err
	}
	d.recovery = ""
	d.pending = nil
	if err := d.store.ClearPending(); err != nil {
		d.log.Warn("could not clear the confirmation record; it is ignored after a restart", "err", err)
	}
	for _, w := range d.flushIfPolicyChangedLocked(empty) {
		d.log.Warn(w)
	}
	d.sets = res.Sets
	d.ifaddrSets, d.ifaddrFilled = res.IfAddrSets, nil
	d.wantNICs = nil
	d.wantNet = netdev.Want{}
	d.wantRoutes = nil
	d.wantNATIPs = nil
	d.wantFRR = frr.Compile(empty)
	d.setRunningLocked(empty)
	d.syncNetLocked(nicaddr.Commit)
	d.syncRoutesLocked()
	d.syncFRRLocked()
	d.syncDHCPLocked(true)
	d.syncIPSLocked()
	d.syncDecryptLocked(true)
	d.syncLogFwdLocked()
	d.syncSNMPLocked(true)
	return nil
}

// Rollback re-commits revision n as a new revision.
func (d *Daemon) Rollback(n int, author string) (*CommitResult, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	data, err := d.store.Get(n)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	res, err := d.commitLocked(data, author, fmt.Sprintf("rollback to %d", n), 0)
	d.noteCommit(err)
	return res, err
}

// RegisterTags adds ip to each tag, and to the matching nft sets at once.
// ttl 0 means no expiry.
func (d *Daemon) RegisterTags(ip netip.Addr, tagList []string, ttl time.Duration) error {
	for _, t := range tagList {
		if err := tags.Validate(ip, t); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalid, err)
		}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.tags.Register(ip, tagList, ttl, d.Now()); err != nil {
		return err
	}
	var b strings.Builder
	for _, t := range tagList {
		set, ok := d.sets[t]
		if !ok {
			continue // no group uses this tag yet; applied when one does
		}
		el := ip.String()
		if ttl > 0 {
			el = fmt.Sprintf("%s timeout %ds", ip, int(ttl.Seconds()+0.999))
		}
		// add/delete/add in one transaction: refreshes the timeout whether
		// or not the element already exists.
		fmt.Fprintf(&b, "add element %s %s { %s }\n", compiler.Table, set, ip)
		fmt.Fprintf(&b, "delete element %s %s { %s }\n", compiler.Table, set, ip)
		fmt.Fprintf(&b, "add element %s %s { %s }\n", compiler.Table, set, el)
	}
	if b.Len() == 0 {
		return nil
	}
	if err := d.nft.Apply(b.String()); err != nil {
		return fmt.Errorf("registered but not applied: %w", err)
	}
	// Re-evaluate the host's existing sessions under its new tags.
	if err := d.ct.FlushIP(ip); err != nil {
		d.log.Warn("could not flush conntrack; existing sessions keep old verdicts", "ip", ip, "err", err)
	}
	return nil
}

// UnregisterTags removes ip from each tag and its nft set.
func (d *Daemon) UnregisterTags(ip netip.Addr, tagList []string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.tags.Unregister(ip, tagList, d.Now()); err != nil {
		return err
	}
	var b strings.Builder
	for _, t := range tagList {
		if set, ok := d.sets[t]; ok {
			fmt.Fprintf(&b, "add element %s %s { %s }\n", compiler.Table, set, ip)
			fmt.Fprintf(&b, "delete element %s %s { %s }\n", compiler.Table, set, ip)
		}
	}
	if b.Len() == 0 {
		return nil
	}
	if err := d.nft.Apply(b.String()); err != nil {
		return fmt.Errorf("unregistered but not applied: %w", err)
	}
	return nil
}

// ListTags returns live registrations, optionally for one tag.
func (d *Daemon) ListTags(tag string) []tags.Entry {
	return d.tags.List(tag, d.Now())
}

// RoutingStatus answers "bgp", "ospf" or "routes" (optionally for one VRF)
// from FRR. It doesn't take d.mu: vtysh reads FRR, not ngfwd state.
func (d *Daemon) RoutingStatus(what, vrf string) (any, error) {
	if !d.frr.Available() {
		return nil, fmt.Errorf("%w: FRR is not installed on this appliance yet", ErrInvalid)
	}
	switch what {
	case "bgp":
		return frr.BGPSummary(d.frr)
	case "ospf":
		return frr.OSPFNeighbors(d.frr)
	case "routes":
		return frr.Routes(d.frr, vrf)
	}
	return nil, fmt.Errorf("%w: routing status is bgp, ospf or routes", ErrInvalid)
}
