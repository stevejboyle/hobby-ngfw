package daemon

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/stevejboyle/sjb-os/internal/appid"
	"github.com/stevejboyle/sjb-os/internal/compiler"
	"github.com/stevejboyle/sjb-os/internal/config"
	"github.com/stevejboyle/sjb-os/internal/metrics"
	"github.com/stevejboyle/sjb-os/internal/nft"
	"github.com/stevejboyle/sjb-os/internal/sysd"
)

// Monitoring collection (Prometheus and SNMP share it):
//
//   - One collection at a time. Callers within MetricsMaxAge of the last
//     one get it as it is; others start one (or join the one under way)
//     and wait at most MetricsWait, then take the newest snapshot there is.
//     However many scrapes arrive, there is one collector goroutine, plus
//     at most one reading the parts behind d.mu.
//   - The parts behind d.mu (config, IPS, decryption, NAT) are read by a
//     goroutine the collection waits on for at most slowWait: a commit can
//     hold d.mu for minutes, and monitoring must keep answering. When it
//     doesn't finish in time, the last values are used and marked stale.
//   - Each section carries its own state (current, stale, never, failed)
//     and read time, so old values are never presented as fresh, and
//     values never read are absent rather than zero.
//   - Every subprocess on the way (nft, systemctl) has a time limit.

// MetricsMaxAge is how old a snapshot may be and still be served without a
// new collection: Prometheus typically scrapes every 15-60 s and SNMP's
// snapshot is saved every 15 s, so 5 s keeps them current while bounding
// the work however many clients poll.
var MetricsMaxAge = 5 * time.Second

// MetricsWait is how long a caller waits for a collection before taking
// the newest snapshot there is.
var MetricsWait = 4 * time.Second

// slowWait is how long a collection waits for the parts behind d.mu.
var slowWait = 3 * time.Second

// metricsState is what monitoring needs beyond the daemon's other state.
// None of it waits for d.mu.
type metricsState struct {
	running atomic.Pointer[config.Config] // the running config
	commit  atomic.Pointer[commitRecord]  // the last commit's outcome

	// OS package and reboot state: read through osStatus (it runs dpkg-deb
	// over the bundled packages), at most once per osStatusTTL.
	osMu     sync.Mutex
	osStatus func() *metrics.OS
	osAt     time.Time
	osLast   *metrics.OS

	kickOnce sync.Once
	matchMu  sync.Mutex
	matches  map[string]map[string]uint64 // severity -> action -> IPS matches

	// The parts behind d.mu: the latest read (with its read time), and
	// whether a read is under way.
	slow     atomic.Pointer[slowMetrics]
	slowBusy atomic.Bool

	// The collector: the latest snapshot, and the collection under way.
	collectMu sync.Mutex
	latest    *metrics.Snapshot
	inflight  chan struct{} // closed when the collection under way ends
	last      map[string]sectionMemo
	collects  atomic.Int64 // collections run (tests)
	// epoch changes with every commit; a snapshot from an older epoch is
	// never served as recent. latestEpoch is the one latest was taken in.
	epoch       atomic.Int64
	latestEpoch int64

	// serviceActive reports whether a systemd unit is active (tests
	// replace it).
	serviceActive func(unit string) bool
	// snmpRunning reports whether the SNMP agent runs (nil: not managed).
	snmpRunning func() bool
	// kick asks the snapshot saver for a snapshot now (SNMP just turned
	// on: the agent shouldn't wait 15 s for its first values).
	kick chan struct{}
}

// sectionMemo is a section's last good values and when they were read.
type sectionMemo struct {
	at  time.Time
	err string
}

// SnapshotKick is signalled when a snapshot should be saved at once.
func (d *Daemon) SnapshotKick() <-chan struct{} { return d.kickChan() }

func (d *Daemon) kickChan() chan struct{} {
	d.metrics.kickOnce.Do(func() { d.metrics.kick = make(chan struct{}, 1) })
	return d.metrics.kick
}

type commitRecord struct {
	ok   bool
	at   time.Time
	note string
}

// slowMetrics are the parts read through methods that take d.mu.
type slowMetrics struct {
	at     time.Time // when this read finished
	ips    IPSStatus
	nat    []NATEntry
	natErr error
	dec    DecryptionStatus
	geo    *metrics.GeoIP
	status Status
	stErr  error
}

// recordCommit notes a commit's outcome for monitoring, and makes the next
// snapshot a new collection.
func (d *Daemon) recordCommit(ok bool, note string) {
	d.metrics.commit.Store(&commitRecord{ok: ok, at: d.Now(), note: note})
	d.metrics.epoch.Add(1)
}

// countIPSMatch counts a logged IPS match.
func (d *Daemon) countIPSMatch(severity, action string) {
	d.metrics.matchMu.Lock()
	defer d.metrics.matchMu.Unlock()
	if d.metrics.matches == nil {
		d.metrics.matches = map[string]map[string]uint64{}
	}
	if d.metrics.matches[severity] == nil {
		d.metrics.matches[severity] = map[string]uint64{}
	}
	d.metrics.matches[severity][action]++
}

func (d *Daemon) ipsMatches() map[string]map[string]uint64 {
	d.metrics.matchMu.Lock()
	defer d.metrics.matchMu.Unlock()
	out := map[string]map[string]uint64{}
	for s, m := range d.metrics.matches {
		out[s] = map[string]uint64{}
		for a, n := range m {
			out[s][a] = n
		}
	}
	return out
}

// SetSNMPRunning tells the snapshot how to see whether the SNMP agent runs.
func (d *Daemon) SetSNMPRunning(f func() bool) { d.metrics.snmpRunning = f }

// slowParts starts a read of the parts behind d.mu unless one is under way,
// waits for it at most slowWait, and returns the newest read there is (nil
// before the first finishes).
func (d *Daemon) slowParts() *slowMetrics {
	if d.metrics.slowBusy.CompareAndSwap(false, true) {
		done := make(chan struct{})
		go func() {
			defer close(done)
			defer d.metrics.slowBusy.Store(false)
			var s slowMetrics
			s.ips = d.IPS()
			s.nat, s.natErr = d.natStatus()
			s.dec = d.Decryption()
			d.mu.Lock()
			if age, ok, inUse, have := d.geoMetricsLocked(); have {
				s.geo = &metrics.GeoIP{AgeSeconds: age, LastUpdateOK: ok, CountriesInUse: inUse}
			}
			d.mu.Unlock()
			s.status, s.stErr = d.Status()
			s.at = d.Now()
			d.metrics.slow.Store(&s)
		}()
		select {
		case <-done:
		case <-time.After(slowWait):
		}
	}
	return d.metrics.slow.Load()
}

// Metrics returns the monitoring snapshot: the shared one when it's
// recent, otherwise a new collection's (joined if one is under way), or,
// when that takes longer than MetricsWait, the newest there is with its
// sections marked as they are.
func (d *Daemon) Metrics() metrics.Snapshot {
	m := &d.metrics
	m.collectMu.Lock()
	if m.latest != nil && m.latestEpoch == m.epoch.Load() && d.Now().Sub(m.latest.Time) < MetricsMaxAge {
		s := *m.latest
		m.collectMu.Unlock()
		return s
	}
	wait := m.inflight
	if wait == nil {
		wait = make(chan struct{})
		m.inflight = wait
		go func() {
			epoch := m.epoch.Load()
			s := d.collect()
			m.collectMu.Lock()
			m.latest, m.latestEpoch = &s, epoch
			m.inflight = nil
			m.collectMu.Unlock()
			close(wait)
		}()
	}
	m.collectMu.Unlock()
	select {
	case <-wait:
	case <-time.After(MetricsWait):
	}
	m.collectMu.Lock()
	defer m.collectMu.Unlock()
	if m.latest != nil {
		return *m.latest
	}
	// The first collection hasn't finished: say so, with nothing in it.
	s := metrics.Snapshot{Time: d.Now().UTC(), Version: d.version, Sections: map[string]metrics.SectionStatus{}}
	for _, sec := range metrics.Sections {
		s.Sections[sec] = metrics.SectionStatus{State: metrics.Never}
	}
	return s
}

// section records one section's outcome and returns its status: current
// when read now, stale when read before (err says why not now), never or
// failed when it has no values.
func (d *Daemon) section(s *metrics.Snapshot, name string, readAt time.Time, start time.Time, err error) {
	if d.metrics.last == nil {
		d.metrics.last = map[string]sectionMemo{}
	}
	memo := d.metrics.last[name]
	st := metrics.SectionStatus{}
	switch {
	case err == nil && !readAt.IsZero() && !readAt.Before(start):
		memo = sectionMemo{at: readAt}
		st.State = metrics.Current
	case err == nil && !readAt.IsZero():
		// Read by an earlier attempt that finished late: last known.
		memo = sectionMemo{at: readAt}
		st.State, st.Error = metrics.Stale, "not read in time (the daemon is busy, e.g. a long commit)"
	case err != nil && !memo.at.IsZero():
		st.State, st.Error = metrics.Stale, err.Error()
	case err != nil:
		st.State, st.Error = metrics.Failed, err.Error()
	default:
		st.State = metrics.Never
	}
	if !memo.at.IsZero() {
		at := memo.at.UTC()
		st.CollectedAt = &at
	}
	d.metrics.last[name] = memo
	s.Sections[name] = st
}

// collect takes a snapshot. Only one runs at a time (Metrics).
func (d *Daemon) collect() metrics.Snapshot {
	d.metrics.collects.Add(1)
	start := d.Now()
	root := d.statsRoot
	if root == "" {
		root = "/"
	}
	d.metrics.collectMu.Lock()
	prev := d.metrics.latest
	d.metrics.collectMu.Unlock()
	s := metrics.Snapshot{Time: start.UTC(), Version: d.version, Sections: map[string]metrics.SectionStatus{}}
	s.Hostname, _ = os.Hostname()
	s.System = metrics.ReadSystem(root, []string{"/", "/var"})
	s.System.OS = d.osState()
	s.Sessions = metrics.ReadSessions(root)
	d.section(&s, "system", d.Now(), start, nil)
	cfg := d.metrics.running.Load()

	// The parts behind d.mu.
	slow := d.slowParts()
	slowAt := time.Time{}
	if slow != nil {
		slowAt = slow.at
	} else {
		slow = &slowMetrics{}
	}
	var stErr error
	if slow.stErr != nil {
		stErr = slow.stErr
	}
	d.section(&s, "config", slowAt, start, stErr)
	d.section(&s, "ips", slowAt, start, nil)
	d.section(&s, "decryption", slowAt, start, nil)
	natErr := slow.natErr
	d.section(&s, "nat", slowAt, start, natErr)

	// Config: the commit record is always current; the revision and state
	// only when the config section has values.
	s.Config = metrics.Config{LastCommitOK: true}
	if s.Valid("config") {
		s.Config.RunningRevision, s.Config.Uncommitted, s.Config.Recovery = slow.status.Running, slow.status.Pending, slow.status.Recovery != ""
	}
	if c := d.metrics.commit.Load(); c != nil {
		at := c.at.UTC()
		s.Config.LastCommitOK, s.Config.LastCommitTime, s.Config.LastCommitNote = c.ok, &at, c.note
	}

	// Interfaces: every interface of the running config, mgmt included.
	if cfg != nil {
		for _, i := range cfg.Interfaces {
			if in, ok := metrics.ReadInterface(root, i.Name); ok {
				in.Zone = i.Zone
				s.Interfaces = append(s.Interfaces, in)
			}
		}
		if mg := cfg.System.MgmtInterface; mg != "" && !hasIface(s.Interfaces, mg) {
			if in, ok := metrics.ReadInterface(root, mg); ok {
				s.Interfaces = append(s.Interfaces, in)
			}
		}
	}

	// Rules: on a failed read, the last known counters (stale), never
	// zeros.
	rules, rerr := d.ruleCounters(cfg)
	d.section(&s, "rules", d.Now(), start, rerr)
	switch {
	case rerr == nil:
		s.Rules = rules
	case s.Valid("rules") && prev != nil:
		s.Rules = prev.Rules
	}

	// NAT: when the counters failed, the last known entries (stale).
	if s.Valid("nat") {
		if natErr != nil && prev != nil {
			s.NAT = prev.NAT
		} else {
			for _, n := range slow.nat {
				e := metrics.NAT{Name: n.Name, Type: n.Type}
				if n.Hits != nil {
					e.Hits = *n.Hits
				}
				if n.OutHits != nil {
					e.OutHits = *n.OutHits
				}
				if n.HairpinHits != nil {
					e.Hairpin = *n.HairpinHits
				}
				s.NAT = append(s.NAT, e)
			}
		}
	}

	// IPS: the matches are counted as they happen (always current); the
	// engine's state only when the section has values.
	s.IPS = metrics.IPS{Matches: d.ipsMatches()}
	if s.Valid("ips") {
		s.IPS.State, s.IPS.Up, s.IPS.Loaded, s.IPS.QueueDropped = slow.ips.State, slow.ips.Running, slow.ips.Loaded, slow.ips.QueueDropped
		if s.IPS.State == "" {
			s.IPS.State = "off"
		}
		if t := slow.ips.Engine.Updated; !t.IsZero() {
			u := t.UTC()
			s.IPS.Updated = &u
		}
		for _, e := range slow.ips.Exceptions {
			if e.Inactive {
				s.IPS.ExceptionsIdle++
			} else {
				s.IPS.ExceptionsActive++
			}
		}
	}
	s.FillThreats()

	// App Identification: appidd's stats file.
	enabled := cfg != nil && cfg.System.AppIDOn()
	seen := d.appid.Seen(enabled)
	var aerr error
	if strings.HasPrefix(seen.Note, "appidd's statistics are unreadable") {
		aerr = fmt.Errorf("%s", seen.Note)
	}
	d.section(&s, "appid", d.Now(), start, aerr)
	s.AppID = metrics.AppID{Enabled: enabled, Up: seen.Running}
	if aerr == nil {
		s.AppID.Apps = topApps(seen)
	} else if prev != nil {
		s.AppID.Apps = prev.AppID.Apps
	}

	// Geo-blocking (read with the IPS section's locked parts).
	if s.Valid("ips") && slow != nil {
		s.GeoIP = slow.geo
	}

	// Decryption.
	if s.Valid("decryption") {
		s.Decryption = metrics.Decryption{State: slow.dec.State, Up: slow.dec.Running, Active: slow.dec.Active, Counts: slow.dec.Counts}
		if s.Decryption.State == "" {
			s.Decryption.State = "off"
		}
	}

	// Log forwarding and tags: ngfwd's own memory, always current.
	for _, l := range d.LogForwarding().Servers {
		s.LogServers = append(s.LogServers, metrics.LogServer{Name: l.Name, Connected: l.State == "connected", Sent: l.Sent, Dropped: l.Dropped, Queued: l.Queued})
	}
	counts := map[string]int{}
	var order []string
	for _, e := range d.tags.List("", start) {
		if counts[e.Tag] == 0 {
			order = append(order, e.Tag)
		}
		counts[e.Tag]++
	}
	for _, t := range order {
		s.Tags = append(s.Tags, metrics.TagCount{Tag: t, Addresses: counts[t]})
	}

	// Services. Suricata and tlsd come from the IPS and decryption reads:
	// unknown (never a fault, never healthy) unless those are current.
	active := d.metrics.serviceActive
	if active == nil {
		active = sysd.Active
	}
	used := func(f func(*config.Config) bool) bool { return cfg != nil && f(cfg) }
	s.Services = []metrics.Service{
		{Name: "ngfwd", Up: true, Used: true},
		{Name: "suricata", Up: slow.ips.Running, Used: used(func(c *config.Config) bool { return c.IPSActive() }), Unknown: !s.Fresh("ips")},
		{Name: "tlsd", Up: slow.dec.Running, Used: used(func(c *config.Config) bool { return c.System.DecryptionOn() && c.DecryptionActive() }), Unknown: !s.Fresh("decryption")},
		{Name: "appidd", Up: seen.Running, Used: enabled},
		{Name: "frr", Up: d.frr.Available() && active("frr"), Used: used(func(c *config.Config) bool { return len(c.Routing) > 0 })},
		{Name: "kea", Up: d.dhcp.Running(), Used: used(func(c *config.Config) bool { return len(c.DHCPServers) > 0 })},
	}
	if d.metrics.snmpRunning != nil {
		s.Services = append(s.Services, metrics.Service{Name: "snmpd", Up: d.metrics.snmpRunning(), Used: used(func(c *config.Config) bool { return c.SNMP.On() })})
	}
	for i := range s.Services {
		if s.Services[i].Unknown {
			s.Services[i].Up = false
		}
	}
	s.CollectSeconds = d.Now().Sub(start).Seconds()
	return s
}

func topApps(seen appid.Status) []metrics.App {
	var apps []metrics.App
	for _, a := range seen.Apps {
		apps = append(apps, metrics.App{Name: a.Name, Bytes: a.Bytes, Connections: a.Flows})
	}
	return metrics.TopApps(apps)
}

func hasIface(list []metrics.Interface, name string) bool {
	for _, i := range list {
		if i.Name == name {
			return true
		}
	}
	return false
}

// ruleChains are the ruleset chains security rules have lines in.
var ruleChains = []string{"forward", "allowed", "appid"}

// ruleCounters reads every rule's counters (its lines summed; a rule's
// "application pending" lines count too) and the default deny. A failed
// read is an error, never zeros; a chain that doesn't exist (nothing of
// that kind configured) contributes nothing.
func (d *Daemon) ruleCounters(cfg *config.Config) ([]metrics.Rule, error) {
	if cfg == nil {
		return nil, nil
	}
	reader, _ := d.nft.(counterReader)
	if reader == nil {
		return nil, fmt.Errorf("rule counters can't be read on this system")
	}
	all, err := reader.Counters(compiler.Table, ruleChains...)
	if err != nil {
		return nil, err
	}
	sum := map[string]nft.Counter{}
	for _, chain := range all {
		for comment, c := range chain {
			name, ok := strings.CutPrefix(comment, "rule:")
			if !ok {
				if comment == "default-deny" {
					name = comment
				} else {
					continue
				}
			}
			name, _, _ = strings.Cut(name, " (")
			t := sum[name]
			t.Packets += c.Packets
			t.Bytes += c.Bytes
			sum[name] = t
		}
	}
	out := make([]metrics.Rule, 0, len(cfg.Rules)+1)
	for _, r := range cfg.Rules {
		c := sum[r.Name]
		out = append(out, metrics.Rule{Name: r.Name, Action: r.Action, Packets: c.Packets, Bytes: c.Bytes})
	}
	c := sum["default-deny"]
	return append(out, metrics.Rule{Name: "default-deny", Action: "deny", Packets: c.Packets, Bytes: c.Bytes}), nil
}

// osStatusTTL is how long an OS package reading is reused.
const osStatusTTL = 30 * time.Second

// SetOSStatus sets how monitoring reads the OS package and reboot state.
func (d *Daemon) SetOSStatus(f func() *metrics.OS) {
	d.metrics.osMu.Lock()
	defer d.metrics.osMu.Unlock()
	d.metrics.osStatus, d.metrics.osAt, d.metrics.osLast = f, time.Time{}, nil
}

// osState is the OS package and reboot state, cached for osStatusTTL.
func (d *Daemon) osState() *metrics.OS {
	d.metrics.osMu.Lock()
	defer d.metrics.osMu.Unlock()
	if d.metrics.osStatus == nil {
		return nil
	}
	if now := time.Now(); d.metrics.osLast == nil || now.Sub(d.metrics.osAt) >= osStatusTTL {
		d.metrics.osLast, d.metrics.osAt = d.metrics.osStatus(), now
	}
	if d.metrics.osLast == nil {
		return nil
	}
	o := *d.metrics.osLast
	return &o
}
