package daemon

import (
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/stevejboyle/sjb-os/internal/compiler"
	"github.com/stevejboyle/sjb-os/internal/config"
	"github.com/stevejboyle/sjb-os/internal/metrics"
	"github.com/stevejboyle/sjb-os/internal/nft"
)

// metricsState is what the monitoring snapshot needs beyond the daemon's
// other state. None of it waits for d.mu: a commit can hold that for
// minutes (rebuilding the IPS signatures), and monitoring must keep
// answering meanwhile.
type metricsState struct {
	running atomic.Pointer[config.Config] // the running config
	commit  atomic.Pointer[commitRecord]  // the last commit's outcome

	matchMu sync.Mutex
	matches map[string]map[string]uint64 // severity -> action -> IPS matches

	// slow holds the parts read through methods that take d.mu (IPS, NAT,
	// decryption, Status); slowBusy is set while a read is under way.
	slow     atomic.Pointer[slowMetrics]
	slowBusy atomic.Bool

	// ServiceActive reports whether a systemd unit is active (tests
	// replace it).
	serviceActive func(unit string) bool
	// snmpRunning reports whether the SNMP agent runs (nil: not managed).
	snmpRunning func() bool
}

type commitRecord struct {
	ok   bool
	at   time.Time
	note string
}

type slowMetrics struct {
	ips    IPSStatus
	nat    []NATEntry
	dec    DecryptionStatus
	status Status
}

// slowWait is how long a snapshot waits for the parts behind d.mu before
// using the last ones.
const slowWait = 3 * time.Second

// recordCommit notes a commit's outcome for monitoring.
func (d *Daemon) recordCommit(ok bool, note string) {
	d.metrics.commit.Store(&commitRecord{ok: ok, at: d.Now(), note: note})
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

func systemdActive(unit string) bool {
	return exec.Command("systemctl", "is-active", "--quiet", unit).Run() == nil
}

// slowParts reads the parts behind d.mu, waiting at most slowWait; when
// d.mu is busy it returns the last ones read (zero before the first).
func (d *Daemon) slowParts() slowMetrics {
	if d.metrics.slowBusy.CompareAndSwap(false, true) {
		done := make(chan struct{})
		go func() {
			defer close(done)
			defer d.metrics.slowBusy.Store(false)
			var s slowMetrics
			s.ips = d.IPS()
			s.nat = d.NAT()
			s.dec = d.Decryption()
			s.status, _ = d.Status()
			d.metrics.slow.Store(&s)
		}()
		select {
		case <-done:
		case <-time.After(slowWait):
		}
	}
	if p := d.metrics.slow.Load(); p != nil {
		return *p
	}
	return slowMetrics{}
}

// Metrics takes the monitoring snapshot.
func (d *Daemon) Metrics() metrics.Snapshot {
	now := d.Now()
	root := d.statsRoot
	if root == "" {
		root = "/"
	}
	s := metrics.Snapshot{Time: now.UTC(), Version: d.version}
	s.Hostname, _ = os.Hostname()
	s.System = metrics.ReadSystem(root, []string{"/", "/var"})
	s.Sessions = metrics.ReadSessions(root)
	cfg := d.metrics.running.Load()
	slow := d.slowParts()

	// Config.
	s.Config = metrics.Config{RunningRevision: slow.status.Running, Uncommitted: slow.status.Pending, Recovery: slow.status.Recovery != "", LastCommitOK: true}
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

	// Rules: counters summed per rule across its ruleset lines.
	s.Rules = d.ruleCounters(cfg)

	// NAT.
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

	// IPS.
	s.IPS = metrics.IPS{State: slow.ips.State, Up: slow.ips.Running, Loaded: slow.ips.Loaded, QueueDropped: slow.ips.QueueDropped, Matches: d.ipsMatches()}
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
	s.FillThreats()

	// App Identification.
	enabled := cfg != nil && cfg.System.AppIDOn()
	seen := d.appid.Seen(enabled)
	s.AppID = metrics.AppID{Enabled: enabled, Up: seen.Running}
	var apps []metrics.App
	for _, a := range seen.Apps {
		apps = append(apps, metrics.App{Name: a.Name, Bytes: a.Bytes, Connections: a.Flows})
	}
	s.AppID.Apps = metrics.TopApps(apps)

	// Decryption.
	s.Decryption = metrics.Decryption{State: slow.dec.State, Up: slow.dec.Running, Active: slow.dec.Active, Counts: slow.dec.Counts}
	if s.Decryption.State == "" {
		s.Decryption.State = "off"
	}

	// Log forwarding.
	for _, l := range d.LogForwarding().Servers {
		s.LogServers = append(s.LogServers, metrics.LogServer{Name: l.Name, Connected: l.State == "connected", Sent: l.Sent, Dropped: l.Dropped, Queued: l.Queued})
	}

	// Tags.
	counts := map[string]int{}
	var order []string
	for _, e := range d.tags.List("", now) {
		if counts[e.Tag] == 0 {
			order = append(order, e.Tag)
		}
		counts[e.Tag]++
	}
	for _, t := range order {
		s.Tags = append(s.Tags, metrics.TagCount{Tag: t, Addresses: counts[t]})
	}

	// Services.
	active := d.metrics.serviceActive
	if active == nil {
		active = systemdActive
	}
	used := func(f func(*config.Config) bool) bool { return cfg != nil && f(cfg) }
	s.Services = []metrics.Service{
		{Name: "ngfwd", Up: true, Used: true},
		{Name: "suricata", Up: slow.ips.Running, Used: used(func(c *config.Config) bool { return c.IPSActive() })},
		{Name: "tlsd", Up: slow.dec.Running, Used: used(func(c *config.Config) bool { return c.System.DecryptionOn() && c.DecryptionActive() })},
		{Name: "appidd", Up: seen.Running, Used: enabled},
		{Name: "frr", Up: d.frr.Available() && active("frr"), Used: used(func(c *config.Config) bool { return len(c.Routing) > 0 })},
		{Name: "kea", Up: d.dhcp.Running(), Used: used(func(c *config.Config) bool { return len(c.DHCPServers) > 0 })},
	}
	if d.metrics.snmpRunning != nil {
		s.Services = append(s.Services, metrics.Service{Name: "snmpd", Up: d.metrics.snmpRunning(), Used: used(func(c *config.Config) bool { return c.SNMP.On() })})
	}
	return s
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
// "application pending" lines count too) and the default deny.
func (d *Daemon) ruleCounters(cfg *config.Config) []metrics.Rule {
	if cfg == nil {
		return nil
	}
	reader, _ := d.nft.(counterReader)
	var all map[string]map[string]nft.Counter
	if reader != nil {
		all, _ = reader.Counters(compiler.Table, ruleChains...)
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
	return append(out, metrics.Rule{Name: "default-deny", Action: "deny", Packets: c.Packets, Bytes: c.Bytes})
}
