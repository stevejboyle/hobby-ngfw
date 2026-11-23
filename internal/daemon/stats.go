package daemon

import (
	"github.com/stevejboyle/sjb-os/internal/stats"
)

// SetStats sets where the dashboard statistics are kept, and the root
// filesystem interface counters are read from ("/" on the appliance).
// Call before Start.
func (d *Daemon) SetStats(s *stats.Store, root string) { d.stats, d.statsRoot = s, root }

// SampleStats takes the minute's sample: interface counters of the running
// config's zoned interfaces, and appidd's per-application and per-host
// totals. ngfwd calls it once a minute.
func (d *Daemon) SampleStats() error {
	if d.stats == nil {
		return nil
	}
	// No d.mu here: a long commit must not make the sampler skip minutes.
	var names []string
	if p := d.statsIfaces.Load(); p != nil {
		names = *p
	}
	in := stats.Input{If: stats.ReadInterfaces(d.statsRoot, names)}
	apps, hosts := d.appid.Counters()
	for _, a := range apps {
		in.Apps = append(in.Apps, stats.Counter{Key: a.Key, Bytes: a.Bytes, Flows: a.Flows})
	}
	for _, h := range hosts {
		in.Hosts = append(in.Hosts, stats.Counter{Key: h.Key, Bytes: h.Bytes, Flows: h.Flows})
	}
	return d.stats.Take(in)
}

// StatsView is the dashboard's statistics for a window.
type StatsView struct {
	stats.Report
	AppID bool `json:"app_id"` // App Identification on (applications and hosts)
	IPS   bool `json:"ips"`    // some rule uses an IPS profile, IPS on
}

// Stats reports a window ("1h", "24h", "7d") of statistics.
func (d *Daemon) Stats(window string) (StatsView, error) {
	var v StatsView
	if d.stats == nil {
		r, err := (&stats.Store{}).Window(window)
		v.Report = r
		return v, err
	}
	r, err := d.stats.Window(window)
	if err != nil {
		return v, err
	}
	v.Report = r
	d.mu.Lock()
	if d.running != nil {
		v.AppID = d.running.System.AppIDOn()
		v.IPS = d.running.IPSActive()
	}
	d.mu.Unlock()
	return v, nil
}
