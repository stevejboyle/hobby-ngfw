package metrics

import (
	"bufio"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
)

// promWriter writes the Prometheus text exposition format (version 0.0.4).
type promWriter struct {
	w    *bufio.Writer
	seen map[string]bool
}

// family starts a metric family (HELP and TYPE once per name).
func (p *promWriter) family(name, typ, help string) {
	if p.seen[name] {
		return
	}
	p.seen[name] = true
	p.w.WriteString("# HELP " + name + " " + escHelp(help) + "\n")
	p.w.WriteString("# TYPE " + name + " " + typ + "\n")
}

// sample writes one sample; labels are name, value pairs.
func (p *promWriter) sample(name string, v float64, labels ...string) {
	p.w.WriteString(name)
	if len(labels) > 0 {
		p.w.WriteByte('{')
		for i := 0; i+1 < len(labels); i += 2 {
			if i > 0 {
				p.w.WriteByte(',')
			}
			p.w.WriteString(labels[i] + `="` + escLabel(labels[i+1]) + `"`)
		}
		p.w.WriteByte('}')
	}
	p.w.WriteByte(' ')
	// Whole numbers (counters, timestamps) as integers: 'g' would write
	// a timestamp as 1.79539994e+09.
	if v == math.Trunc(v) && math.Abs(v) < 1e15 {
		p.w.WriteString(strconv.FormatInt(int64(v), 10))
	} else {
		p.w.WriteString(strconv.FormatFloat(v, 'g', -1, 64))
	}
	p.w.WriteByte('\n')
}

// one writes a family with a single sample.
func (p *promWriter) one(name, typ, help string, v float64, labels ...string) {
	p.family(name, typ, help)
	p.sample(name, v, labels...)
}

func escHelp(s string) string {
	return strings.NewReplacer(`\`, `\\`, "\n", `\n`).Replace(s)
}

func escLabel(s string) string {
	return strings.NewReplacer(`\`, `\\`, "\n", `\n`, `"`, `\"`).Replace(s)
}

func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// WritePrometheus renders s as Prometheus text. Every name starts sjbos_.
func WritePrometheus(out io.Writer, s Snapshot) error {
	p := &promWriter{w: bufio.NewWriter(out), seen: map[string]bool{}}

	p.one("sjbos_info", "gauge", "SJB-OS version and hostname (always 1).", 1, "version", s.Version, "hostname", s.Hostname)
	p.one("sjbos_uptime_seconds", "gauge", "Seconds since the appliance booted.", s.System.UptimeSeconds)
	p.family("sjbos_cpu_seconds_total", "counter", "CPU time by mode, all CPUs together.")
	for _, m := range sortedKeys(s.System.CPUSeconds) {
		p.sample("sjbos_cpu_seconds_total", s.System.CPUSeconds[m], "mode", m)
	}
	p.one("sjbos_cpus", "gauge", "Number of CPUs.", float64(s.System.CPUs))
	p.family("sjbos_load_average", "gauge", "System load average.")
	for i, per := range []string{"1m", "5m", "15m"} {
		p.sample("sjbos_load_average", s.System.Load[i], "period", per)
	}
	p.one("sjbos_memory_total_bytes", "gauge", "Total memory.", float64(s.System.MemTotal))
	p.one("sjbos_memory_available_bytes", "gauge", "Memory available for new work.", float64(s.System.MemAvailable))
	if o := s.System.OS; o != nil {
		p.one("sjbos_reboot_required", "gauge", "1 when a newer kernel is installed than the one running (or the running kernel was removed).", b2f(o.RebootRequired), "kernel", o.Kernel)
		p.family("sjbos_os_packages_state", "gauge", "State of the last OS package install (1 for the current state).")
		for _, st := range OSStates {
			p.sample("sjbos_os_packages_state", b2f(o.PackagesState == st), "state", st)
		}
		p.one("sjbos_os_packages_pending", "gauge", "Bundled Debian packages not installed yet.", float64(o.PackagesPending))
	}
	if len(s.System.Disks) > 0 {
		p.family("sjbos_filesystem_size_bytes", "gauge", "Filesystem size.")
		for _, d := range s.System.Disks {
			p.sample("sjbos_filesystem_size_bytes", float64(d.Size), "mount", d.Mount)
		}
		p.family("sjbos_filesystem_free_bytes", "gauge", "Filesystem space available.")
		for _, d := range s.System.Disks {
			p.sample("sjbos_filesystem_free_bytes", float64(d.Free), "mount", d.Mount)
		}
	}

	// Collection health: each section's state and read time.
	p.family("sjbos_collection_state", "gauge", "How fresh each part of the metrics is (1 for its state): current (read by this collection), stale (last known values), never (not read yet, values left out), failed (no values: every read failed).")
	for _, sec := range sortedKeys(s.Sections) {
		for _, st := range States {
			p.sample("sjbos_collection_state", b2f(s.Sections[sec].State == st), "section", sec, "state", st)
		}
	}
	p.family("sjbos_collection_timestamp_seconds", "gauge", "When each part's values were read (Unix time); absent for parts never read.")
	for _, sec := range sortedKeys(s.Sections) {
		if t := s.Sections[sec].CollectedAt; t != nil {
			p.sample("sjbos_collection_timestamp_seconds", float64(t.Unix()), "section", sec)
		}
	}
	p.one("sjbos_collection_duration_seconds", "gauge", "How long the collection behind these metrics took.", s.CollectSeconds)

	if s.Valid("config") {
		p.one("sjbos_config_running_revision", "gauge", "The running config revision.", float64(s.Config.RunningRevision))
		p.one("sjbos_config_uncommitted_changes", "gauge", "1 when the candidate differs from the running config.", b2f(s.Config.Uncommitted))
	}
	p.one("sjbos_config_last_commit_success", "gauge", "0 when the last commit failed or was rolled back automatically.", b2f(s.Config.LastCommitOK))
	if s.Config.LastCommitTime != nil {
		p.one("sjbos_config_last_commit_timestamp_seconds", "gauge", "When the last commit finished (Unix time).", float64(s.Config.LastCommitTime.Unix()))
	}
	if s.Valid("config") {
		p.one("sjbos_config_recovery", "gauge", "1 when enforcement may not match the running revision.", b2f(s.Config.Recovery))
	}

	p.family("sjbos_service_up", "gauge", "1 when the service is running (absent while its state can't be read freshly).")
	for _, sv := range s.Services {
		if !sv.Unknown {
			p.sample("sjbos_service_up", b2f(sv.Up), "service", sv.Name)
		}
	}
	p.family("sjbos_service_used", "gauge", "1 when the config needs the service.")
	for _, sv := range s.Services {
		p.sample("sjbos_service_used", b2f(sv.Used), "service", sv.Name)
	}

	ifc := []struct {
		name, help string
		get        func(Interface) uint64
	}{
		{"sjbos_interface_receive_bytes_total", "Bytes received.", func(i Interface) uint64 { return i.RxBytes }},
		{"sjbos_interface_transmit_bytes_total", "Bytes sent.", func(i Interface) uint64 { return i.TxBytes }},
		{"sjbos_interface_receive_packets_total", "Packets received.", func(i Interface) uint64 { return i.RxPackets }},
		{"sjbos_interface_transmit_packets_total", "Packets sent.", func(i Interface) uint64 { return i.TxPackets }},
		{"sjbos_interface_receive_errors_total", "Receive errors.", func(i Interface) uint64 { return i.RxErrors }},
		{"sjbos_interface_transmit_errors_total", "Transmit errors.", func(i Interface) uint64 { return i.TxErrors }},
		{"sjbos_interface_receive_drops_total", "Packets dropped on receive.", func(i Interface) uint64 { return i.RxDropped }},
		{"sjbos_interface_transmit_drops_total", "Packets dropped on transmit.", func(i Interface) uint64 { return i.TxDropped }},
	}
	if len(s.Interfaces) > 0 {
		p.family("sjbos_interface_up", "gauge", "1 when the interface is up.")
		for _, in := range s.Interfaces {
			p.sample("sjbos_interface_up", b2f(in.Up), "interface", in.Name, "zone", in.Zone)
		}
		for _, c := range ifc {
			p.family(c.name, "counter", c.help)
			for _, in := range s.Interfaces {
				p.sample(c.name, float64(c.get(in)), "interface", in.Name, "zone", in.Zone)
			}
		}
	}

	p.one("sjbos_sessions", "gauge", "Tracked connections.", float64(s.Sessions.Count))
	p.one("sjbos_sessions_max", "gauge", "Connection tracking limit.", float64(s.Sessions.Max))

	if len(s.Rules) > 0 {
		p.family("sjbos_rule_packets_total", "counter", "Packets matched by the security rule (new connections, and packets re-evaluated by application rules).")
		for _, r := range s.Rules {
			p.sample("sjbos_rule_packets_total", float64(r.Packets), "rule", r.Name, "action", r.Action)
		}
		p.family("sjbos_rule_bytes_total", "counter", "Bytes in the packets the security rule matched.")
		for _, r := range s.Rules {
			p.sample("sjbos_rule_bytes_total", float64(r.Bytes), "rule", r.Name, "action", r.Action)
		}
	}
	if len(s.NAT) > 0 {
		p.family("sjbos_nat_translations_total", "counter", "New connections translated by the NAT entry (inbound for published servers, outbound for masquerade).")
		for _, n := range s.NAT {
			p.sample("sjbos_nat_translations_total", float64(n.Hits), "nat", n.Name, "type", n.Type, "direction", "primary")
			if n.OutHits > 0 || n.Type == "static" {
				p.sample("sjbos_nat_translations_total", float64(n.OutHits), "nat", n.Name, "type", n.Type, "direction", "outbound")
			}
		}
		p.family("sjbos_nat_hairpin_total", "counter", "Connections from SJB-OS's other interfaces to the published server (hairpin NAT).")
		for _, n := range s.NAT {
			p.sample("sjbos_nat_hairpin_total", float64(n.Hairpin), "nat", n.Name)
		}
	}

	if s.Valid("ips") {
		p.family("sjbos_ips_state", "gauge", "The IPS state (1 for the current one): off, unavailable, starting, loading, inspecting.")
		for _, st := range []string{"off", "unavailable", "starting", "loading", "inspecting"} {
			p.sample("sjbos_ips_state", b2f(s.IPS.State == st), "state", st)
		}
		p.one("sjbos_ips_signatures_loaded", "gauge", "Signatures the running engine has active.", float64(s.IPS.Loaded))
		if s.IPS.Updated != nil {
			p.one("sjbos_ips_signatures_updated_timestamp_seconds", "gauge", "Last successful signature download (Unix time).", float64(s.IPS.Updated.Unix()))
		}
		p.one("sjbos_ips_queue_dropped_total", "counter", "Packets that passed uninspected or were dropped because the IPS queue was full.", float64(s.IPS.QueueDropped))
	}
	p.family("sjbos_ips_matches_total", "counter", "IPS matches logged since ngfwd started, by severity and action.")
	for _, sev := range Severities {
		for _, act := range []string{"block", "alert"} {
			p.sample("sjbos_ips_matches_total", float64(s.IPS.Matches[sev][act]), "severity", sev, "action", act)
		}
	}
	if s.Valid("ips") {
		p.family("sjbos_ips_exceptions", "gauge", "IPS exceptions in the running config, by status.")
		p.sample("sjbos_ips_exceptions", float64(s.IPS.ExceptionsActive), "status", "active")
		p.sample("sjbos_ips_exceptions", float64(s.IPS.ExceptionsIdle), "status", "inactive")
	}

	p.one("sjbos_appid_enabled", "gauge", "1 when App Identification is on.", b2f(s.AppID.Enabled))
	if len(s.AppID.Apps) > 0 {
		p.family("sjbos_app_bytes_total", "counter", "Bytes of finished connections per application since appidd started (top applications).")
		for _, a := range s.AppID.Apps {
			p.sample("sjbos_app_bytes_total", float64(a.Bytes), "app", a.Name)
		}
		p.family("sjbos_app_connections_total", "counter", "Finished connections per application since appidd started (top applications).")
		for _, a := range s.AppID.Apps {
			p.sample("sjbos_app_connections_total", float64(a.Connections), "app", a.Name)
		}
	}

	if s.Valid("decryption") {
		p.family("sjbos_decryption_state", "gauge", "The TLS decryption state (1 for the current one).")
		for _, st := range []string{"off", "no-ca", "unavailable", "busy", "observing", "decrypting"} {
			p.sample("sjbos_decryption_state", b2f(s.Decryption.State == st), "state", st)
		}
		p.one("sjbos_decryption_active_connections", "gauge", "Connections tlsd handles now.", float64(s.Decryption.Active))
	}
	if len(s.Decryption.Counts) > 0 {
		p.family("sjbos_decryption_connections_total", "counter", "Connections handled by tlsd since it started, by outcome.")
		for _, k := range sortedKeys(s.Decryption.Counts) {
			p.sample("sjbos_decryption_connections_total", float64(s.Decryption.Counts[k]), "outcome", k)
		}
	}

	if len(s.LogServers) > 0 {
		p.family("sjbos_logforward_connected", "gauge", "1 when the log server is connected (always 1 for UDP once sending).")
		for _, l := range s.LogServers {
			p.sample("sjbos_logforward_connected", b2f(l.Connected), "server", l.Name)
		}
		p.family("sjbos_logforward_sent_total", "counter", "Log messages sent since ngfwd started.")
		for _, l := range s.LogServers {
			p.sample("sjbos_logforward_sent_total", float64(l.Sent), "server", l.Name)
		}
		p.family("sjbos_logforward_dropped_total", "counter", "Log messages dropped (queue full) since ngfwd started.")
		for _, l := range s.LogServers {
			p.sample("sjbos_logforward_dropped_total", float64(l.Dropped), "server", l.Name)
		}
		p.family("sjbos_logforward_queued", "gauge", "Log messages waiting to be sent.")
		for _, l := range s.LogServers {
			p.sample("sjbos_logforward_queued", float64(l.Queued), "server", l.Name)
		}
	}
	if len(s.Tags) > 0 {
		p.family("sjbos_tag_addresses", "gauge", "Addresses registered with the tag.")
		for _, t := range s.Tags {
			p.sample("sjbos_tag_addresses", float64(t.Addresses), "tag", t.Tag)
		}
	}
	p.one("sjbos_scrape_timestamp_seconds", "gauge", "When this snapshot was taken (Unix time).", float64(s.Time.Unix()))
	return p.w.Flush()
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
