// Package metrics is SJB-OS's monitoring snapshot: one point-in-time view of
// the appliance (interfaces, sessions, rules, NAT, the IPS, App
// Identification, decryption, log forwarding, tags, system health and the
// config) that ngfwd assembles from what it already knows. It renders as
// Prometheus text (GET /metrics on the tag API) and is saved as JSON for the
// SNMP agent's pass_persist helper (fwctl snmp-pass).
package metrics

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// SnapshotPath is where ngfwd saves the snapshot for the SNMP helper.
const SnapshotPath = "/run/sjb-os/metrics.json"

// Snapshot is everything exported, at Time.
type Snapshot struct {
	Time     time.Time `json:"time"`
	Version  string    `json:"version"`
	Hostname string    `json:"hostname"`

	System     System       `json:"system"`
	Config     Config       `json:"config"`
	Services   []Service    `json:"services"`
	Interfaces []Interface  `json:"interfaces"`
	Sessions   Sessions     `json:"sessions"`
	Rules      []Rule       `json:"rules"`
	NAT        []NAT        `json:"nat"`
	IPS        IPS          `json:"ips"`
	AppID      AppID        `json:"app_id"`
	Decryption Decryption   `json:"decryption"`
	LogServers []LogServer  `json:"log_servers"`
	Tags       []TagCount   `json:"tags"`
	Threats    []ThreatStat `json:"threats"` // IPS matches by severity (same data as IPS.Matches, as rows)

	// Sections says how fresh each independently collected part is (see
	// SectionStatus); a part that was never collected holds no values.
	Sections map[string]SectionStatus `json:"sections"`
	// CollectSeconds is how long the collection behind this snapshot took.
	CollectSeconds float64 `json:"collect_seconds"`
}

// Collection states of a section.
const (
	// Current: read by the collection behind this snapshot.
	Current = "current"
	// Stale: the last known values; the latest attempt didn't finish in
	// time (a long commit holds the daemon) or failed (Error says why).
	Stale = "stale"
	// Never: not read yet since ngfwd started; its values are absent.
	Never = "never"
	// Failed: every attempt so far failed; its values are absent.
	Failed = "failed"
)

// States are the collection states, in order.
var States = []string{Current, Stale, Never, Failed}

// Sections are the independently collected parts of a snapshot.
var Sections = []string{"config", "ips", "decryption", "nat", "rules", "appid", "system"}

// SectionStatus is how fresh one part of the snapshot is.
type SectionStatus struct {
	State       string     `json:"state"`
	CollectedAt *time.Time `json:"collected_at,omitempty"` // when its values were read
	Error       string     `json:"error,omitempty"`        // the latest attempt's failure
}

// Valid reports whether the section has values (current or stale).
func (s Snapshot) Valid(section string) bool {
	st := s.Sections[section].State
	return st == Current || st == Stale
}

// Fresh reports whether the section was read by this collection.
func (s Snapshot) Fresh(section string) bool { return s.Sections[section].State == Current }

// System is host health read from /proc and statfs.
type System struct {
	UptimeSeconds float64            `json:"uptime_seconds"`
	CPUSeconds    map[string]float64 `json:"cpu_seconds"` // mode: user, system, idle, iowait, other
	CPUs          int                `json:"cpus"`
	Load          [3]float64         `json:"load"` // 1, 5, 15 minutes
	MemTotal      uint64             `json:"mem_total_bytes"`
	MemAvailable  uint64             `json:"mem_available_bytes"`
	Disks         []Disk             `json:"disks"`
	// OS is the state of the Debian packages upgrades install (nil when
	// unknown, such as off the appliance).
	OS *OS `json:"os,omitempty"`
}

// OS package states, as fwctl records them.
var OSStates = []string{"idle", "installing", "ok", "failed"}

// OS is the OS package and reboot state.
type OS struct {
	PackagesState   string `json:"packages_state"` // one of OSStates
	PackagesPending int    `json:"packages_pending"`
	RebootRequired  bool   `json:"reboot_required"`
	Kernel          string `json:"kernel"`
}

// Disk is one filesystem's size and free space.
type Disk struct {
	Mount string `json:"mount"`
	Size  uint64 `json:"size_bytes"`
	Free  uint64 `json:"free_bytes"`
}

// Config is the configuration's state.
type Config struct {
	RunningRevision int  `json:"running_revision"`
	Uncommitted     bool `json:"uncommitted_changes"`
	// LastCommitOK is false when the last commit failed, or the last
	// unconfirmed commit was rolled back automatically. True before any
	// commit since ngfwd started.
	LastCommitOK   bool       `json:"last_commit_ok"`
	LastCommitTime *time.Time `json:"last_commit_time,omitempty"`
	LastCommitNote string     `json:"last_commit_note,omitempty"`
	Recovery       bool       `json:"recovery"` // enforcement may not match the running revision
}

// Service is one of the appliance's services.
type Service struct {
	Name string `json:"name"`
	Up   bool   `json:"up"`
	// Used: the config needs it (e.g. Kea only with DHCP servers). An
	// unused service that's down is normal, not a fault.
	Used bool `json:"used"`
	// Unknown: its state couldn't be read freshly (Up means nothing);
	// never a fault, never healthy.
	Unknown bool `json:"unknown,omitempty"`
}

// Interface is one interface's counters (from /sys/class/net).
type Interface struct {
	Name      string `json:"name"`
	Zone      string `json:"zone"` // "" for mgmt and trunks
	Up        bool   `json:"up"`
	RxBytes   uint64 `json:"rx_bytes"`
	TxBytes   uint64 `json:"tx_bytes"`
	RxPackets uint64 `json:"rx_packets"`
	TxPackets uint64 `json:"tx_packets"`
	RxErrors  uint64 `json:"rx_errors"`
	TxErrors  uint64 `json:"tx_errors"`
	RxDropped uint64 `json:"rx_dropped"`
	TxDropped uint64 `json:"tx_dropped"`
}

// Sessions is the connection tracking table.
type Sessions struct {
	Count uint64 `json:"count"`
	Max   uint64 `json:"max"`
}

// Rule is a security rule's counters: packets its lines matched (new
// connections, and packets re-evaluated by application rules).
type Rule struct {
	Name    string `json:"name"`
	Action  string `json:"action"`
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

// NAT is a NAT entry's translations.
type NAT struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Hits    uint64 `json:"hits"`
	OutHits uint64 `json:"out_hits"`
	Hairpin uint64 `json:"hairpin"`
}

// IPS is the intrusion prevention engine.
type IPS struct {
	State        string     `json:"state"` // off, unavailable, starting, loading, inspecting
	Up           bool       `json:"up"`    // Suricata running
	Loaded       int        `json:"signatures_loaded"`
	Updated      *time.Time `json:"signatures_updated,omitempty"`
	QueueDropped uint64     `json:"queue_dropped"`
	// Matches counts logged matches since ngfwd started, by severity and
	// action (block, alert).
	Matches          map[string]map[string]uint64 `json:"matches"`
	ExceptionsActive int                          `json:"exceptions_active"`
	ExceptionsIdle   int                          `json:"exceptions_inactive"`
}

// ThreatStat is the IPS matches of one severity.
type ThreatStat struct {
	Severity string `json:"severity"`
	Blocked  uint64 `json:"blocked"`
	Alerted  uint64 `json:"alerted"`
}

// AppID is App Identification.
type AppID struct {
	Enabled bool  `json:"enabled"`
	Up      bool  `json:"up"`
	Apps    []App `json:"apps"` // top by bytes, at most MaxApps
}

// App is one application's totals since appidd started.
type App struct {
	Name        string `json:"name"`
	Bytes       int64  `json:"bytes"`
	Connections int64  `json:"connections"`
}

// MaxApps caps the applications exported (one series each).
const MaxApps = 50

// Decryption is TLS decryption.
type Decryption struct {
	State  string           `json:"state"` // off, no-ca, unavailable, busy, observing, decrypting
	Up     bool             `json:"up"`    // tlsd running
	Active int64            `json:"active"`
	Counts map[string]int64 `json:"counts"` // tlsd's outcome counters since it started
}

// LogServer is one log forwarding destination.
type LogServer struct {
	Name      string `json:"name"`
	Connected bool   `json:"connected"`
	Sent      uint64 `json:"sent"`
	Dropped   uint64 `json:"dropped"`
	Queued    int    `json:"queued"`
}

// TagCount is how many addresses carry a tag.
type TagCount struct {
	Tag       string `json:"tag"`
	Addresses int    `json:"addresses"`
}

// Severities are the IPS severities, in order.
var Severities = []string{"critical", "major", "minor", "informational"}

// FillThreats sets Threats from IPS.Matches (every severity, in order).
func (s *Snapshot) FillThreats() {
	s.Threats = s.Threats[:0]
	for _, sev := range Severities {
		m := s.IPS.Matches[sev]
		s.Threats = append(s.Threats, ThreatStat{Severity: sev, Blocked: m["block"], Alerted: m["alert"]})
	}
}

// TopApps sorts apps by bytes (then name) and keeps the first MaxApps.
func TopApps(apps []App) []App {
	sort.Slice(apps, func(i, j int) bool {
		if apps[i].Bytes != apps[j].Bytes {
			return apps[i].Bytes > apps[j].Bytes
		}
		return apps[i].Name < apps[j].Name
	})
	if len(apps) > MaxApps {
		apps = apps[:MaxApps]
	}
	return apps
}

// Save writes the snapshot to path atomically with the given mode, and
// group gid when gid >= 0 (the SNMP agent's group, so it can read it).
func Save(path string, s Snapshot, mode os.FileMode, gid int) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".metrics-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), mode); err != nil {
		return err
	}
	if gid >= 0 {
		if err := os.Chown(tmp.Name(), -1, gid); err != nil {
			return err
		}
	}
	return os.Rename(tmp.Name(), path)
}

// Load reads a saved snapshot.
func Load(path string) (Snapshot, error) {
	var s Snapshot
	b, err := os.ReadFile(path)
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return s, fmt.Errorf("%s: %w", path, err)
	}
	return s, nil
}
