// Package stats keeps a week of per-minute traffic statistics for the
// dashboard: interface throughput, applications and hosts (from
// appidd's counters), and IPS matches. ngfwd takes one sample a minute;
// samples persist as JSON lines so history survives restarts.
package stats

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Keep is how long samples are kept.
const Keep = 7 * 24 * time.Hour

// hostsPerSample bounds a sample's host map (the busiest by bytes).
const hostsPerSample = 25

// Pair is two counters: bytes and connections, or rx and tx bytes.
type Pair [2]int64

// Sample is one minute of activity (deltas, not totals).
type Sample struct {
	T       int64             `json:"t"`                 // Unix time the minute ended
	If      map[string]Pair   `json:"if,omitempty"`      // interface: rx, tx bytes
	Apps    map[string]Pair   `json:"apps,omitempty"`    // application: bytes, connections
	Hosts   map[string]Pair   `json:"hosts,omitempty"`   // source IP: bytes, connections
	Threats map[string][2]int `json:"threats,omitempty"` // severity: blocked, alerted
	Sigs    map[int]int       `json:"sigs,omitempty"`    // signature ID: matches
	TSrc    map[string]int    `json:"tsrc,omitempty"`    // source IP: matches
}

// SigInfo describes a signature seen in a threat.
type SigInfo struct {
	Signature string `json:"signature"`
	Severity  string `json:"severity"`
}

// Counter is a running total read from a source (appidd's apps or hosts).
type Counter struct {
	Key          string
	Bytes, Flows int64
}

// Input is what a sample is computed from: running totals, as read now.
type Input struct {
	If    map[string]Pair // interface: rx, tx byte counters
	Apps  []Counter
	Hosts []Counter
}

// Store holds the samples. Safe for concurrent use.
type Store struct {
	Path string // samples.jsonl; "" keeps them in memory only
	Now  func() time.Time

	mu       sync.Mutex
	samples  []Sample
	sigs     map[int]SigInfo
	last     *Input // previous totals, for deltas
	pending  Sample // threats since the last sample
	appended int    // lines appended since the file was last compacted
}

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Open loads the samples kept on disk (those within Keep). now is the
// clock (nil: time.Now).
func Open(path string, now func() time.Time) (*Store, error) {
	s := &Store{Path: path, Now: now}
	if path == "" {
		return s, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, s.loadSigs()
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	cut := s.now().Add(-Keep).Unix()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 4<<20)
	for sc.Scan() {
		var sm Sample
		if json.Unmarshal(sc.Bytes(), &sm) == nil && sm.T >= cut {
			s.samples = append(s.samples, sm)
		}
	}
	sort.SliceStable(s.samples, func(i, j int) bool { return s.samples[i].T < s.samples[j].T })
	if err := s.loadSigs(); err != nil {
		return nil, err
	}
	return s, s.compactLocked()
}

func (s *Store) sigsPath() string { return strings.TrimSuffix(s.Path, ".jsonl") + "-signatures.json" }

func (s *Store) loadSigs() error {
	s.sigs = map[int]SigInfo{}
	b, err := os.ReadFile(s.sigsPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	json.Unmarshal(b, &s.sigs)
	return nil
}

// AddThreat counts one IPS match (logged ones: blocked or alerted) into the
// minute under way.
func (s *Store) AddThreat(severity, action string, sid int, signature, src string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := &s.pending
	if p.Threats == nil {
		p.Threats, p.Sigs, p.TSrc = map[string][2]int{}, map[int]int{}, map[string]int{}
	}
	c := p.Threats[severity]
	if action == "block" {
		c[0]++
	} else {
		c[1]++
	}
	p.Threats[severity] = c
	p.Sigs[sid]++
	if src != "" {
		p.TSrc[src]++
	}
	if s.sigs == nil {
		s.sigs = map[int]SigInfo{}
	}
	if old, ok := s.sigs[sid]; !ok || old.Signature != signature {
		s.sigs[sid] = SigInfo{Signature: signature, Severity: severity}
		s.saveSigsLocked()
	}
}

func (s *Store) saveSigsLocked() {
	if s.Path == "" {
		return
	}
	b, _ := json.Marshal(s.sigs)
	tmp := s.sigsPath() + ".tmp"
	if os.WriteFile(tmp, b, 0o644) == nil {
		os.Rename(tmp, s.sigsPath())
	}
}

// delta is now - before, or now when the counter went backwards (the
// source restarted).
func delta(now, before int64) int64 {
	if now < before {
		return now
	}
	return now - before
}

// Take records a sample from in: the change since the previous Take (the
// first one only sets the baseline for counters), plus the threats counted
// since.
func (s *Store) Take(in Input) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sm := s.pending
	s.pending = Sample{}
	sm.T = s.now().Unix()
	if prev := s.last; prev != nil {
		for k, v := range in.If {
			if p, ok := prev.If[k]; ok {
				d := Pair{delta(v[0], p[0]), delta(v[1], p[1])}
				if d[0] > 0 || d[1] > 0 {
					if sm.If == nil {
						sm.If = map[string]Pair{}
					}
					sm.If[k] = d
				}
			}
		}
		sm.Apps = counterDeltas(in.Apps, prev.Apps, 0)
		sm.Hosts = counterDeltas(in.Hosts, prev.Hosts, hostsPerSample)
	}
	cp := in
	s.last = &cp
	s.samples = append(s.samples, sm)
	cut := s.now().Add(-Keep).Unix()
	i := 0
	for i < len(s.samples) && s.samples[i].T < cut {
		i++
	}
	s.samples = s.samples[i:]
	if s.Path == "" {
		return nil
	}
	b, err := json.Marshal(sm)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(s.Path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	_, err = f.Write(append(b, '\n'))
	f.Close()
	if s.appended++; s.appended >= 1440 { // daily: drop what's past Keep
		return s.compactLocked()
	}
	return err
}

// counterDeltas returns the changed counters, keeping the top max by bytes
// (0: all).
func counterDeltas(now, before []Counter, max int) map[string]Pair {
	prev := map[string]Counter{}
	for _, c := range before {
		prev[c.Key] = c
	}
	var out []Counter
	for _, c := range now {
		p, ok := prev[c.Key]
		d := Counter{Key: c.Key, Bytes: c.Bytes, Flows: c.Flows}
		if ok {
			d.Bytes, d.Flows = delta(c.Bytes, p.Bytes), delta(c.Flows, p.Flows)
		}
		if d.Bytes > 0 || d.Flows > 0 {
			out = append(out, d)
		}
	}
	if len(out) == 0 {
		return nil
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Bytes > out[j].Bytes })
	if max > 0 && len(out) > max {
		out = out[:max]
	}
	m := make(map[string]Pair, len(out))
	for _, c := range out {
		m[c.Key] = Pair{c.Bytes, c.Flows}
	}
	return m
}

// compactLocked rewrites the file with the samples in memory.
func (s *Store) compactLocked() error {
	s.appended = 0
	if s.Path == "" {
		return nil
	}
	tmp := s.Path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(f)
	for _, sm := range s.samples {
		b, _ := json.Marshal(sm)
		w.Write(append(b, '\n'))
	}
	if err := w.Flush(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, s.Path)
}

// Windows are the periods the dashboard offers, with their point size.
var Windows = map[string]struct{ Span, Step time.Duration }{
	"1h":  {time.Hour, time.Minute},
	"24h": {24 * time.Hour, 15 * time.Minute},
	"7d":  {7 * 24 * time.Hour, 2 * time.Hour},
}

// IfSeries is one interface's throughput over a window.
type IfSeries struct {
	Name     string    `json:"name"`
	In       []float64 `json:"in"`  // bits per second, per point
	Out      []float64 `json:"out"` // bits per second, per point
	InBytes  int64     `json:"in_bytes"`
	OutBytes int64     `json:"out_bytes"`
	PeakBps  float64   `json:"peak_bps"` // highest in+out point
}

// Top is an application's or host's total over a window.
type Top struct {
	Name    string `json:"name"`
	Bytes   int64  `json:"bytes"`
	Flows   int64  `json:"connections"`
	Threats int    `json:"threats,omitempty"` // hosts: IPS matches from it
}

// Sig is a signature's matches over a window.
type Sig struct {
	SID       int    `json:"sid"`
	Signature string `json:"signature"`
	Severity  string `json:"severity"`
	Count     int    `json:"count"`
}

// Threats is the IPS view of a window.
type Threats struct {
	Series  map[string][]int `json:"series"` // severity: matches per point
	Blocked int              `json:"blocked"`
	Alerted int              `json:"alerted"`
	Top     []Sig            `json:"top"`
}

// Report is a window's worth of statistics for the dashboard.
type Report struct {
	Window     string     `json:"window"`
	Step       int        `json:"step"`    // seconds per point
	Times      []int64    `json:"times"`   // each point's start (Unix)
	Covered    []int      `json:"covered"` // minute samples in each point (0: no data, a gap)
	Samples    int        `json:"samples"`
	Interfaces []IfSeries `json:"interfaces"`
	Apps       []Top      `json:"apps"`
	Hosts      []Top      `json:"hosts"`
	Threats    Threats    `json:"threats"`
}

// Severities in the order the dashboard stacks them.
var Severities = []string{"critical", "major", "minor", "informational"}

// Window summarises the samples in a window ("1h", "24h" or "7d").
func (s *Store) Window(name string) (Report, error) {
	w, ok := Windows[name]
	if !ok {
		return Report{}, fmt.Errorf("window must be 1h, 24h or 7d")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	n := int(w.Span / w.Step)
	step := int64(w.Step / time.Second)
	end := s.now().Unix()
	// Points end at the current step boundary, so they don't shift every
	// minute.
	end = (end/step + 1) * step
	start := end - int64(n)*step
	r := Report{Window: name, Step: int(step), Times: make([]int64, n), Interfaces: []IfSeries{}, Apps: []Top{}, Hosts: []Top{},
		Threats: Threats{Series: map[string][]int{}, Top: []Sig{}}}
	r.Covered = make([]int, n)
	for i := range r.Times {
		r.Times[i] = start + int64(i)*step
	}
	for _, sev := range Severities {
		r.Threats.Series[sev] = make([]int, n)
	}
	ifs := map[string]*IfSeries{}
	apps, hosts := map[string]*Top{}, map[string]*Top{}
	sigs := map[int]int{}
	for _, sm := range s.samples {
		// A sample covers the minute before its time.
		t := sm.T - 1
		if t < start || t >= end {
			continue
		}
		r.Samples++
		i := int((t - start) / step)
		r.Covered[i]++
		for k, v := range sm.If {
			is := ifs[k]
			if is == nil {
				is = &IfSeries{Name: k, In: make([]float64, n), Out: make([]float64, n)}
				ifs[k] = is
			}
			is.In[i] += float64(v[0])
			is.Out[i] += float64(v[1])
			is.InBytes += v[0]
			is.OutBytes += v[1]
		}
		add := func(m map[string]*Top, k string, v Pair) {
			t := m[k]
			if t == nil {
				t = &Top{Name: k}
				m[k] = t
			}
			t.Bytes += v[0]
			t.Flows += v[1]
		}
		for k, v := range sm.Apps {
			add(apps, k, v)
		}
		for k, v := range sm.Hosts {
			add(hosts, k, v)
		}
		for sev, c := range sm.Threats {
			if ser, ok := r.Threats.Series[sev]; ok {
				ser[i] += c[0] + c[1]
			}
			r.Threats.Blocked += c[0]
			r.Threats.Alerted += c[1]
		}
		for sid, c := range sm.Sigs {
			sigs[sid] += c
		}
		for ip, c := range sm.TSrc {
			t := hosts[ip]
			if t == nil {
				t = &Top{Name: ip}
				hosts[ip] = t
			}
			t.Threats += c
		}
	}
	for _, is := range ifs {
		// Bytes to bits per second over the minutes sampled (a point still
		// filling, or with samples missing, isn't diluted).
		for i := range is.In {
			if c := r.Covered[i]; c > 0 {
				is.In[i] = is.In[i] * 8 / float64(c*60)
				is.Out[i] = is.Out[i] * 8 / float64(c*60)
			}
		}
		for i := range is.In {
			if v := is.In[i] + is.Out[i]; v > is.PeakBps {
				is.PeakBps = v
			}
		}
		r.Interfaces = append(r.Interfaces, *is)
	}
	sort.Slice(r.Interfaces, func(i, j int) bool { return ifOrder(r.Interfaces[i].Name) < ifOrder(r.Interfaces[j].Name) })
	r.Apps = topN(apps, 10)
	r.Hosts = topN(hosts, 10)
	for sid, c := range sigs {
		info := s.sigs[sid]
		r.Threats.Top = append(r.Threats.Top, Sig{SID: sid, Signature: info.Signature, Severity: info.Severity, Count: c})
	}
	sort.Slice(r.Threats.Top, func(i, j int) bool {
		a, b := r.Threats.Top[i], r.Threats.Top[j]
		if a.Count != b.Count {
			return a.Count > b.Count
		}
		return a.SID < b.SID
	})
	if len(r.Threats.Top) > 5 {
		r.Threats.Top = r.Threats.Top[:5]
	}
	return r, nil
}

// ifOrder sorts inside, then outside, then the rest by name.
func ifOrder(name string) string {
	switch name {
	case "inside":
		return "0"
	case "outside":
		return "1"
	}
	return "2" + name
}

func topN(m map[string]*Top, n int) []Top {
	out := make([]Top, 0, len(m))
	for _, t := range m {
		if t.Bytes > 0 || t.Flows > 0 || t.Threats > 0 {
			out = append(out, *t)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Bytes != out[j].Bytes {
			return out[i].Bytes > out[j].Bytes
		}
		if out[i].Threats != out[j].Threats {
			return out[i].Threats > out[j].Threats
		}
		return out[i].Name < out[j].Name
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// ReadInterfaces reads rx/tx byte counters from sysfs (root "/" on the
// appliance) for the named interfaces; missing ones are left out.
func ReadInterfaces(root string, names []string) map[string]Pair {
	out := map[string]Pair{}
	for _, n := range names {
		var p Pair
		ok := true
		for i, f := range []string{"rx_bytes", "tx_bytes"} {
			b, err := os.ReadFile(filepath.Join(root, "sys/class/net", n, "statistics", f))
			if err != nil {
				ok = false
				break
			}
			fmt.Sscan(strings.TrimSpace(string(b)), &p[i])
		}
		if ok {
			out[n] = p
		}
	}
	return out
}
