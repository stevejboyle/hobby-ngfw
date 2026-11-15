// Package tags is the tag → IP registry behind dynamic address groups.
// It is the source of truth for registrations; nftables sets mirror it.
// Registrations persist to a JSON file so they survive a restart.
package tags

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"time"
)

var tagRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$`)

// Entry is one IP registered with one tag.
type Entry struct {
	IP      netip.Addr `json:"ip"`
	Tag     string     `json:"tag"`
	Expires time.Time  `json:"expires,omitempty"` // zero = never
}

// Remaining returns the time left before expiry, or 0 for no expiry.
func (e Entry) Remaining(now time.Time) time.Duration {
	if e.Expires.IsZero() {
		return 0
	}
	return e.Expires.Sub(now)
}

// Registry holds registrations keyed by tag then IP.
type Registry struct {
	mu   sync.Mutex
	path string
	m    map[string]map[netip.Addr]Entry
}

// Open loads the registry from path, or starts empty if it does not exist.
func Open(path string) (*Registry, error) {
	r := &Registry{path: path, m: map[string]map[netip.Addr]Entry{}}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return r, nil
	}
	if err != nil {
		return nil, err
	}
	var es []Entry
	if err := json.Unmarshal(b, &es); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	for _, e := range es {
		r.put(e)
	}
	return r, nil
}

// Validate checks an IP and tag before registration.
func Validate(ip netip.Addr, tag string) error {
	if !ip.IsValid() || !ip.Is4() {
		return fmt.Errorf("invalid IPv4 address %q", ip)
	}
	if !tagRE.MatchString(tag) {
		return fmt.Errorf("invalid tag %q", tag)
	}
	return nil
}

// Register adds or refreshes ip on each tag. ttl 0 means no expiry.
func (r *Registry) Register(ip netip.Addr, tags []string, ttl time.Duration, now time.Time) error {
	for _, t := range tags {
		if err := Validate(ip, t); err != nil {
			return err
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, t := range tags {
		e := Entry{IP: ip, Tag: t}
		if ttl > 0 {
			e.Expires = now.Add(ttl)
		}
		r.put(e)
	}
	return r.save(now)
}

// Unregister removes ip from each tag. Missing entries are not an error.
func (r *Registry) Unregister(ip netip.Addr, tags []string, now time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, t := range tags {
		delete(r.m[t], ip)
		if len(r.m[t]) == 0 {
			delete(r.m, t)
		}
	}
	return r.save(now)
}

// List returns live entries, optionally for one tag, sorted by tag then IP.
func (r *Registry) List(tag string, now time.Time) []Entry {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []Entry
	for t, ips := range r.m {
		if tag != "" && t != tag {
			continue
		}
		for _, e := range ips {
			if live(e, now) {
				out = append(out, e)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Tag != out[j].Tag {
			return out[i].Tag < out[j].Tag
		}
		return out[i].IP.Less(out[j].IP)
	})
	return out
}

func live(e Entry, now time.Time) bool {
	return e.Expires.IsZero() || e.Expires.After(now)
}

func (r *Registry) put(e Entry) {
	if r.m[e.Tag] == nil {
		r.m[e.Tag] = map[netip.Addr]Entry{}
	}
	r.m[e.Tag][e.IP] = e
}

// save prunes expired entries and writes the file. Caller holds mu.
func (r *Registry) save(now time.Time) error {
	var es []Entry
	for t, ips := range r.m {
		for ip, e := range ips {
			if !live(e, now) {
				delete(ips, ip)
				continue
			}
			es = append(es, e)
		}
		if len(ips) == 0 {
			delete(r.m, t)
		}
	}
	sort.Slice(es, func(i, j int) bool {
		if es[i].Tag != es[j].Tag {
			return es[i].Tag < es[j].Tag
		}
		return es[i].IP.Less(es[j].IP)
	})
	b, _ := json.MarshalIndent(es, "", "  ")
	tmp, err := os.CreateTemp(filepath.Dir(r.path), ".tags-*")
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
	return os.Rename(tmp.Name(), r.path)
}
