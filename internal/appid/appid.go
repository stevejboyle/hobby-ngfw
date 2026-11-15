// Package appid is App Identification's application catalog (the nDPI build's, embedded
// so the compiler, validation and UI use the same IDs as appidd) and reads
// the per-application counters appidd writes every 10 seconds.
package appid

import (
	_ "embed"
	"encoding/json"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// Paths on the appliance.
const (
	CatalogPath = "/usr/share/sjb-os/appid/catalog.json"
	StatsPath   = "/run/appidd/stats.json"
)

// Unknown is the application name for connections App Identification couldn't
// identify (nDPI gave up): app ID 0 with classification done.
const Unknown = "unknown"

//go:embed catalog.json
var catalogJSON []byte

var (
	loadOnce sync.Once
	apps     []App
	byName   map[string]App
)

// catalog parses the embedded catalog once. Safe for concurrent use: the
// web UI asks for the catalog and its categories in parallel.
func catalog() []App {
	loadOnce.Do(func() {
		var all []App
		if err := json.Unmarshal(catalogJSON, &all); err != nil {
			panic("appid: embedded catalog: " + err.Error())
		}
		m := make(map[string]App, len(all))
		for _, a := range all {
			m[strings.ToLower(a.Name)] = a
		}
		apps, byName = all, m
	})
	return apps
}

// ByID returns the catalog application with nDPI ID id.
func ByID(id int) (App, bool) {
	for _, a := range catalog() {
		if a.ID == id {
			return a, true
		}
	}
	return App{}, false
}

// Lookup finds an application by name, ignoring case. "unknown" is not in
// the catalog: callers handle it (it's ID 0).
func Lookup(name string) (App, bool) {
	catalog()
	a, ok := byName[strings.ToLower(name)]
	return a, ok
}

// Names lists every application's name, lower-cased, sorted, plus "unknown".
func Names() []string {
	out := []string{Unknown}
	for _, a := range catalog() {
		out = append(out, strings.ToLower(a.Name))
	}
	sort.Strings(out[1:])
	return out
}

// CategoryPrefix marks a category in an application list:
// "category:video" means every application in nDPI's Video category.
const CategoryPrefix = "category:"

// Category is one of nDPI's application categories.
type Category struct {
	Name string `json:"name"` // as nDPI spells it, e.g. SocialNetwork
	Ref  string `json:"ref"`  // as rules write it, e.g. category:socialnetwork
	Apps int    `json:"apps"` // how many applications it holds
}

// Categories lists the catalog's categories, by name.
func Categories() []Category {
	count := map[string]int{}
	for _, a := range catalog() {
		count[a.Category]++
	}
	var out []Category
	for name, n := range count {
		if name == "" {
			continue
		}
		out = append(out, Category{Name: name, Ref: CategoryPrefix + strings.ToLower(name), Apps: n})
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out
}

// CategoryApps returns the applications of a category reference
// ("category:video", any case); ok is false if it isn't one.
func CategoryApps(ref string) (apps []App, ok bool) {
	name, isCat := strings.CutPrefix(strings.ToLower(ref), CategoryPrefix)
	if !isCat || name == "" {
		return nil, false
	}
	for _, a := range catalog() {
		if strings.ToLower(a.Category) == name {
			apps = append(apps, a)
		}
	}
	return apps, len(apps) > 0
}

// App is one application nDPI knows.
type App struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	Category string `json:"category"`
}

// Seen is an application seen in traffic since appidd started.
type Seen struct {
	App
	Flows    int64     `json:"flows"`
	Bytes    int64     `json:"bytes"`
	LastSeen time.Time `json:"last_seen"`
}

// Status is the apps view: whether App Identification runs, and what it has seen.
type Status struct {
	Enabled     bool      `json:"enabled"`           // system app_id on
	Running     bool      `json:"running"`           // appidd wrote its stats recently
	Updated     time.Time `json:"updated,omitempty"` // when it last did
	ActiveFlows int       `json:"active_flows"`      // flows being classified now
	Apps        []Seen    `json:"apps"`              // by bytes, most first
	Note        string    `json:"note,omitempty"`    // why the list may be empty
}

// Source reads the catalog and stats files.
type Source struct {
	StatsFile string // default StatsPath
	Now       func() time.Time
}

func (s Source) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Catalog returns the applications whose name or category contains q
// (any case), by name.
func (s Source) Catalog(q string) ([]App, error) {
	q = strings.ToLower(q)
	out := []App{}
	for _, a := range catalog() {
		if q == "" || strings.Contains(strings.ToLower(a.Name), q) || strings.Contains(strings.ToLower(a.Category), q) {
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out, nil
}

// Counter is a running total from appidd: an application (by name) or a
// source host (by address).
type Counter struct {
	Key          string
	Bytes, Flows int64
}

// Counters reads appidd's running totals per application and per source
// host (nil when appidd hasn't written any).
func (s Source) Counters() (apps, hosts []Counter) {
	path := s.StatsFile
	if path == "" {
		path = StatsPath
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil
	}
	var raw struct {
		Apps []struct {
			Name  string `json:"name"`
			Flows int64  `json:"flows"`
			Bytes int64  `json:"bytes"`
		} `json:"apps"`
		Hosts []struct {
			IP    string `json:"ip"`
			Flows int64  `json:"flows"`
			Bytes int64  `json:"bytes"`
		} `json:"hosts"`
	}
	if json.Unmarshal(b, &raw) != nil {
		return nil, nil
	}
	for _, a := range raw.Apps {
		apps = append(apps, Counter{a.Name, a.Bytes, a.Flows})
	}
	for _, h := range raw.Hosts {
		hosts = append(hosts, Counter{h.IP, h.Bytes, h.Flows})
	}
	return apps, hosts
}

// Seen reads appidd's counters. enabled is the config's app_id switch.
func (s Source) Seen(enabled bool) Status {
	st := Status{Enabled: enabled, Apps: []Seen{}}
	path := s.StatsFile
	if path == "" {
		path = StatsPath
	}
	b, err := os.ReadFile(path)
	if err != nil {
		switch {
		case !enabled:
			st.Note = "App Identification is off (set system app-identification on)"
		default:
			st.Note = "appidd isn't running yet (an upgrade installs it in the background; root: systemctl status appidd)"
		}
		return st
	}
	var raw struct {
		Updated     int64 `json:"updated"`
		ActiveFlows int   `json:"active_flows"`
		Apps        []struct {
			App
			Flows    int64 `json:"flows"`
			Bytes    int64 `json:"bytes"`
			LastSeen int64 `json:"last_seen"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		st.Note = "appidd's statistics are unreadable: " + err.Error()
		return st
	}
	st.Updated = time.Unix(raw.Updated, 0)
	st.Running = s.now().Sub(st.Updated) < 30*time.Second
	st.ActiveFlows = raw.ActiveFlows
	for _, a := range raw.Apps {
		st.Apps = append(st.Apps, Seen{App: a.App, Flows: a.Flows, Bytes: a.Bytes, LastSeen: time.Unix(a.LastSeen, 0)})
	}
	sort.SliceStable(st.Apps, func(i, j int) bool { return st.Apps[i].Bytes > st.Apps[j].Bytes })
	switch {
	case !enabled:
		st.Note = "App Identification is off (set system app-identification on); these counts are from before"
	case !st.Running:
		st.Note = "appidd stopped updating its statistics (root: systemctl status appidd)"
	case len(st.Apps) == 0:
		st.Note = "no connections have finished since appidd started"
	}
	return st
}
