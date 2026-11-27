// Package geoip maps IPv4 addresses to countries for geo-blocking rules.
// The data is DB-IP's free "IP to Country Lite" database (CC BY 4.0:
// "IP Geolocation by DB-IP", https://db-ip.com), converted to a compact
// file of merged ranges per country. A copy ships with SJB-OS; the
// appliance refreshes it monthly from DB-IP.
package geoip

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Attribution is the credit DB-IP's licence (CC BY 4.0) asks for wherever
// the data is shown.
const Attribution = "IP Geolocation by DB-IP (https://db-ip.com), CC BY 4.0"

// Source names the database.
const Source = "dbip-country-lite"

// Strict validation of a downloaded month: the full database has about
// 360,000 IPv4 rows and 246 countries.
var (
	MinRows      = 200000
	MinCountries = 200
)

// Range is an inclusive IPv4 range, as 32-bit numbers.
type Range struct{ Start, End uint32 }

// String is "a.b.c.d-e.f.g.h" (nftables interval syntax).
func (r Range) String() string {
	if r.Start == r.End {
		return u2ip(r.Start).String()
	}
	return u2ip(r.Start).String() + "-" + u2ip(r.End).String()
}

func u2ip(v uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

func ip2u(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// Meta describes a database.
type Meta struct {
	Source    string    `json:"source"`
	Month     string    `json:"month"`  // YYYY-MM of DB-IP's release
	Origin    string    `json:"origin"` // shipped, downloaded or imported
	SHA256    string    `json:"sha256"` // of the DB-IP file it came from
	Rows      int       `json:"rows"`   // IPv4 rows in that file
	Countries int       `json:"countries"`
	Installed time.Time `json:"installed"`
}

// DB is a loaded database.
type DB struct {
	meta   Meta
	ranges map[string][]Range // per country, sorted, merged
	index  []indexed          // every range, sorted by start, for Lookup
}

type indexed struct {
	Range
	cc string
}

// Meta returns the database's description.
func (db *DB) Meta() Meta { return db.meta }

// Ranges returns a country's ranges (nil if it has none).
func (db *DB) Ranges(cc string) []Range {
	if db == nil {
		return nil
	}
	return db.ranges[strings.ToUpper(cc)]
}

// Countries returns how many ranges each country has.
func (db *DB) Countries() map[string]int {
	out := map[string]int{}
	if db == nil {
		return out
	}
	for cc, rs := range db.ranges {
		out[cc] = len(rs)
	}
	return out
}

// Lookup returns the country of an IPv4 address ("" if none).
func (db *DB) Lookup(a netip.Addr) string {
	if db == nil || !a.Is4() {
		return ""
	}
	v := ip2u(a)
	i := sort.Search(len(db.index), func(i int) bool { return db.index[i].Start > v }) - 1
	if i >= 0 && db.index[i].End >= v {
		return db.index[i].cc
	}
	return ""
}

func build(raw map[string][]Range, meta Meta) *DB {
	db := &DB{meta: meta, ranges: map[string][]Range{}}
	for cc, rs := range raw {
		sort.Slice(rs, func(i, j int) bool { return rs[i].Start < rs[j].Start })
		var merged []Range
		for _, r := range rs {
			if n := len(merged); n > 0 && (merged[n-1].End == ^uint32(0) || r.Start <= merged[n-1].End+1) {
				if r.End > merged[n-1].End {
					merged[n-1].End = r.End
				}
				continue
			}
			merged = append(merged, r)
		}
		db.ranges[cc] = merged
		for _, r := range merged {
			db.index = append(db.index, indexed{r, cc})
		}
	}
	sort.Slice(db.index, func(i, j int) bool { return db.index[i].Start < db.index[j].Start })
	db.meta.Countries = len(db.ranges)
	return db
}

// Parse reads a DB-IP country CSV ("start,end,country"), gzipped or not.
// IPv6 rows are skipped. strict applies the size checks for a full
// database (a download); an import may be partial.
func Parse(r io.Reader, strict bool) (*DB, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	var in io.Reader = bytes.NewReader(data)
	if len(data) > 2 && data[0] == 0x1f && data[1] == 0x8b {
		gz, err := gzip.NewReader(in)
		if err != nil {
			return nil, fmt.Errorf("geoip: %w", err)
		}
		in = gz
	}
	cr := csv.NewReader(bufio.NewReader(in))
	cr.FieldsPerRecord = -1
	cr.ReuseRecord = true
	raw := map[string][]Range{}
	rows := 0
	for line := 1; ; line++ {
		rec, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("geoip: line %d: %w", line, err)
		}
		if len(rec) < 3 {
			return nil, fmt.Errorf("geoip: line %d: want start,end,country", line)
		}
		if strings.Contains(rec[0], ":") {
			continue // IPv6
		}
		a, err1 := netip.ParseAddr(strings.TrimSpace(rec[0]))
		b, err2 := netip.ParseAddr(strings.TrimSpace(rec[1]))
		cc := strings.ToUpper(strings.TrimSpace(rec[2]))
		if err1 != nil || err2 != nil || !a.Is4() || !b.Is4() || ip2u(b) < ip2u(a) {
			return nil, fmt.Errorf("geoip: line %d: bad range %q-%q", line, rec[0], rec[1])
		}
		if len(cc) != 2 || cc[0] < 'A' || cc[0] > 'Z' || cc[1] < 'A' || cc[1] > 'Z' {
			return nil, fmt.Errorf("geoip: line %d: bad country %q", line, rec[2])
		}
		raw[cc] = append(raw[cc], Range{ip2u(a), ip2u(b)})
		rows++
	}
	if rows == 0 {
		return nil, errors.New("geoip: no IPv4 rows")
	}
	if strict {
		if rows < MinRows || len(raw) < MinCountries || len(raw["US"]) == 0 {
			return nil, fmt.Errorf("geoip: %d IPv4 rows in %d countries: not a complete database", rows, len(raw))
		}
	}
	return build(raw, Meta{Source: Source, SHA256: hex.EncodeToString(sum[:]), Rows: rows}), nil
}

// File names in a database directory.
const (
	dataFile = "countries-v4.txt.gz"
	metaFile = "meta.json"
)

// Save writes the database to dir atomically.
func (db *DB) Save(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	w := bufio.NewWriter(gz)
	ccs := make([]string, 0, len(db.ranges))
	for cc := range db.ranges {
		ccs = append(ccs, cc)
	}
	sort.Strings(ccs)
	for _, cc := range ccs {
		for _, r := range db.ranges[cc] {
			fmt.Fprintf(w, "%s %d %d\n", cc, r.Start, r.End)
		}
	}
	if err := w.Flush(); err != nil {
		return err
	}
	if err := gz.Close(); err != nil {
		return err
	}
	if err := writeAtomic(filepath.Join(dir, dataFile), buf.Bytes()); err != nil {
		return err
	}
	m, _ := json.MarshalIndent(db.meta, "", "  ")
	return writeAtomic(filepath.Join(dir, metaFile), append(m, '\n'))
}

func writeAtomic(path string, data []byte) error {
	tmp := path + ".new"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ReadMeta reads only a directory's description.
func ReadMeta(dir string) (Meta, error) {
	var m Meta
	data, err := os.ReadFile(filepath.Join(dir, metaFile))
	if err != nil {
		return m, err
	}
	return m, json.Unmarshal(data, &m)
}

// Load reads a database saved by Save.
func Load(dir string) (*DB, error) {
	meta, err := ReadMeta(dir)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(filepath.Join(dir, dataFile))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("geoip %s: %w", dir, err)
	}
	raw := map[string][]Range{}
	sc := bufio.NewScanner(gz)
	for sc.Scan() {
		fl := strings.Fields(sc.Text())
		if len(fl) != 3 {
			return nil, fmt.Errorf("geoip %s: bad line %q", dir, sc.Text())
		}
		a, err1 := strconv.ParseUint(fl[1], 10, 32)
		b, err2 := strconv.ParseUint(fl[2], 10, 32)
		if err1 != nil || err2 != nil || b < a {
			return nil, fmt.Errorf("geoip %s: bad line %q", dir, sc.Text())
		}
		raw[fl[0]] = append(raw[fl[0]], Range{uint32(a), uint32(b)})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("geoip %s: %w", dir, err)
	}
	return build(raw, meta), nil
}

// Store is where databases live: the copy shipped with SJB-OS and the one
// downloaded or imported on the appliance. The newer month wins (the local
// one on a tie).
type Store struct {
	Shipped string // usr/share/sjb-os/geoip
	Local   string // var/lib/sjb-os/geoip
}

// Current loads the database in use (nil, nil when there is none).
func (s Store) Current() (*DB, error) {
	dir := s.currentDir()
	if dir == "" {
		return nil, nil
	}
	return Load(dir)
}

// CurrentMeta describes the database in use without loading it.
func (s Store) CurrentMeta() (Meta, bool) {
	dir := s.currentDir()
	if dir == "" {
		return Meta{}, false
	}
	m, err := ReadMeta(dir)
	return m, err == nil
}

func (s Store) currentDir() string {
	sm, serr := ReadMeta(s.Shipped)
	lm, lerr := ReadMeta(s.Local)
	switch {
	case serr != nil && lerr != nil:
		return ""
	case lerr != nil:
		return s.Shipped
	case serr != nil:
		return s.Local
	case sm.Month > lm.Month:
		return s.Shipped
	}
	return s.Local
}

// Install saves db as the local database.
func (s Store) Install(db *DB) error { return db.Save(s.Local) }

// SetMeta fills in where a database came from.
func (db *DB) SetMeta(month, origin string, installed time.Time) {
	db.meta.Month, db.meta.Origin, db.meta.Installed = month, origin, installed.UTC()
}
