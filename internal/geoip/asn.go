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
	"unicode"
)

// ASNSource names the AS database: DB-IP's free "IP to ASN Lite" (CC BY
// 4.0, the same attribution as the country data).
const ASNSource = "dbip-asn-lite"

// Strict validation of a downloaded AS month: the full database has about
// 410,000 IPv4 rows and 80,000 ASes.
var (
	MinASNRows = 200000
	MinASNs    = 10000
)

// ASNDB maps IPv4 addresses to autonomous systems.
type ASNDB struct {
	meta  Meta
	index []asnRange // sorted by start, merged where the same AS continues
	names map[uint32]string
}

type asnRange struct {
	Range
	asn uint32
}

// Meta returns the database's description.
func (db *ASNDB) Meta() Meta { return db.meta }

// SetMeta fills in where a database came from.
func (db *ASNDB) SetMeta(month, origin string, installed time.Time) {
	db.meta.Month, db.meta.Origin, db.meta.Installed = month, origin, installed.UTC()
}

// Lookup returns the AS number and organisation of an IPv4 address (0, ""
// if none).
func (db *ASNDB) Lookup(a netip.Addr) (uint32, string) {
	if db == nil || !a.Is4() {
		return 0, ""
	}
	v := ip2u(a)
	i := sort.Search(len(db.index), func(i int) bool { return db.index[i].Start > v }) - 1
	if i >= 0 && db.index[i].End >= v {
		asn := db.index[i].asn
		return asn, db.names[asn]
	}
	return 0, ""
}

// ASNs is how many ASes the database names.
func (db *ASNDB) ASNs() int {
	if db == nil {
		return 0
	}
	return len(db.names)
}

func buildASN(rs []asnRange, names map[uint32]string, meta Meta) *ASNDB {
	sort.Slice(rs, func(i, j int) bool { return rs[i].Start < rs[j].Start })
	var merged []asnRange
	for _, r := range rs {
		if n := len(merged); n > 0 && merged[n-1].asn == r.asn && merged[n-1].End != ^uint32(0) && r.Start <= merged[n-1].End+1 {
			if r.End > merged[n-1].End {
				merged[n-1].End = r.End
			}
			continue
		}
		merged = append(merged, r)
	}
	meta.ASNs = len(names)
	return &ASNDB{meta: meta, index: merged, names: names}
}

// cleanOrg keeps an organisation name printable and short: it ends up in
// log lines, CEF and syslog.
func cleanOrg(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == '\t' {
			return ' '
		}
		return r
	}, strings.TrimSpace(s))
	if len(s) > 120 {
		s = s[:120]
	}
	return s
}

// ParseASN reads a DB-IP ASN CSV ("start,end,asn,org"), gzipped or not.
// IPv6 rows are skipped; strict applies the size checks for a full
// database (a download).
func ParseASN(r io.Reader, strict bool) (*ASNDB, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	in, err := maybeGunzip(data)
	if err != nil {
		return nil, err
	}
	cr := csv.NewReader(bufio.NewReader(in))
	cr.FieldsPerRecord = -1
	var rs []asnRange
	names := map[uint32]string{}
	rows := 0
	for line := 1; ; line++ {
		rec, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("asn: line %d: %w", line, err)
		}
		if len(rec) < 4 {
			return nil, fmt.Errorf("asn: line %d: want start,end,asn,org", line)
		}
		if strings.Contains(rec[0], ":") {
			continue // IPv6
		}
		a, err1 := netip.ParseAddr(strings.TrimSpace(rec[0]))
		b, err2 := netip.ParseAddr(strings.TrimSpace(rec[1]))
		if err1 != nil || err2 != nil || !a.Is4() || !b.Is4() || ip2u(b) < ip2u(a) {
			return nil, fmt.Errorf("asn: line %d: bad range %q-%q", line, rec[0], rec[1])
		}
		n, err := strconv.ParseUint(strings.TrimPrefix(strings.TrimSpace(rec[2]), "AS"), 10, 32)
		if err != nil || n == 0 {
			return nil, fmt.Errorf("asn: line %d: bad AS number %q", line, rec[2])
		}
		asn := uint32(n)
		if _, ok := names[asn]; !ok {
			names[asn] = cleanOrg(rec[3])
		}
		rs = append(rs, asnRange{Range{ip2u(a), ip2u(b)}, asn})
		rows++
	}
	if rows == 0 {
		return nil, errors.New("asn: no IPv4 rows")
	}
	if strict && (rows < MinASNRows || len(names) < MinASNs) {
		return nil, fmt.Errorf("asn: %d IPv4 rows for %d ASes: not a complete database", rows, len(names))
	}
	return buildASN(rs, names, Meta{Source: ASNSource, SHA256: hex.EncodeToString(sum[:]), Rows: rows}), nil
}

// maybeGunzip returns a reader of data, gunzipping it if it is gzip.
func maybeGunzip(data []byte) (io.Reader, error) {
	if len(data) > 2 && data[0] == 0x1f && data[1] == 0x8b {
		gz, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("geoip: %w", err)
		}
		return gz, nil
	}
	return bytes.NewReader(data), nil
}

// IsASNCSV reports whether data (gzipped or not) looks like an ASN CSV
// (four columns) rather than a country one (three).
func IsASNCSV(data []byte) bool {
	in, err := maybeGunzip(data)
	if err != nil {
		return false
	}
	cr := csv.NewReader(bufio.NewReader(in))
	cr.FieldsPerRecord = -1
	rec, err := cr.Read()
	return err == nil && len(rec) >= 4
}

// AS database files, beside the country ones.
const (
	asnFile      = "asn-v4.txt.gz"
	asnNamesFile = "asn-names.txt.gz"
	asnMetaFile  = "asn-meta.json"
)

// Save writes the database to dir atomically (data first, meta last).
func (db *ASNDB) Save(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	ranges, err := gzLines(func(w *bufio.Writer) {
		for _, r := range db.index {
			fmt.Fprintf(w, "%d %d %d\n", r.Start, r.End, r.asn)
		}
	})
	if err != nil {
		return err
	}
	asns := make([]uint32, 0, len(db.names))
	for a := range db.names {
		asns = append(asns, a)
	}
	sort.Slice(asns, func(i, j int) bool { return asns[i] < asns[j] })
	names, err := gzLines(func(w *bufio.Writer) {
		for _, a := range asns {
			fmt.Fprintf(w, "%d\t%s\n", a, db.names[a])
		}
	})
	if err != nil {
		return err
	}
	if err := writeAtomic(filepath.Join(dir, asnFile), ranges); err != nil {
		return err
	}
	if err := writeAtomic(filepath.Join(dir, asnNamesFile), names); err != nil {
		return err
	}
	m, _ := json.MarshalIndent(db.meta, "", "  ")
	return writeAtomic(filepath.Join(dir, asnMetaFile), append(m, '\n'))
}

func gzLines(write func(*bufio.Writer)) ([]byte, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	w := bufio.NewWriter(gz)
	write(w)
	if err := w.Flush(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func readGzLines(path string, each func(string) error) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	sc := bufio.NewScanner(gz)
	for sc.Scan() {
		if err := each(sc.Text()); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
	}
	return sc.Err()
}

// ReadASNMeta reads only the AS database's description in dir.
func ReadASNMeta(dir string) (Meta, error) {
	var m Meta
	data, err := os.ReadFile(filepath.Join(dir, asnMetaFile))
	if err != nil {
		return m, err
	}
	return m, json.Unmarshal(data, &m)
}

// LoadASN reads an AS database saved by Save.
func LoadASN(dir string) (*ASNDB, error) {
	meta, err := ReadASNMeta(dir)
	if err != nil {
		return nil, err
	}
	var rs []asnRange
	err = readGzLines(filepath.Join(dir, asnFile), func(l string) error {
		fl := strings.Fields(l)
		if len(fl) != 3 {
			return fmt.Errorf("bad line %q", l)
		}
		a, err1 := strconv.ParseUint(fl[0], 10, 32)
		b, err2 := strconv.ParseUint(fl[1], 10, 32)
		n, err3 := strconv.ParseUint(fl[2], 10, 32)
		if err1 != nil || err2 != nil || err3 != nil || b < a {
			return fmt.Errorf("bad line %q", l)
		}
		rs = append(rs, asnRange{Range{uint32(a), uint32(b)}, uint32(n)})
		return nil
	})
	if err != nil {
		return nil, err
	}
	names := map[uint32]string{}
	err = readGzLines(filepath.Join(dir, asnNamesFile), func(l string) error {
		a, org, ok := strings.Cut(l, "\t")
		n, err := strconv.ParseUint(a, 10, 32)
		if !ok || err != nil {
			return fmt.Errorf("bad line %q", l)
		}
		names[uint32(n)] = org
		return nil
	})
	if err != nil {
		return nil, err
	}
	return buildASN(rs, names, meta), nil
}

// CurrentASN loads the AS database in use (nil, nil when there is none):
// the newer month of the shipped and local copies, the local one on a tie.
func (s Store) CurrentASN() (*ASNDB, error) {
	dir := s.newerDir(ReadASNMeta)
	if dir == "" {
		return nil, nil
	}
	return LoadASN(dir)
}

// CurrentASNMeta describes the AS database in use without loading it.
func (s Store) CurrentASNMeta() (Meta, bool) {
	dir := s.newerDir(ReadASNMeta)
	if dir == "" {
		return Meta{}, false
	}
	m, err := ReadASNMeta(dir)
	return m, err == nil
}

// InstallASN saves db as the local AS database.
func (s Store) InstallASN(db *ASNDB) error { return db.Save(s.Local) }
