package geoip

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const sample = `1.0.0.0,1.0.0.255,AU
1.0.1.0,1.0.3.255,CN
1.0.4.0,1.0.7.255,AU
1.0.8.0,1.0.8.255,AU
2001:200::,2001:200:ffff:ffff:ffff:ffff:ffff:ffff,JP
5.0.0.0,5.0.0.0,US
8.8.8.0,8.8.8.255,US
255.255.255.0,255.255.255.255,ZZ
`

func gz(s string) []byte {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	w.Write([]byte(s))
	w.Close()
	return b.Bytes()
}

func TestParseMergeLookup(t *testing.T) {
	for _, in := range [][]byte{[]byte(sample), gz(sample)} {
		db, err := Parse(bytes.NewReader(in), false)
		if err != nil {
			t.Fatal(err)
		}
		if m := db.Meta(); m.Rows != 7 || m.Countries != 4 || len(m.SHA256) != 64 {
			t.Errorf("meta %+v (IPv6 rows skipped: want 7 IPv4 rows)", m)
		}
		au := db.Ranges("au")
		if len(au) != 2 || au[0].String() != "1.0.0.0-1.0.0.255" || au[1].String() != "1.0.4.0-1.0.8.255" {
			t.Errorf("AU %v: adjacent ranges must merge, separate ones stay", au)
		}
		if us := db.Ranges("US"); len(us) != 2 || us[0].String() != "5.0.0.0" {
			t.Errorf("US %v", us)
		}
		for ip, want := range map[string]string{"1.0.2.7": "CN", "1.0.0.0": "AU", "1.0.8.255": "AU", "1.0.9.0": "", "8.8.8.8": "US", "10.0.0.1": "", "255.255.255.255": "ZZ"} {
			if got := db.Lookup(netip.MustParseAddr(ip)); got != want {
				t.Errorf("Lookup(%s) = %q, want %q", ip, got, want)
			}
		}
		if db.Lookup(netip.MustParseAddr("2001:200::1")) != "" {
			t.Error("IPv6 lookup must find nothing")
		}
	}
}

func TestParseRejects(t *testing.T) {
	for name, in := range map[string]string{
		"empty":       "",
		"ipv6 only":   "2001::,2001::ff,JP\n",
		"bad address": "1.0.0,1.0.0.255,AU\n",
		"reversed":    "1.0.0.255,1.0.0.0,AU\n",
		"bad country": "1.0.0.0,1.0.0.255,Australia\n",
		"short row":   "1.0.0.0,1.0.0.255\n",
	} {
		if _, err := Parse(strings.NewReader(in), false); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Truncated gzip.
	data := gz(sample)
	if _, err := Parse(bytes.NewReader(data[:len(data)/2]), false); err == nil {
		t.Error("truncated gzip accepted")
	}
	// A partial file is fine for an import, not for a download.
	if _, err := Parse(strings.NewReader(sample), true); err == nil || !strings.Contains(err.Error(), "not a complete database") {
		t.Errorf("strict: %v", err)
	}
}

func TestMergeAtTopOfRange(t *testing.T) {
	db, err := Parse(strings.NewReader("255.255.255.0,255.255.255.255,ZZ\n255.255.255.128,255.255.255.200,ZZ\n"), false)
	if err != nil {
		t.Fatal(err)
	}
	if r := db.Ranges("ZZ"); len(r) != 1 || r[0].String() != "255.255.255.0-255.255.255.255" {
		t.Errorf("%v", r)
	}
}

func TestSaveLoadAndStore(t *testing.T) {
	db, _ := Parse(strings.NewReader(sample), false)
	db.SetMeta("2026-10", "shipped", time.Unix(1790000000, 0))
	root := t.TempDir()
	st := Store{Shipped: filepath.Join(root, "share"), Local: filepath.Join(root, "var")}
	if cur, err := st.Current(); cur != nil || err != nil {
		t.Fatalf("empty store: %v %v", cur, err)
	}
	if err := db.Save(st.Shipped); err != nil {
		t.Fatal(err)
	}
	got, err := st.Current()
	if err != nil {
		t.Fatal(err)
	}
	if got.Meta().Month != "2026-10" || got.Lookup(netip.MustParseAddr("1.0.2.7")) != "CN" || len(got.Ranges("AU")) != 2 {
		t.Fatalf("round trip: %+v", got.Meta())
	}
	// A newer local month wins; an older one doesn't.
	newer, _ := Parse(strings.NewReader("9.9.9.0,9.9.9.255,CH\n"), false)
	newer.SetMeta("2026-11", "downloaded", time.Now())
	st.Install(newer)
	if m, _ := st.CurrentMeta(); m.Month != "2026-11" {
		t.Errorf("newer local month not in use: %+v", m)
	}
	older, _ := Parse(strings.NewReader("9.9.9.0,9.9.9.255,CH\n"), false)
	older.SetMeta("2026-09", "downloaded", time.Now())
	st.Install(older)
	if m, _ := st.CurrentMeta(); m.Month != "2026-10" || m.Origin != "shipped" {
		t.Errorf("an older local month replaced the shipped one: %+v", m)
	}
	// A damaged file is an error, not an empty database.
	os.WriteFile(filepath.Join(st.Shipped, dataFile), []byte("not gzip"), 0o644)
	if _, err := Load(st.Shipped); err == nil {
		t.Error("damaged file loaded")
	}
}

func TestKnown(t *testing.T) {
	for _, cc := range []string{"US", "CN", "XK", "GB"} {
		if !Known(cc) {
			t.Errorf("%s unknown", cc)
		}
	}
	for _, cc := range []string{"ZZ", "UK", "us", "EU"} {
		if Known(cc) {
			t.Errorf("%s known", cc)
		}
	}
}

func TestFetch(t *testing.T) {
	// A full-size file is needed for a download: lower the bar for the test.
	MinRows, MinCountries = 3, 2
	defer func() { MinRows, MinCountries = 200000, 200 }()
	full := sample
	var served []string
	months := map[string][]byte{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		served = append(served, r.URL.Path)
		for m, b := range months {
			if strings.HasSuffix(r.URL.Path, "dbip-country-lite-"+m+".csv.gz") {
				w.Write(b)
				return
			}
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	old := BaseURL
	BaseURL = srv.URL
	defer func() { BaseURL = old }()
	now := time.Date(2026, 12, 2, 0, 0, 0, 0, time.UTC)

	// December isn't out yet: November is used.
	months["2026-11"] = gz(full)
	db, err := Fetch(context.Background(), srv.Client(), now, "2026-10")
	if err != nil || db == nil || db.Meta().Month != "2026-11" || db.Meta().Origin != "downloaded" {
		t.Fatalf("fallback: %v %+v", err, db)
	}
	// Already have November: nothing to do.
	if db, err := Fetch(context.Background(), srv.Client(), now, "2026-11"); db != nil || err != nil {
		t.Errorf("up to date: %v %v", db, err)
	}
	// December is out.
	months["2026-12"] = gz(full)
	if db, _ := Fetch(context.Background(), srv.Client(), now, "2026-11"); db == nil || db.Meta().Month != "2026-12" {
		t.Errorf("current month not taken")
	}
	// A bad file is an error (the caller keeps its data).
	months["2026-12"] = gz("1.0.0.0,1.0.0.255,AU\n")
	if _, err := Fetch(context.Background(), srv.Client(), now, "2026-11"); err == nil {
		t.Error("incomplete download accepted")
	}
	// A server error on the current month is an error, not a fallback.
	months["2026-12"] = nil
	fail := true
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail && strings.HasSuffix(r.URL.Path, "2026-12.csv.gz") {
			http.Error(w, "busy", http.StatusServiceUnavailable)
			return
		}
		if strings.HasSuffix(r.URL.Path, "2026-11.csv.gz") {
			w.Write(months["2026-11"])
			return
		}
		http.NotFound(w, r)
	})
	if db, err := Fetch(context.Background(), srv.Client(), now, ""); err == nil || db != nil {
		t.Errorf("503 on the current month fell back: %v %v", db, err)
	}
	// Nothing published: an error.
	delete(months, "2026-12")
	delete(months, "2026-11")
	if _, err := Fetch(context.Background(), srv.Client(), now, ""); err == nil {
		t.Error("no months: no error")
	}
	_ = fmt.Sprint(served)
}

func TestMonths(t *testing.T) {
	if m := Months(time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)); m[0] != "2026-01" || m[1] != "2025-12" {
		t.Errorf("%v", m)
	}
}

func TestFetchSizeCap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(bytes.Repeat([]byte("x"), 2048))
	}))
	defer srv.Close()
	old, oldMax := BaseURL, maxDownload
	BaseURL, maxDownload = srv.URL, 1024
	defer func() { BaseURL, maxDownload = old, oldMax }()
	_, err := Fetch(context.Background(), srv.Client(), time.Now(), "")
	if err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("err %v", err)
	}
}
