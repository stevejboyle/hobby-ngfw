package geoip

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

const asnSample = `1.0.0.0,1.0.0.255,13335,"Cloudflare, Inc."
1.0.1.0,1.0.1.255,13335,"Cloudflare, Inc."
1.0.4.0,1.0.7.255,38803,"Gtelecom Pty Ltd"
2001:200::,2001:200:ffff:ffff:ffff:ffff:ffff:ffff,2500,"WIDE"
8.8.8.0,8.8.8.255,15169,"Google LLC"
9.9.9.0,9.9.9.255,19281,"Quad9	evil` + "\x07" + `name"
`

func TestASNParseLookup(t *testing.T) {
	for _, in := range [][]byte{[]byte(asnSample), gz(asnSample)} {
		db, err := ParseASN(bytes.NewReader(in), false)
		if err != nil {
			t.Fatal(err)
		}
		if db.Meta().Rows != 5 || db.ASNs() != 4 || db.Meta().Source != ASNSource {
			t.Errorf("meta %+v asns %d", db.Meta(), db.ASNs())
		}
		// The two adjacent Cloudflare rows merge.
		if len(db.index) != 4 {
			t.Errorf("index %v", db.index)
		}
		for ip, want := range map[string]uint32{"1.0.0.1": 13335, "1.0.1.255": 13335, "1.0.2.0": 0, "8.8.8.8": 15169, "1.0.5.5": 38803, "255.1.1.1": 0} {
			if a, _ := db.Lookup(netip.MustParseAddr(ip)); a != want {
				t.Errorf("%s: AS%d, want AS%d", ip, a, want)
			}
		}
		if _, org := db.Lookup(netip.MustParseAddr("8.8.8.8")); org != "Google LLC" {
			t.Errorf("org %q", org)
		}
		// Tabs and control characters never reach the logs.
		if _, org := db.Lookup(netip.MustParseAddr("9.9.9.9")); strings.ContainsAny(org, "\t\x07") {
			t.Errorf("org not cleaned: %q", org)
		}
		if a, _ := db.Lookup(netip.MustParseAddr("2001:200::1")); a != 0 {
			t.Error("IPv6 looked up")
		}
	}
	var nilDB *ASNDB
	if a, o := nilDB.Lookup(netip.MustParseAddr("8.8.8.8")); a != 0 || o != "" {
		t.Error("nil db")
	}
}

func TestASNRejects(t *testing.T) {
	for name, in := range map[string]string{
		"three columns": "1.0.0.0,1.0.0.255,AU\n",
		"bad number":    "1.0.0.0,1.0.0.255,x,y\n",
		"AS 0":          "1.0.0.0,1.0.0.255,0,y\n",
		"reversed":      "1.0.0.9,1.0.0.1,5,y\n",
		"no rows":       "2001::,2001::1,5,y\n",
	} {
		if _, err := ParseASN(strings.NewReader(in), false); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := ParseASN(strings.NewReader(asnSample), true); err == nil {
		t.Error("strict accepted a 5-row file")
	}
}

func TestIsASNCSV(t *testing.T) {
	if !IsASNCSV([]byte(asnSample)) || !IsASNCSV(gz(asnSample)) || IsASNCSV([]byte(sample)) || IsASNCSV(gz(sample)) {
		t.Error("misdetected")
	}
}

func TestASNSaveLoadStore(t *testing.T) {
	db, err := ParseASN(strings.NewReader(asnSample), false)
	if err != nil {
		t.Fatal(err)
	}
	st := Store{Shipped: t.TempDir(), Local: t.TempDir()}
	if got, err := st.CurrentASN(); got != nil || err != nil {
		t.Fatalf("empty store: %v %v", got, err)
	}
	db.SetMeta("2026-10", "shipped", time.Now())
	if err := db.Save(st.Shipped); err != nil {
		t.Fatal(err)
	}
	// A country database in the same directory is unaffected.
	cdb, _ := Parse(strings.NewReader(sample), false)
	cdb.SetMeta("2026-12", "shipped", time.Now())
	if err := cdb.Save(st.Shipped); err != nil {
		t.Fatal(err)
	}
	got, err := st.CurrentASN()
	if err != nil || got == nil || got.Meta().Month != "2026-10" || got.ASNs() != 4 {
		t.Fatalf("load: %v %+v", err, got)
	}
	if a, org := got.Lookup(netip.MustParseAddr("8.8.4.4")); a != 0 || org != "" {
		t.Errorf("8.8.4.4: %d %q", a, org)
	}
	if a, org := got.Lookup(netip.MustParseAddr("8.8.8.8")); a != 15169 || org != "Google LLC" {
		t.Errorf("after load: %d %q", a, org)
	}
	// A newer local month wins; the country choice is separate.
	db.SetMeta("2026-11", "downloaded", time.Now())
	if err := st.InstallASN(db); err != nil {
		t.Fatal(err)
	}
	if m, ok := st.CurrentASNMeta(); !ok || m.Month != "2026-11" || m.Origin != "downloaded" {
		t.Errorf("newer local: %+v", m)
	}
	if m, ok := st.CurrentMeta(); !ok || m.Month != "2026-12" {
		t.Errorf("country meta: %+v", m)
	}
}

func TestFetchASN(t *testing.T) {
	MinASNRows, MinASNs = 3, 2
	defer func() { MinASNRows, MinASNs = 200000, 10000 }()
	status := http.StatusServiceUnavailable
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/dbip-asn-lite-2026-12.csv.gz"):
			http.Error(w, "x", status)
		case strings.HasSuffix(r.URL.Path, "/dbip-asn-lite-2026-11.csv.gz"):
			w.Write(gz(asnSample))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	old := BaseURL
	BaseURL = srv.URL
	defer func() { BaseURL = old }()
	now := time.Date(2026, 12, 2, 0, 0, 0, 0, time.UTC)
	// A server error on December is an error, not a fall back to November.
	if db, err := FetchASN(context.Background(), srv.Client(), now, ""); err == nil || db != nil {
		t.Errorf("503 fell back: %v", err)
	}
	// December not published: November.
	status = http.StatusNotFound
	db, err := FetchASN(context.Background(), srv.Client(), now, "2026-10")
	if err != nil || db == nil || db.Meta().Month != "2026-11" || db.Meta().Origin != "downloaded" {
		t.Fatalf("fallback: %v %+v", err, db)
	}
	if db, err := FetchASN(context.Background(), srv.Client(), now, "2026-11"); db != nil || err != nil {
		t.Errorf("up to date: %v %v", db, err)
	}
	if u := URLFor(ASNSource, "2026-11"); !strings.HasSuffix(u, "/dbip-asn-lite-2026-11.csv.gz") {
		t.Error(u)
	}
}
