package daemon

import (
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stevejboyle/sjb-os/internal/accounts"
	"github.com/stevejboyle/sjb-os/internal/geoip"
)

const (
	testCountryCSV = "1.0.1.0,1.0.3.255,CN\n8.8.8.0,8.8.8.255,US\n10.0.0.0,10.255.255.255,ZZ\n"
	testASNCSV     = "1.0.1.0,1.0.1.255,4134,\"Chinanet\"\n8.8.8.0,8.8.8.255,15169,\"Google LLC\"\n"
)

func TestGeoOfAndASNImport(t *testing.T) {
	d, f := setup(t)
	root := t.TempDir()
	d.SetGeoIP(geoip.Store{Shipped: filepath.Join(root, "share"), Local: filepath.Join(root, "var")}, nil)
	if cc, asn, org := d.GeoOf("8.8.8.8"); cc != "" || asn != 0 || org != "" {
		t.Errorf("no databases: %q %d %q", cc, asn, org)
	}
	if _, err := d.ImportGeoIP(accounts.Root, []byte(testCountryCSV)); err != nil {
		t.Fatal(err)
	}
	revs, _ := d.Revisions()
	applied := f.Last()
	st, err := d.ImportGeoIP(accounts.Root, []byte(testASNCSV))
	if err != nil {
		t.Fatal(err)
	}
	if !st.ASN.Available || st.ASN.Meta.Origin != "imported" || st.ASN.Meta.ASNs != 2 || !st.Available {
		t.Errorf("status: %+v", st)
	}
	// The AS database is for the logs: no re-apply, no revision.
	if after, _ := d.Revisions(); len(after) != len(revs) || f.Last() != applied {
		t.Error("an AS import touched the ruleset or made a revision")
	}
	for addr, want := range map[string][3]string{
		"8.8.8.8":    {"US", "15169", "Google LLC"},
		"1.0.1.5":    {"CN", "4134", "Chinanet"},
		"1.0.2.5":    {"CN", "0", ""}, // in the country data only
		"10.1.2.3":   {"", "0", ""},   // ZZ: private, shown blank
		"2001:db8::": {"", "0", ""},
		"not an ip":  {"", "0", ""},
	} {
		cc, asn, org := d.GeoOf(addr)
		if cc != want[0] || strconv.FormatUint(uint64(asn), 10) != want[1] || org != want[2] {
			t.Errorf("%s: %q %d %q, want %v", addr, cc, asn, org, want)
		}
	}
	lk, err := d.GeoIPLookup("8.8.8.8")
	if err != nil || lk["country"] != "US" || lk["asn"] != "15169" || lk["as_org"] != "Google LLC" {
		t.Errorf("lookup: %v %v", lk, err)
	}
	// Both survive a restart.
	d.SetGeoIP(geoip.Store{Shipped: filepath.Join(root, "share"), Local: filepath.Join(root, "var")}, nil)
	if _, asn, _ := d.GeoOf("8.8.8.8"); asn != 15169 {
		t.Error("AS database not loaded at start")
	}
}

// Reading logs (GeoOf) must never wait for d.mu: a commit can hold it for
// minutes.
func TestGeoOfDoesNotWaitForTheLock(t *testing.T) {
	d, _ := setup(t)
	root := t.TempDir()
	d.SetGeoIP(geoip.Store{Shipped: filepath.Join(root, "share"), Local: filepath.Join(root, "var")}, nil)
	if _, err := d.ImportGeoIP(accounts.Root, []byte(testASNCSV)); err != nil {
		t.Fatal(err)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	done := make(chan uint32, 1)
	go func() {
		_, asn, _ := d.GeoOf("8.8.8.8")
		done <- asn
	}()
	select {
	case asn := <-done:
		if asn != 15169 {
			t.Errorf("asn %d", asn)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("GeoOf waited for d.mu")
	}
}

// The daily check runs with auto-update on, country rules or not.
func TestGeoUpdateDueWithoutCountryRules(t *testing.T) {
	d, _ := setup(t)
	root := t.TempDir()
	d.SetGeoIP(geoip.Store{Shipped: filepath.Join(root, "share"), Local: filepath.Join(root, "var")}, nil)
	now := time.Date(2026, 12, 2, 12, 0, 0, 0, time.UTC)
	d.Now = func() time.Time { return now }
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.geoUpdateDueLocked() {
		t.Error("never checked: not due")
	}
	d.geo.check.Time = now.Add(-22 * time.Hour)
	if d.geoUpdateDueLocked() {
		t.Error("due after 22 hours")
	}
	d.geo.check.Time = now.Add(-23 * time.Hour)
	if !d.geoUpdateDueLocked() {
		t.Error("not due after 23 hours")
	}
	d.running.System.GeoIPAutoUpdate = "off"
	if d.geoUpdateDueLocked() {
		t.Error("due with auto-update off")
	}
}

func gzipped(s string) []byte {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	w.Write([]byte(s))
	w.Close()
	return b.Bytes()
}

// An update fetches both databases; one failing doesn't stop the other.
func TestGeoIPUpdateBoth(t *testing.T) {
	geoip.MinRows, geoip.MinCountries, geoip.MinASNRows, geoip.MinASNs = 2, 2, 2, 2
	defer func() {
		geoip.MinRows, geoip.MinCountries, geoip.MinASNRows, geoip.MinASNs = 200000, 200, 200000, 10000
	}()
	asnStatus := http.StatusServiceUnavailable
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "dbip-country-lite-2026-12"):
			w.Write(gzipped(testCountryCSV))
		case strings.Contains(r.URL.Path, "dbip-asn-lite-2026-12"):
			if asnStatus != http.StatusOK {
				http.Error(w, "busy", asnStatus)
				return
			}
			w.Write(gzipped(testASNCSV))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	old := geoip.BaseURL
	geoip.BaseURL = srv.URL
	defer func() { geoip.BaseURL = old }()
	d, _ := setup(t)
	d.Now = func() time.Time { return time.Date(2026, 12, 2, 12, 0, 0, 0, time.UTC) }
	root := t.TempDir()
	d.SetGeoIP(geoip.Store{Shipped: filepath.Join(root, "share"), Local: filepath.Join(root, "var")}, srv.Client())
	st, err := d.UpdateGeoIP(context.Background())
	if err == nil || st.LastCheck.OK || !strings.Contains(st.LastCheck.Result, "country updated to 2026-12") ||
		!strings.Contains(st.LastCheck.Result, "AS: ") || !st.Available || st.ASN.Available {
		t.Fatalf("AS failing: %v %+v", err, st)
	}
	asnStatus = http.StatusOK
	st, err = d.UpdateGeoIP(context.Background())
	if err != nil || !st.LastCheck.OK || st.LastCheck.Result != "country up to date (2026-12); AS updated to 2026-12" || !st.ASN.Available {
		t.Fatalf("second update: %v %+v", err, st.LastCheck)
	}
	if _, asn, _ := d.GeoOf("8.8.8.8"); asn != 15169 {
		t.Error("downloaded AS database not in use")
	}
}
