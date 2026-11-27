package daemon

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stevejboyle/sjb-os/internal/accounts"
	"github.com/stevejboyle/sjb-os/internal/conntrack"
	"github.com/stevejboyle/sjb-os/internal/geoip"
	"github.com/stevejboyle/sjb-os/internal/nft"
	"github.com/stevejboyle/sjb-os/internal/store"
	"github.com/stevejboyle/sjb-os/internal/tags"
)

// withGeoRule is the lab config with a rule denying a country first.
func withGeoRule(t *testing.T) []byte {
	s := string(lab(t))
	return []byte(strings.Replace(s, "rules:\n", "rules:\n  - name: deny-cn\n    from: [users]\n    source: [country:CN]\n    action: deny\n", 1))
}

func TestGeoIPImportRefreshesWithoutRevision(t *testing.T) {
	dir := t.TempDir()
	d, f := setupAt(t, dir)
	root := t.TempDir()
	d.SetGeoIP(geoip.Store{Shipped: filepath.Join(root, "share"), Local: filepath.Join(root, "var")}, nil)
	if err := d.SetCandidate(withGeoRule(t)); err != nil {
		t.Fatal(err)
	}
	res, err := d.Commit("steve", "geo", 0)
	if err != nil {
		t.Fatal(err)
	}
	warned := false
	for _, w := range res.Warnings {
		warned = warned || strings.Contains(w, "no country database yet")
	}
	if !warned || !strings.Contains(f.Last(), "set geo_cn {") || strings.Contains(f.Last(), "add element inet ngfw geo_cn") {
		t.Fatalf("commit without a database: warnings %v", res.Warnings)
	}
	revs, _ := d.Revisions()
	policy := d.policy

	st, err := d.ImportGeoIP(accounts.Root, []byte("1.0.1.0,1.0.3.255,CN\n8.8.8.0,8.8.8.255,US\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !st.Available || st.Meta.Origin != "imported" || len(st.InUse) != 1 || st.InUse[0].Code != "CN" || st.InUse[0].Ranges != 1 {
		t.Errorf("status after import: %+v", st)
	}
	if !strings.Contains(f.Last(), "add element inet ngfw geo_cn { 1.0.1.0-1.0.3.255 }") || !strings.Contains(f.Last(), "set geo_cn {") {
		t.Fatalf("the import didn't re-apply the ruleset with the ranges:\n%s", f.Last())
	}
	after, _ := d.Revisions()
	if len(after) != len(revs) {
		t.Errorf("a database refresh made a revision: %d -> %d", len(revs), len(after))
	}
	if d.policy != policy {
		t.Error("the policy (without set elements) changed: conntrack would be flushed for a data refresh")
	}
	if r, err := d.GeoIPLookup("1.0.2.3"); err != nil || r["country"] != "CN" || r["name"] != "China" {
		t.Errorf("lookup %v %v", r, err)
	}
	if _, err := d.GeoIPLookup("not-an-ip"); err == nil {
		t.Error("bad address accepted")
	}

	// A later commit keeps the ranges (same transaction as the ruleset).
	d.SetCandidate(withGeoRule(t))
	if _, err := d.Commit("steve", "again", 0); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.Last(), "add element inet ngfw geo_cn") {
		t.Error("a commit dropped the country ranges")
	}

	// An ngfwd restart loads the imported database before the first apply.
	d2, f2 := newAt(t, dir)
	d2.SetGeoIP(geoip.Store{Shipped: filepath.Join(root, "share"), Local: filepath.Join(root, "var")}, nil)
	if err := d2.Start(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f2.Last(), "add element inet ngfw geo_cn { 1.0.1.0-1.0.3.255 }") {
		t.Error("after a restart the first ruleset has no country ranges")
	}
}

func TestGeoIPRejectsBadImport(t *testing.T) {
	d, f := setup(t)
	root := t.TempDir()
	d.SetGeoIP(geoip.Store{Shipped: filepath.Join(root, "share"), Local: filepath.Join(root, "var")}, nil)
	n := len(f.Applied)
	if _, err := d.ImportGeoIP(accounts.Root, []byte("garbage")); err == nil {
		t.Fatal("garbage imported")
	}
	if len(f.Applied) != n {
		t.Error("a failed import applied something")
	}
	if st := d.GeoIP(); st.Available {
		t.Errorf("a failed import installed a database: %+v", st)
	}
}

func TestGeoIPUpdateWithoutNetwork(t *testing.T) {
	d, _ := setup(t)
	root := t.TempDir()
	old := geoip.BaseURL
	geoip.BaseURL = "http://127.0.0.1:1" // nothing listens
	defer func() { geoip.BaseURL = old }()
	d.SetGeoIP(geoip.Store{Shipped: filepath.Join(root, "share"), Local: filepath.Join(root, "var")}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	st, err := d.UpdateGeoIP(ctx)
	if err == nil || st.LastCheck.OK || st.LastCheck.Result == "" {
		t.Errorf("failed update: %v %+v", err, st.LastCheck)
	}
	// The outcome is kept across restarts.
	d.SetGeoIP(geoip.Store{Shipped: filepath.Join(root, "share"), Local: filepath.Join(root, "var")}, nil)
	if st := d.GeoIP(); st.LastCheck.OK || st.LastCheck.Time.IsZero() {
		t.Errorf("last check not kept: %+v", st.LastCheck)
	}
}

// newAt is setupAt without Start: ngfwd's start order can then be followed.
func newAt(t *testing.T, dir string) (*Daemon, *nft.Fake) {
	t.Helper()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	reg, err := tags.Open(filepath.Join(dir, "tags.json"))
	if err != nil {
		t.Fatal(err)
	}
	f := &nft.Fake{}
	return New(st, reg, f, &conntrack.Fake{}, slog.New(slog.NewTextHandler(io.Discard, nil))), f
}
