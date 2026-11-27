package compiler

import (
	"os"
	"testing"

	"github.com/stevejboyle/sjb-os/internal/config"
	"github.com/stevejboyle/sjb-os/internal/geoip"
)

// TestGeoLiveScript writes the nft script for rules naming real countries,
// for a check against real nft (GEO_LIVE_DB: a geoip directory;
// GEO_LIVE_OUT: where to write the script).
func TestGeoLiveScript(t *testing.T) {
	dir, out := os.Getenv("GEO_LIVE_DB"), os.Getenv("GEO_LIVE_OUT")
	if dir == "" || out == "" {
		t.Skip("set GEO_LIVE_DB and GEO_LIVE_OUT")
	}
	db, err := geoip.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		System:     config.System{Hostname: "fw"},
		Zones:      []config.Zone{{Name: "inside"}, {Name: "outside"}},
		Interfaces: []config.Interface{{Name: "eth1", Zone: "inside"}, {Name: "eth2", Zone: "outside"}},
		Rules: []config.Rule{
			{Name: "deny-some", From: []string{"outside"}, Source: []string{"country:CN", "country:RU"}, Action: "deny"},
			{Name: "us-only", From: []string{"outside"}, Source: []string{"country:US", "country:GB", "country:DE"}, SourceNegate: true, Action: "deny"},
			{Name: "allow", From: []string{"outside"}, Action: "allow"},
		},
	}
	res, err := CompileWith(cfg, nil, Options{Geo: db})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, []byte(res.Script()), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("script %d bytes, warnings %v", len(res.Script()), res.Warnings)
}
