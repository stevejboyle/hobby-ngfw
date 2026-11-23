package frr

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stevejboyle/sjb-os/internal/config"
)

var update = flag.Bool("update", false, "rewrite golden files")

// TestGolden pins frr.conf for each example; CI checks the goldens with
// vtysh -C. Run go test ./internal/frr -update after an intended change.
func TestGolden(t *testing.T) {
	for _, name := range []string{"routing", "basic"} {
		t.Run(name, func(t *testing.T) {
			cfg, err := config.Load(filepath.Join("..", "..", "examples", name+".yaml"))
			if err != nil {
				t.Fatal(err)
			}
			got := Compile(cfg).Conf
			golden := filepath.Join("testdata", name+".conf")
			if *update {
				os.MkdirAll("testdata", 0o755)
				if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatalf("%v (run with -update)", err)
			}
			if got != string(want) {
				t.Errorf("frr.conf differs from %s; run with -update and review.\n--- got ---\n%s", golden, got)
			}
		})
	}
}

func TestDaemons(t *testing.T) {
	cfg, _ := config.Load("../../examples/routing.yaml")
	r := Compile(cfg)
	if !r.Daemons["bgpd"] || !r.Daemons["ospfd"] || !r.Enabled() {
		t.Fatalf("daemons: %v", r.Daemons)
	}
	cfg.Routing = nil
	cfg.BGPNeighbors, cfg.OSPFInterfaces = nil, nil
	if r := Compile(cfg); r.Enabled() || strings.Contains(r.Conf, "router ") {
		t.Fatalf("no routing should mean no daemons:\n%s", r.Conf)
	}
}

func TestSetDaemons(t *testing.T) {
	debian := "# This file tells the frr package which daemons to start.\nbgpd=no\nospfd=no\nospf6d=no\nvtysh_enable=yes\n"
	out, changed := SetDaemons(debian, map[string]bool{"bgpd": true, "ospfd": false})
	if !changed || !strings.Contains(out, "\nbgpd=yes\n") || !strings.Contains(out, "\nospfd=no\n") || !strings.Contains(out, "ospf6d=no") {
		t.Fatalf("SetDaemons:\n%s", out)
	}
	if _, changed := SetDaemons(out, map[string]bool{"bgpd": true, "ospfd": false}); changed {
		t.Fatal("no change expected the second time")
	}
}
