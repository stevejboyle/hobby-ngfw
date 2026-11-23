package dhcp

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stevejboyle/sjb-os/internal/config"
)

var update = flag.Bool("update", false, "rewrite golden files")

func lab() *config.Config {
	return &config.Config{
		System:     config.System{Hostname: "fw", MgmtInterface: "mgmt"},
		Zones:      []config.Zone{{Name: "trust"}, {Name: "lab"}},
		VRFs:       []config.VRF{{Name: "blue"}},
		Interfaces: []config.Interface{{Name: "mgmt"}, {Name: "inside", Zone: "trust", Address: "192.168.150.1/24"}, {Name: "inside.20", Zone: "lab", Address: "172.16.20.1/24", VRF: "blue"}},
		DHCPServers: []config.DHCPServer{
			{Name: "inside", Range: "192.168.150.100-192.168.150.199", Domain: "lab.example", NTP: []string{"192.168.150.1"}, Options: []string{"66=tftp.lab", "150=0x0a000001"}},
			{Name: "inside.20", Range: "172.16.20.50-172.16.20.60", Gateway: "172.16.20.254", DNS: []string{"9.9.9.9"}, LeaseTime: 600},
		},
		DHCPReservations: []config.DHCPReservation{{Name: "printer", Interface: "inside", MAC: "52:54:00:AB:CD:01", Address: "192.168.150.20"}},
	}
}

// The golden is also checked by real Kea (kea-dhcp4 -t) in CI.
func TestCompileGolden(t *testing.T) {
	c := lab()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	r := Compile(c, Options{DNS: []string{"1.1.1.1", "127.0.0.53", "fd00::1"}})
	path := filepath.Join("testdata", "lab.conf")
	if *update {
		os.WriteFile(path, []byte(r.Conf), 0o644)
		os.WriteFile(filepath.Join("testdata", "lab-check.conf"), []byte(r.CheckConf), 0o644)
	}
	if strings.Contains(r.CheckConf, `"interface"`) || strings.Contains(r.CheckConf, `"inside"`) {
		t.Errorf("check config still names interfaces:\n%s", r.CheckConf)
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if r.Conf != string(want) {
		t.Errorf("config differs from %s (go test -update to accept):\n%s", path, r.Conf)
	}
	if strings.Join(r.Interfaces, ",") != "inside,inside.20" || r.Subnets[SubnetID("inside.20")] != "inside.20" || len(r.Warnings) != 0 {
		t.Errorf("result: %+v", r)
	}
	if !strings.Contains(r.Conf, `"data": "1.1.1.1"`) {
		t.Error("default DNS should be the firewall's IPv4, non-loopback servers")
	}
}

func TestCompileEmptyAndNoDNS(t *testing.T) {
	r := Compile(&config.Config{}, Options{})
	if r.Enabled() || !strings.Contains(r.Conf, `"interfaces": []`) {
		t.Fatalf("empty config: %+v", r)
	}
	c := lab()
	c.DHCPServers = c.DHCPServers[:1]
	r = Compile(c, Options{})
	if len(r.Warnings) != 1 || !strings.Contains(r.Warnings[0], "no DNS servers") {
		t.Fatalf("warnings: %q", r.Warnings)
	}
}

func TestSubnetIDStable(t *testing.T) {
	if SubnetID("inside") != SubnetID("inside") || SubnetID("inside") == SubnetID("inside.20") || SubnetID("x") < 1 {
		t.Fatal("subnet ids")
	}
}

func TestApplyStartsRestartsAndStops(t *testing.T) {
	dir := t.TempDir()
	var calls []string
	active, enabled := false, false
	passwd := filepath.Join(dir, "passwd")
	os.WriteFile(passwd, []byte(fmt.Sprintf("root:x:0:0::/root:/bin/sh\n_kea:x:%d:%d::/var/lib/kea:/usr/sbin/nologin\n", os.Getuid(), os.Getgid())), 0o644)
	e := Exec{Conf: filepath.Join(dir, "kea-dhcp4.conf"), Passwd: passwd, Systemd: func(args ...string) error {
		calls = append(calls, strings.Join(args, " "))
		switch {
		case args[0] == "is-active" && !active, args[0] == "is-enabled" && !enabled:
			return errExit
		}
		return nil
	}}
	on := Compile(lab(), Options{DNS: []string{"1.1.1.1"}})
	if err := e.Apply(on); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(calls, "; "); got != "is-active --quiet kea-dhcp4-server; enable --quiet kea-dhcp4-server; --no-block restart kea-dhcp4-server" {
		t.Fatalf("first apply: %q", got)
	}
	// Unchanged and running: nothing to do but make sure it's enabled.
	active, enabled, calls = true, true, nil
	e.Apply(on)
	if got := strings.Join(calls, "; "); got != "is-active --quiet kea-dhcp4-server; enable --quiet kea-dhcp4-server" {
		t.Fatalf("unchanged apply: %q", got)
	}
	// Nothing served: stop and disable.
	calls = nil
	e.Apply(Compile(&config.Config{}, Options{}))
	if got := calls[len(calls)-1]; got != "--no-block disable --now --quiet kea-dhcp4-server" {
		t.Fatalf("off: %q", calls)
	}
	// Already off: leave it alone.
	active, enabled, calls = false, false, nil
	e.Apply(Compile(&config.Config{}, Options{}))
	if len(calls) != 2 {
		t.Fatalf("already off: %q", calls)
	}
}

var errExit = os.ErrNotExist

func TestCheckError(t *testing.T) {
	out := "2026-11-13 14:07:43.580 ERROR [kea-dhcp4.dhcp4/780.1] DHCP4_PARSER_COMMIT_FAIL parser failed: bad thing in /tmp/x.conf\n"
	if got := checkError(out, "/tmp/x.conf", errExit); got != "DHCP4_PARSER_COMMIT_FAIL parser failed: bad thing in dhcp config" {
		t.Fatalf("got %q", got)
	}
	if got := checkError("junk\nError encountered: option 150 /tmp/x.conf\n", "/tmp/x.conf", errExit); got != "option 150 dhcp config" {
		t.Fatalf("got %q", got)
	}
}

func TestKeaIDsMissing(t *testing.T) {
	p := filepath.Join(t.TempDir(), "passwd")
	os.WriteFile(p, []byte("root:x:0:0::/root:/bin/sh\n"), 0o644)
	if _, err := (Exec{Passwd: p}).keaIDs(); err == nil || !strings.Contains(err.Error(), "_kea") {
		t.Fatalf("err: %v", err)
	}
	if err := (Exec{Passwd: p, Conf: filepath.Join(t.TempDir(), "k.conf")}).Apply(Compile(lab(), Options{})); err == nil {
		t.Fatal("Apply should refuse when Kea's user is missing")
	}
}
