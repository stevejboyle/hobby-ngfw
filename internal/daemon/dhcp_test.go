package daemon

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stevejboyle/hobby-ngfw/internal/dhcp"
)

type fakeKea struct {
	applied  []*dhcp.Result
	checkErr error
	dns      []string
	leases   []dhcp.RawLease
}

func (f *fakeKea) Available() bool                  { return true }
func (f *fakeKea) Options() dhcp.Options            { return dhcp.Options{DNS: f.dns} }
func (f *fakeKea) Check(string) error               { return f.checkErr }
func (f *fakeKea) Apply(r *dhcp.Result) error       { f.applied = append(f.applied, r); return nil }
func (f *fakeKea) Running() bool                    { return true }
func (f *fakeKea) Leases() ([]dhcp.RawLease, error) { return f.leases, nil }

const dhcpYAML = `
dhcp_servers:
  - name: veth-users
    range: 10.10.1.100-10.10.1.199
dhcp_reservations:
  - name: printer
    interface: veth-users
    mac: 52:54:00:AB:CD:01
    address: 10.10.1.20
`

func TestCommitAppliesDHCP(t *testing.T) {
	d, _ := setup(t)
	k := &fakeKea{dns: []string{"1.1.1.1"}}
	d.SetDHCP(k)
	if err := d.SetCandidate([]byte(string(lab(t)) + dhcpYAML)); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Commit("t", "dhcp", 0); err != nil {
		t.Fatal(err)
	}
	if len(k.applied) != 1 || !k.applied[0].Enabled() || !strings.Contains(k.applied[0].Conf, `"data": "1.1.1.1"`) {
		t.Fatalf("applied: %+v", k.applied)
	}
	// Periodic pass with nothing changed: no re-apply.
	d.ReconcileRoutes()
	if len(k.applied) != 1 {
		t.Fatalf("unchanged config re-applied: %d", len(k.applied))
	}

	now := d.Now()
	id := dhcp.SubnetID("veth-users")
	k.leases = []dhcp.RawLease{
		{Address: "10.10.1.100", MAC: "52:54:00:00:00:09", Hostname: "laptop.", SubnetID: id, CLTT: now.Unix(), Valid: 3600},
		{Address: "10.10.1.20", MAC: "52:54:00:ab:cd:01", SubnetID: id, CLTT: now.Add(-2 * time.Hour).Unix(), Valid: 3600},
	}
	ls, err := d.DHCPLeases("")
	if err != nil {
		t.Fatal(err)
	}
	if len(ls) != 2 || ls[0].Address != "10.10.1.20" || ls[0].Reserved != "printer" || ls[0].State != "expired" ||
		ls[1].Hostname != "laptop" || ls[1].State != "active" || ls[1].Interface != "veth-users" {
		t.Fatalf("leases: %+v", ls)
	}
	st := d.DHCP()
	if len(st.Servers) != 1 || st.Servers[0].Leases != 1 || st.Servers[0].Gateway != "10.10.1.1" || !st.Servers[0].DNSDefault || st.Servers[0].Reservations != 1 {
		t.Fatalf("status: %+v", st)
	}

	// Removing the servers turns Kea off.
	if err := d.SetCandidate(lab(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Commit("t", "no dhcp", 0); err != nil {
		t.Fatal(err)
	}
	if last := k.applied[len(k.applied)-1]; last.Enabled() {
		t.Fatal("Kea should be turned off")
	}
}

func TestKeaRejectionFailsCommit(t *testing.T) {
	d, f := setup(t)
	d.SetDHCP(&fakeKea{checkErr: errors.New("option 150: no definition")})
	before := len(f.Applied)
	if err := d.SetCandidate([]byte(string(lab(t)) + dhcpYAML)); err != nil {
		t.Fatal(err)
	}
	_, err := d.Commit("t", "dhcp", 0)
	if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "rejected by Kea, nothing applied") {
		t.Fatalf("err: %v", err)
	}
	if len(f.Applied) != before {
		t.Fatal("ruleset applied despite Kea rejecting the config")
	}
}

func TestDHCPWaitsForDNSAfterStart(t *testing.T) {
	d, _ := setup(t)
	k := &fakeKea{}
	d.SetDHCP(k)
	if err := d.SetCandidate([]byte(string(lab(t)) + dhcpYAML)); err != nil {
		t.Fatal(err)
	}
	// Commit applies even without DNS (with a warning).
	res, err := d.Commit("t", "dhcp", 0)
	if err != nil || len(k.applied) != 1 || !strings.Contains(strings.Join(res.Warnings, "\n"), "no DNS servers") {
		t.Fatalf("commit: %v %+v", err, res)
	}
	// Right after start, the periodic pass leaves Kea alone while DNS is unknown.
	d.dhcpApplied = ""
	d.ReconcileRoutes()
	if len(k.applied) != 1 {
		t.Fatal("periodic pass applied a config without DNS right after start")
	}
	// Once DNS is known, it applies.
	k.dns = []string{"9.9.9.9"}
	d.ReconcileRoutes()
	if len(k.applied) != 2 || !strings.Contains(k.applied[1].Conf, "9.9.9.9") {
		t.Fatalf("applied: %d", len(k.applied))
	}
}
