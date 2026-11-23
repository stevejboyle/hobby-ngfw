package daemon

import (
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/stevejboyle/sjb-os/internal/natips"
)

// liveAddrs is a natips syncer whose interfaces have the given addresses.
type liveAddrs struct {
	natips.Noop
	addrs map[string][]netip.Addr
}

func (l *liveAddrs) Addrs(dev string) ([]netip.Addr, error) { return l.addrs[dev], nil }

func countScripts(applied []string, s string) int {
	n := 0
	for _, a := range applied {
		if strings.Contains(a, s) {
			n++
		}
	}
	return n
}

func TestHairpinInterfaceAddressSet(t *testing.T) {
	d, f := setup(t)
	live := &liveAddrs{addrs: map[string][]netip.Addr{"outside": {netip.MustParseAddr("203.0.113.5")}}}
	d.SetNATIPs(live)
	b, err := os.ReadFile("../../examples/nat.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err := d.SetCandidate(b); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Commit("t", "nat", 0); err != nil {
		t.Fatal(err)
	}
	fill := "add element inet ngfw ifaddr_outside { 203.0.113.5 }"
	if countScripts(f.Applied, fill) != 1 {
		t.Fatalf("commit should fill the set once:\n%s", strings.Join(f.Applied, "\n---\n"))
	}
	// Unchanged: the 10 s resync writes nothing.
	d.ReconcileRoutes()
	if countScripts(f.Applied, "add element inet ngfw ifaddr_outside") != 1 {
		t.Fatal("an unchanged address was written again")
	}
	// A DHCP change follows at the next resync.
	live.addrs["outside"] = []netip.Addr{netip.MustParseAddr("203.0.113.9")}
	d.ReconcileRoutes()
	if !strings.Contains(f.Last(), "flush set inet ngfw ifaddr_outside") || !strings.Contains(f.Last(), "{ 203.0.113.9 }") {
		t.Fatalf("new address not filled in: %s", f.Last())
	}
	// A ruleset load empties the sets: a rollback refills them.
	if _, err := d.Rollback(1, "t"); err != nil {
		t.Fatal(err)
	}
	if countScripts(f.Applied, "{ 203.0.113.9 }") != 2 {
		t.Fatal("the set was not refilled after the ruleset was loaded again")
	}
}
