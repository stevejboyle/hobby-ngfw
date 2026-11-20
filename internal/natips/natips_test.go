package natips

import (
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

const listing = `[
 {"ifname":"lo","addr_info":[{"local":"127.0.0.1","prefixlen":8,"label":"lo"}]},
 {"ifname":"outside","addr_info":[
   {"local":"198.51.100.2","prefixlen":24,"label":"outside"},
   {"local":"198.51.100.25","prefixlen":32,"label":"outside:nat"},
   {"local":"198.51.100.99","prefixlen":32,"label":"outside:nat"},
   {"local":"198.51.100.50","prefixlen":32,"label":"outside:other"}]},
 {"ifname":"outside.4094","addr_info":[{"local":"192.0.2.9","prefixlen":32,"label":"outside.4094:n"}]}
]`

func fake(calls *[]string, fail string) func(args ...string) ([]byte, error) {
	return func(args ...string) ([]byte, error) {
		c := strings.Join(args, " ")
		*calls = append(*calls, c)
		if c == "-4 -j addr show" {
			return []byte(listing), nil
		}
		if fail != "" && strings.Contains(c, fail) {
			return []byte("RTNETLINK answers: busy"), errors.New("exit status 2")
		}
		return nil, nil
	}
}

func TestSync(t *testing.T) {
	var calls []string
	e := Exec{Run: fake(&calls, "")}
	want := []Addr{
		{Dev: "outside", IP: netip.MustParseAddr("198.51.100.25"), Name: "mail"},  // already there
		{Dev: "outside", IP: netip.MustParseAddr("198.51.100.30"), Name: "game"},  // missing
		{Dev: "outside", IP: netip.MustParseAddr("198.51.100.2"), Name: "own"},    // the interface's own address
		{Dev: "outside.77", IP: netip.MustParseAddr("192.0.2.1"), Name: "absent"}, // no such interface
	}
	states, err := e.Sync(want)
	if err != nil {
		t.Fatal(err)
	}
	wantCalls := []string{
		"-4 -j addr show",
		"-4 addr del 198.51.100.99/32 dev outside",  // ours, no longer wanted
		"-4 addr del 192.0.2.9/32 dev outside.4094", // ours (short label)
		"-4 addr add 198.51.100.30/32 dev outside label outside:nat",
	}
	if !reflect.DeepEqual(calls, wantCalls) {
		t.Errorf("calls:\n%s\nwant:\n%s", strings.Join(calls, "\n"), strings.Join(wantCalls, "\n"))
	}
	applied := map[string]bool{}
	for _, s := range states {
		applied[s.Name] = s.Applied
	}
	if !applied["mail"] || !applied["game"] || !applied["own"] || applied["absent"] {
		t.Errorf("states: %+v", states)
	}
}

func TestSyncAddFails(t *testing.T) {
	var calls []string
	e := Exec{Run: fake(&calls, "addr add")}
	states, err := e.Sync([]Addr{{Dev: "outside", IP: netip.MustParseAddr("198.51.100.30")}})
	if err != nil {
		t.Fatal(err)
	}
	if states[0].Applied || !strings.Contains(states[0].Error, "busy") {
		t.Errorf("want a failed state, got %+v", states[0])
	}
}

func TestLabel(t *testing.T) {
	for dev, want := range map[string]string{"outside": "outside:nat", "inside.40": "inside.40:nat", "outside.4094": "outside.4094:n"} {
		if got := Label(dev); got != want || len(got) > 15 {
			t.Errorf("Label(%q) = %q, want %q", dev, got, want)
		}
	}
}
