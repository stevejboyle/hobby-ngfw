package netdev

import (
	"strings"
	"testing"
)

type fakeIP struct {
	show  string
	calls []string
}

func (f *fakeIP) run(args ...string) ([]byte, error) {
	line := strings.Join(args, " ")
	if strings.HasPrefix(line, "-j -d addr show") {
		return []byte(f.show), nil
	}
	f.calls = append(f.calls, line)
	return nil, nil
}

const kernel = `[
 {"ifname":"lo","flags":["LOOPBACK","UP"],"addr_info":[]},
 {"ifname":"mgmt","flags":["UP"],"master":"vrf-mgmt","addr_info":[{"family":"inet","local":"10.0.2.15","prefixlen":24,"scope":"global"}]},
 {"ifname":"vrf-mgmt","flags":["UP"],"linkinfo":{"info_kind":"vrf","info_data":{"table":100}}},
 {"ifname":"inside","flags":["UP"],"addr_info":[{"family":"inet","local":"10.10.1.1","prefixlen":24,"scope":"global"}]},
 {"ifname":"outside","flags":["UP"]},
 {"ifname":"vrf-blue","flags":["UP"],"linkinfo":{"info_kind":"vrf","info_data":{"table":1001}}},
 {"ifname":"vrf-old","flags":["UP"],"linkinfo":{"info_kind":"vrf","info_data":{"table":1009}}},
 {"ifname":"inside.20","flags":["UP"],"link":"inside","master":"vrf-blue","linkinfo":{"info_kind":"vlan","info_data":{"id":20}},
  "addr_info":[{"family":"inet","local":"10.20.0.1","prefixlen":24,"scope":"global"}]},
 {"ifname":"inside.30","flags":[],"link":"inside","linkinfo":{"info_kind":"vlan","info_data":{"id":30}},
  "addr_info":[{"family":"inet","local":"10.30.0.9","prefixlen":24,"scope":"global"}]},
 {"ifname":"inside.99","flags":["UP"],"link":"inside","linkinfo":{"info_kind":"vlan","info_data":{"id":99}}}
]`

func TestSync(t *testing.T) {
	f := &fakeIP{show: kernel}
	states, err := Exec{Run: f.run}.Sync(Want{
		VRFs: []VRF{{Dev: "vrf-blue", Table: 1001}, {Dev: "vrf-red", Table: 1002}},
		VLANs: []VLAN{
			{Name: "inside.20", Parent: "inside", ID: 20, VRF: "vrf-blue", Addr: "10.20.0.1/24"}, // already right
			{Name: "inside.30", Parent: "inside", ID: 30, VRF: "vrf-red", Addr: "10.30.0.1/24"},  // move, readdress, up
			{Name: "outside.40", Parent: "outside", ID: 40, Addr: "192.0.2.1/24"},                // new, default VRF
			{Name: "ghost.50", Parent: "ghost", ID: 50},                                          // parent missing
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"link del inside.99",
		"link del vrf-old",
		"link add vrf-red type vrf table 1002",
		"link set vrf-red up",
		"link set inside.30 master vrf-red",
		"addr flush dev inside.30 scope global",
		"addr add 10.30.0.1/24 dev inside.30",
		"link set inside.30 up",
		"link add link outside name outside.40 type vlan id 40",
		"addr add 192.0.2.1/24 dev outside.40",
		"link set outside.40 up",
	}
	if got := strings.Join(f.calls, "\n"); got != strings.Join(want, "\n") {
		t.Fatalf("ip calls:\n%s\nwant:\n%s", got, strings.Join(want, "\n"))
	}
	if len(states) != 6 || !states[0].OK || !states[2].OK || states[5].OK || !strings.Contains(states[5].Error, "parent interface ghost") {
		t.Fatalf("states: %+v", states)
	}
}

func TestSyncRecreatesOnTableOrIDChange(t *testing.T) {
	f := &fakeIP{show: kernel}
	_, err := Exec{Run: f.run}.Sync(Want{
		VRFs:  []VRF{{Dev: "vrf-blue", Table: 1005}},
		VLANs: []VLAN{{Name: "inside.20", Parent: "inside", ID: 20, VRF: "vrf-blue", Addr: "10.20.0.1/24"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(f.calls, "\n")
	if !strings.Contains(got, "link del vrf-blue") || !strings.Contains(got, "link add vrf-blue type vrf table 1005") {
		t.Fatalf("table change should re-create the VRF:\n%s", got)
	}
}

func TestNeverTouchesFirstBootDevices(t *testing.T) {
	f := &fakeIP{show: kernel}
	if _, err := (Exec{Run: f.run}).Sync(Want{}); err != nil {
		t.Fatal(err)
	}
	for _, c := range f.calls {
		for _, dev := range []string{"vrf-mgmt", " mgmt", " inside ", " outside", " lo"} {
			if strings.Contains(c+" ", dev+" ") {
				t.Fatalf("touched %s: %s", dev, c)
			}
		}
	}
	if len(f.calls) != 5 { // inside.20, inside.30, inside.99, then vrf-blue, vrf-old
		t.Fatalf("an empty Want should remove only owned devices: %v", f.calls)
	}
}

func TestNeighbors(t *testing.T) {
	e := Exec{Run: func(args ...string) ([]byte, error) {
		if got := strings.Join(args, " "); got != "-4 -j neigh show" {
			t.Fatalf("args %q", got)
		}
		return []byte(`[{"dst":"192.168.1.1","dev":"outside","lladdr":"3c:61:04:ff:3e:81","state":["REACHABLE"]},
			{"dst":"10.10.1.50","dev":"inside","state":["FAILED"]}]`), nil
	}}
	nb, err := e.Neighbors()
	if err != nil {
		t.Fatal(err)
	}
	want := []Neighbor{{"192.168.1.1", "outside", "3c:61:04:ff:3e:81", "REACHABLE"}, {"10.10.1.50", "inside", "", "FAILED"}}
	if len(nb) != 2 || nb[0] != want[0] || nb[1] != want[1] {
		t.Fatalf("got %+v", nb)
	}
}
