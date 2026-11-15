package routes

import (
	"errors"
	"strings"
	"testing"
	"time"
)

type fakeIP struct {
	show     string
	defaults string // output of "route list default table main"
	later    string // if set, what that listing returns from the second call on
	listed   int
	calls    []string
	fail     map[string]bool // destination -> replace fails
}

func (f *fakeIP) run(args ...string) ([]byte, error) {
	line := strings.Join(args, " ")
	f.calls = append(f.calls, line)
	if strings.Contains(line, "route list default") {
		f.listed++
		if f.later != "" && f.listed > 1 {
			return []byte(f.later), nil
		}
		return []byte(f.defaults), nil
	}
	if strings.Contains(line, "route show") {
		return []byte(f.show), nil
	}
	for dst := range f.fail {
		if strings.Contains(line, "replace "+dst+" ") {
			return []byte("Error: Nexthop has invalid gateway."), errors.New("exit status 2")
		}
	}
	return nil, nil
}

func (f *fakeIP) changes() []string {
	var out []string
	for _, c := range f.calls {
		if !strings.Contains(c, "route show") && !strings.Contains(c, "route list") {
			out = append(out, c)
		}
	}
	return out
}

func TestSync(t *testing.T) {
	f := &fakeIP{
		show: `[{"dst":"10.20.0.0/16","gateway":"10.10.1.254","dev":"inside","protocol":"sjb"},
		        {"dst":"10.99.0.0/16","gateway":"10.10.1.254","dev":"inside","protocol":"sjb"},
		        {"dst":"192.0.2.0/24","gateway":"10.0.2.2","dev":"mgmt","table":"100","protocol":"sjb"}]`,
		fail: map[string]bool{"10.40.0.0/16": true},
	}
	e := Exec{Run: f.run}
	states, err := e.Sync([]Route{
		{Name: "lab", Dest: "10.20.0.0/16", Gateway: "10.10.1.254"},                               // unchanged
		{Name: "moved", Dest: "192.0.2.0/24", Gateway: "10.0.2.3", Dev: "mgmt", Table: MgmtTable}, // gateway changed
		{Name: "new", Dest: "10.30.0.0/16", Gateway: "10.10.1.254", Dev: "inside"},
		{Name: "unreachable", Dest: "10.40.0.0/16", Gateway: "172.31.0.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"-4 route del 10.99.0.0/16 table main proto 222",
		"-4 route replace 192.0.2.0/24 via 10.0.2.3 dev mgmt table 100 proto 222",
		"-4 route replace 10.30.0.0/16 via 10.10.1.254 dev inside table main proto 222",
		"-4 route replace 10.40.0.0/16 via 172.31.0.1 table main proto 222",
	}
	if got := f.changes(); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("ip calls:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if len(states) != 4 || !states[0].Installed || !states[1].Installed || !states[2].Installed {
		t.Fatalf("states: %+v", states)
	}
	if states[3].Installed || !strings.Contains(states[3].Error, "isn't on a connected network") {
		t.Fatalf("failed route state: %+v", states[3])
	}
}

func TestSyncEmpty(t *testing.T) {
	f := &fakeIP{show: ""}
	states, err := Exec{Run: f.run}.Sync(nil)
	if err != nil || len(states) != 0 || len(f.changes()) != 0 {
		t.Fatalf("empty sync: %v %v %v", states, err, f.changes())
	}
}

func TestSyncRemovesAll(t *testing.T) {
	f := &fakeIP{show: `[{"dst":"10.20.0.0/16","gateway":"10.10.1.254","dev":"inside"}]`}
	if _, err := (Exec{Run: f.run}).Sync(nil); err != nil {
		t.Fatal(err)
	}
	if got := f.changes(); len(got) != 1 || !strings.HasPrefix(got[0], "-4 route del 10.20.0.0/16") {
		t.Fatalf("calls: %v", got)
	}
}

func TestSyncVRFRoutes(t *testing.T) {
	f := &fakeIP{show: ""}
	_, err := Exec{Run: f.run}.Sync([]Route{
		{Name: "blue-net", Dest: "10.40.0.0/16", Gateway: "10.20.0.254", Table: 1002, VRFDev: "vrf-blue"},
		{Name: "leak", Dest: "10.30.0.0/16", Dev: "vrf-red", Table: 1002, VRFDev: "vrf-blue"},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := "-4 route replace 10.40.0.0/16 via 10.20.0.254 vrf vrf-blue proto 222\n-4 route replace 10.30.0.0/16 dev vrf-red vrf vrf-blue proto 222"
	if got := strings.Join(f.changes(), "\n"); got != want {
		t.Fatalf("calls:\n%s\nwant:\n%s", got, want)
	}
}

func TestSyncDefaultRoute(t *testing.T) {
	f := &fakeIP{}
	e := Exec{Run: f.run}
	st, err := e.Sync([]Route{{Name: "def", Dest: DefaultDest, Gateway: "203.0.113.1", Dev: "outside"}})
	if err != nil || !st[0].Installed {
		t.Fatalf("sync: %v %+v", err, st)
	}
	want := "-4 route replace 0.0.0.0/0 via 203.0.113.1 dev outside table main proto 222"
	if got := strings.Join(f.changes(), "\n"); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}

	// The kernel lists it as "default": already installed, no churn.
	f = &fakeIP{show: `[{"dst":"default","gateway":"203.0.113.1","dev":"outside","protocol":"sjb"}]`}
	e = Exec{Run: f.run}
	if st, err := e.Sync([]Route{{Name: "def", Dest: DefaultDest, Gateway: "203.0.113.1", Dev: "outside"}}); err != nil || !st[0].Installed || len(f.changes()) != 0 {
		t.Fatalf("re-sync: %v %+v %q", err, st, f.changes())
	}
}

func TestSyncRemovedDefaultRestoresDeployment(t *testing.T) {
	for _, tc := range []struct {
		name     string
		defaults string
		later    string
		restore  bool
	}{
		{"none left", "[]", "", true},
		{"dhcp default still there", `[{"dst":"default","gateway":"10.0.2.2","dev":"outside","protocol":"dhcp"}]`, "", false},
		// FRR installs the BGP default it was holding back only once ours is
		// gone: give it time, don't reconfigure the NIC under it.
		{"bgp default arrives shortly", "[]", `[{"dst":"default","gateway":"203.0.113.1","dev":"outside","protocol":"bgp","metric":20}]`, false},
	} {
		f := &fakeIP{show: `[{"dst":"default","gateway":"203.0.113.1","dev":"outside","protocol":"sjb"}]`, defaults: tc.defaults, later: tc.later}
		restored := false
		e := Exec{Run: f.run, RestoreDefault: func() error { restored = true; return nil }, DefaultWait: time.Second}
		if _, err := e.Sync(nil); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got := strings.Join(f.changes(), "\n"); got != "-4 route del 0.0.0.0/0 table main proto 222" {
			t.Fatalf("%s: changes %q", tc.name, got)
		}
		if restored != tc.restore {
			t.Fatalf("%s: restored=%v, want %v", tc.name, restored, tc.restore)
		}
	}
}
