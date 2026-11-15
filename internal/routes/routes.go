// Package routes installs the config's static routes in the kernel. ngfwd
// owns only the routes it tagged with its own protocol number, so routes
// from the deployment settings (systemd-networkd) are never deleted.
//
// The one overlap is a configured default route in the main table. It takes
// over from the deployment's default: it has metric 0, so it wins over a
// DHCP default (metric 1024) and replaces a static Gateway= default (also
// metric 0) outright. When it is removed and no default route turns up
// shortly (a routing protocol's default that ours was hiding, or DHCP's),
// RestoreDefault asks networkd to put the deployment's default back.
package routes

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Proto marks routes installed by ngfwd (`ip route ... proto 222`). 222 is
// unassigned in iproute2's rt_protos; sjb-migrate names it "sjb".
const Proto = 222

// MgmtTable is the routing table of the management VRF (vrf-mgmt).
const MgmtTable = 100

// Route is one wanted route.
type Route struct {
	Name    string `json:"name"`
	Dest    string `json:"destination"`
	Gateway string `json:"gateway"`
	Dev     string `json:"interface,omitempty"`
	Table   int    `json:"table"` // 0 = main
	// VRFDev, when set, adds the route with "vrf <dev>" so the gateway is
	// looked up in that VRF (its table is Table).
	VRFDev string `json:"vrf_device,omitempty"`
	VRF    string `json:"vrf,omitempty"` // for display
}

// State reports whether a wanted route is in the kernel.
type State struct {
	Route
	Installed bool   `json:"installed"`
	Error     string `json:"error,omitempty"`
}

// Syncer makes the kernel's ngfwd-owned routes match want.
type Syncer interface {
	Sync(want []Route) ([]State, error)
}

// Noop never touches the kernel (development on a machine without ip).
type Noop struct{}

// Sync reports every route as not installed.
func (Noop) Sync(want []Route) ([]State, error) {
	out := make([]State, len(want))
	for i, r := range want {
		out[i] = State{Route: r, Error: "routes are not managed on this system"}
	}
	return out, nil
}

// Exec drives the ip command.
type Exec struct {
	Path string
	// Run executes ip with args; tests replace it.
	Run func(args ...string) ([]byte, error)
	// RestoreDefault re-applies the deployment's network settings after a
	// configured main-table default route was removed and none is left.
	RestoreDefault func() error
	// DefaultWait is how long Sync waits for another default route to turn
	// up before calling RestoreDefault (default 3 s). FRR keeps a BGP or
	// OSPF default out of the kernel while ours is there, and installs it
	// only after ours is gone.
	DefaultWait time.Duration
}

// defaultAppears reports whether the main table has a default route, or
// gets one within DefaultWait. A failed listing counts as having one: never
// disturb networkd on a guess.
func (e Exec) defaultAppears() bool {
	wait := e.DefaultWait
	if wait == 0 {
		wait = 3 * time.Second
	}
	for end := time.Now().Add(wait); ; {
		out, err := e.run("-4", "-j", "route", "list", "default", "table", "main")
		if err != nil || hasRoutes(out) {
			return true
		}
		if !time.Now().Before(end) {
			return false
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// DefaultDest is the destination of a default route.
const DefaultDest = "0.0.0.0/0"

// kernelDst normalises the kernel's name for a destination ("default").
func kernelDst(s string) string {
	if s == "default" {
		return DefaultDest
	}
	return s
}

func (e Exec) run(args ...string) ([]byte, error) {
	var out []byte
	var err error
	if e.Run != nil {
		out, err = e.Run(args...)
	} else {
		path := e.Path
		if path == "" {
			path = "ip"
		}
		out, err = exec.Command(path, args...).CombinedOutput()
	}
	if err != nil {
		return out, fmt.Errorf("ip %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

type kernelRoute struct {
	Dst     string `json:"dst"`
	Gateway string `json:"gateway"`
	Dev     string `json:"dev"`
	Table   string `json:"table"`
}

func hasRoutes(out []byte) bool {
	s := strings.TrimSpace(string(out))
	return s != "" && s != "[]"
}

func tableNum(s string) (int, bool) {
	switch s {
	case "", "main":
		return 0, true
	}
	n, err := strconv.Atoi(s)
	return n, err == nil
}

func tableArg(t int) string {
	if t == 0 {
		return "main"
	}
	return strconv.Itoa(t)
}

func key(dst string, table int) string { return fmt.Sprintf("%d %s", table, dst) }

// Sync removes ngfwd-owned routes that are no longer wanted, then adds or
// replaces each wanted one. One failing route does not stop the others;
// its State says why. The error is for failures to read the kernel's
// routes at all.
func (e Exec) Sync(want []Route) ([]State, error) {
	out, err := e.run("-4", "-j", "route", "show", "table", "all", "proto", strconv.Itoa(Proto))
	if err != nil {
		return nil, err
	}
	var have []kernelRoute
	if s := strings.TrimSpace(string(out)); s != "" {
		if err := json.Unmarshal([]byte(s), &have); err != nil {
			return nil, fmt.Errorf("reading routes: %w", err)
		}
	}
	wanted := map[string]Route{}
	for _, r := range want {
		wanted[key(r.Dest, r.Table)] = r
	}
	current := map[string]kernelRoute{}
	removedDefault := false
	for _, k := range have {
		t, ok := tableNum(k.Table)
		if !ok {
			continue
		}
		dst := kernelDst(k.Dst)
		current[key(dst, t)] = k
		if _, keep := wanted[key(dst, t)]; !keep {
			if _, err := e.run("-4", "route", "del", dst, "table", tableArg(t), "proto", strconv.Itoa(Proto)); err != nil {
				return nil, fmt.Errorf("removing %s: %w", dst, err)
			}
			if dst == DefaultDest && t == 0 {
				removedDefault = true
			}
		}
	}
	if removedDefault && e.RestoreDefault != nil {
		// Ours may have replaced the deployment's default; if nothing
		// takes over, have networkd put it back.
		if !e.defaultAppears() {
			if err := e.RestoreDefault(); err != nil {
				return nil, fmt.Errorf("restoring the deployment's default route: %w", err)
			}
		}
	}

	states := make([]State, 0, len(want))
	for _, r := range want {
		st := State{Route: r}
		k, ok := current[key(r.Dest, r.Table)]
		if ok && k.Gateway == r.Gateway && (r.Dev == "" || k.Dev == r.Dev) {
			st.Installed = true // already right; don't churn the kernel every pass
		} else {
			args := []string{"-4", "route", "replace", r.Dest}
			if r.Gateway != "" {
				args = append(args, "via", r.Gateway)
			}
			if r.Dev != "" {
				args = append(args, "dev", r.Dev)
			}
			if r.VRFDev != "" {
				args = append(args, "vrf", r.VRFDev)
			} else {
				args = append(args, "table", tableArg(r.Table))
			}
			args = append(args, "proto", strconv.Itoa(Proto))
			if _, err := e.run(args...); err != nil {
				st.Error = explain(r, err)
			} else {
				st.Installed = true
			}
		}
		states = append(states, st)
	}
	return states, nil
}

// explain turns ip's terse errors into what to check.
func explain(r Route, err error) string {
	msg := err.Error()
	if r.Gateway != "" && (strings.Contains(msg, "invalid gateway") || strings.Contains(msg, "Network is unreachable")) {
		vrf := r.VRF
		if vrf == "" {
			vrf = "default"
		}
		where := "no interface in vrf " + vrf + " has an address on its network"
		if r.Dev != "" {
			where = "interface " + r.Dev + " has no address on its network"
		}
		return fmt.Sprintf("gateway %s isn't on a connected network: %s (check show interfaces)", r.Gateway, where)
	}
	return msg
}
