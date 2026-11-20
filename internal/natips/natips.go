// Package natips puts the public addresses of published servers (static
// NAT and port forwards on an address other than the interface's own) on
// their interfaces, so SJB-OS answers ARP for them. The nftables prerouting
// chain translates the traffic before routing, so it is forwarded to the
// server; nothing on the firewall itself listens on these addresses.
//
// ngfwd owns only the addresses it labelled (Label: "<dev>:nat"), so the
// deployment's addresses and the config's interface addresses are never
// touched.
package natips

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os/exec"
	"sort"
	"strings"
)

// Addr is one wanted public address.
type Addr struct {
	Dev  string     `json:"interface"`
	IP   netip.Addr `json:"address"`
	Name string     `json:"nat"` // the NAT entry, for display
}

// State reports whether a wanted address is on its interface.
type State struct {
	Addr
	Applied bool   `json:"applied"`
	Error   string `json:"error,omitempty"`
}

// Syncer makes the kernel's ngfwd-labelled addresses match want.
type Syncer interface {
	Sync(want []Addr) ([]State, error)
}

// Noop never touches the kernel (development on a machine without ip).
type Noop struct{}

// Sync reports every address as not applied.
func (Noop) Sync(want []Addr) ([]State, error) {
	out := make([]State, len(want))
	for i, a := range want {
		out[i] = State{Addr: a, Error: "addresses are not managed on this system"}
	}
	return out, nil
}

// Label is the address label ngfwd gives a public address on dev. Labels
// must start with the device name and fit in 15 characters.
func Label(dev string) string {
	if len(dev)+4 <= 15 {
		return dev + ":nat"
	}
	return dev + ":n"
}

func owned(dev, label string) bool {
	return label == dev+":nat" || label == dev+":n"
}

// Exec drives the ip command.
type Exec struct {
	Path string
	// Run executes ip with args; tests replace it.
	Run func(args ...string) ([]byte, error)
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

type link struct {
	IfName   string `json:"ifname"`
	AddrInfo []struct {
		Local     string `json:"local"`
		PrefixLen int    `json:"prefixlen"`
		Label     string `json:"label"`
	} `json:"addr_info"`
}

// Sync removes labelled addresses no longer wanted, then adds each wanted
// one that is missing. An address the interface already has for another
// reason (its own address) counts as applied and is left alone. A missing
// interface fails only its own addresses.
func (e Exec) Sync(want []Addr) ([]State, error) {
	out, err := e.run("-4", "-j", "addr", "show")
	if err != nil {
		return nil, err
	}
	var links []link
	if s := strings.TrimSpace(string(out)); s != "" {
		if err := json.Unmarshal([]byte(s), &links); err != nil {
			return nil, fmt.Errorf("reading addresses: %w", err)
		}
	}
	key := func(dev string, ip netip.Addr) string { return dev + " " + ip.String() }
	wanted := map[string]bool{}
	for _, a := range want {
		wanted[key(a.Dev, a.IP)] = true
	}
	devs := map[string]bool{}
	have := map[string]bool{} // any address on the device
	for _, l := range links {
		devs[l.IfName] = true
		for _, ai := range l.AddrInfo {
			ip, err := netip.ParseAddr(ai.Local)
			if err != nil {
				continue
			}
			k := key(l.IfName, ip)
			if owned(l.IfName, ai.Label) && !wanted[k] {
				if _, err := e.run("-4", "addr", "del", fmt.Sprintf("%s/%d", ip, ai.PrefixLen), "dev", l.IfName); err != nil {
					return nil, fmt.Errorf("removing %s from %s: %w", ip, l.IfName, err)
				}
				continue
			}
			have[k] = true
		}
	}
	states := make([]State, 0, len(want))
	for _, a := range want {
		s := State{Addr: a}
		switch {
		case have[key(a.Dev, a.IP)]:
			s.Applied = true
		case !devs[a.Dev]:
			s.Error = fmt.Sprintf("interface %s does not exist yet", a.Dev)
		default:
			if _, err := e.run("-4", "addr", "add", a.IP.String()+"/32", "dev", a.Dev, "label", Label(a.Dev)); err != nil {
				s.Error = err.Error()
			} else {
				s.Applied = true
			}
		}
		states = append(states, s)
	}
	sort.SliceStable(states, func(i, j int) bool { return states[i].Dev < states[j].Dev })
	return states, nil
}
