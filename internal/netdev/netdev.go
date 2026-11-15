// Package netdev keeps the kernel's VRF devices and VLAN subinterfaces in
// step with the config. ngfwd owns only what it creates: VRF devices named
// vrf-<name> (never vrf-mgmt, which first boot owns) and interfaces whose
// name contains a dot (VLAN subinterfaces such as inside.20). The physical
// mgmt, inside and outside interfaces are never touched.
package netdev

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"slices"
	"strconv"
	"strings"
)

// VRF is a wanted VRF device.
type VRF struct {
	Dev   string `json:"device"` // vrf-<name>
	Table int    `json:"table"`
}

// VLAN is a wanted VLAN subinterface.
type VLAN struct {
	Name   string `json:"name"`   // inside.20
	Parent string `json:"parent"` // inside
	ID     int    `json:"vlan"`
	VRF    string `json:"vrf_device,omitempty"` // vrf-<name>, or "" for the default VRF
	Addr   string `json:"address,omitempty"`    // CIDR, or "" for none
}

// Want is everything ngfwd should have in place.
type Want struct {
	VRFs  []VRF
	VLANs []VLAN
}

// State reports one wanted device.
type State struct {
	Name  string `json:"name"`
	Kind  string `json:"kind"` // vrf or vlan
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// Syncer makes the kernel match a Want.
type Syncer interface {
	Sync(Want) ([]State, error)
}

// Noop changes nothing (development machines without ip).
type Noop struct{}

// Sync reports every device as not in place.
func (Noop) Sync(w Want) ([]State, error) {
	var out []State
	for _, v := range w.VRFs {
		out = append(out, State{Name: v.Dev, Kind: "vrf", Error: "devices are not managed on this system"})
	}
	for _, v := range w.VLANs {
		out = append(out, State{Name: v.Name, Kind: "vlan", Error: "devices are not managed on this system"})
	}
	return out, nil
}

// Exec drives the ip command.
type Exec struct {
	Path string
	Run  func(args ...string) ([]byte, error) // tests replace it
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
	Name     string `json:"ifname"`
	Master   string `json:"master"`
	Parent   string `json:"link"`
	OperUp   string `json:"operstate"`
	Flags    []string
	LinkInfo struct {
		Kind string `json:"info_kind"`
		Data struct {
			Table int `json:"table"`
			ID    int `json:"id"`
		} `json:"info_data"`
	} `json:"linkinfo"`
	AddrInfo []struct {
		Family string `json:"family"`
		Local  string `json:"local"`
		Prefix int    `json:"prefixlen"`
		Scope  string `json:"scope"`
	} `json:"addr_info"`
}

func (l link) owned() bool {
	switch l.LinkInfo.Kind {
	case "vrf":
		return strings.HasPrefix(l.Name, "vrf-") && l.Name != "vrf-mgmt"
	case "vlan":
		return strings.Contains(l.Name, ".")
	}
	return false
}

func (l link) up() bool { return slices.Contains(l.Flags, "UP") }

func (l link) addrs() []string {
	var out []string
	for _, a := range l.AddrInfo {
		if a.Family == "inet" && a.Scope == "global" {
			out = append(out, a.Local+"/"+strconv.Itoa(a.Prefix))
		}
	}
	return out
}

// Sync removes owned devices that aren't wanted, then creates or fixes the
// wanted ones. A device that can't be set up (say, its parent is missing)
// gets an error State; the others still go ahead.
func (e Exec) Sync(w Want) ([]State, error) {
	out, err := e.run("-j", "-d", "addr", "show")
	if err != nil {
		return nil, err
	}
	var links []link
	if err := json.Unmarshal(out, &links); err != nil {
		return nil, fmt.Errorf("reading interfaces: %w", err)
	}
	have := map[string]link{}
	for _, l := range links {
		have[l.Name] = l
	}
	wantVRF := map[string]VRF{}
	for _, v := range w.VRFs {
		wantVRF[v.Dev] = v
	}
	wantVLAN := map[string]VLAN{}
	for _, v := range w.VLANs {
		wantVLAN[v.Name] = v
	}

	// Remove owned devices that are no longer wanted, or that differ in a
	// way only re-creating fixes (VRF table, VLAN id or parent). VLANs first:
	// they may be enslaved to a VRF being removed.
	for _, kind := range []string{"vlan", "vrf"} {
		for _, l := range links {
			if l.LinkInfo.Kind != kind || !l.owned() {
				continue
			}
			keep := false
			switch kind {
			case "vlan":
				v, ok := wantVLAN[l.Name]
				keep = ok && v.ID == l.LinkInfo.Data.ID && v.Parent == l.Parent
			case "vrf":
				v, ok := wantVRF[l.Name]
				keep = ok && v.Table == l.LinkInfo.Data.Table
			}
			if !keep {
				if _, err := e.run("link", "del", l.Name); err != nil {
					return nil, err
				}
				delete(have, l.Name)
			}
		}
	}

	var states []State
	for _, v := range w.VRFs {
		st := State{Name: v.Dev, Kind: "vrf"}
		err := e.vrf(v, have)
		if err != nil {
			st.Error = err.Error()
		}
		st.OK = err == nil
		states = append(states, st)
	}
	for _, v := range w.VLANs {
		st := State{Name: v.Name, Kind: "vlan"}
		err := e.vlan(v, have)
		if err != nil {
			st.Error = err.Error()
		}
		st.OK = err == nil
		states = append(states, st)
	}
	return states, nil
}

func (e Exec) vrf(v VRF, have map[string]link) error {
	l, ok := have[v.Dev]
	if !ok {
		if _, err := e.run("link", "add", v.Dev, "type", "vrf", "table", strconv.Itoa(v.Table)); err != nil {
			return err
		}
	}
	if !ok || !l.up() {
		if _, err := e.run("link", "set", v.Dev, "up"); err != nil {
			return err
		}
	}
	return nil
}

func (e Exec) vlan(v VLAN, have map[string]link) error {
	if _, ok := have[v.Parent]; !ok {
		return fmt.Errorf("parent interface %s does not exist", v.Parent)
	}
	l, ok := have[v.Name]
	if !ok {
		if _, err := e.run("link", "add", "link", v.Parent, "name", v.Name, "type", "vlan", "id", strconv.Itoa(v.ID)); err != nil {
			return err
		}
	}
	if l.Master != v.VRF || !ok {
		if v.VRF != "" {
			if _, err := e.run("link", "set", v.Name, "master", v.VRF); err != nil {
				return err
			}
		} else if l.Master != "" {
			if _, err := e.run("link", "set", v.Name, "nomaster"); err != nil {
				return err
			}
		}
	}
	cur := l.addrs()
	if !(len(cur) == 1 && cur[0] == v.Addr) && !(len(cur) == 0 && v.Addr == "") {
		if len(cur) > 0 {
			if _, err := e.run("addr", "flush", "dev", v.Name, "scope", "global"); err != nil {
				return err
			}
		}
		if v.Addr != "" {
			if _, err := e.run("addr", "add", v.Addr, "dev", v.Name); err != nil {
				return err
			}
		}
	}
	if !ok || !l.up() {
		if _, err := e.run("link", "set", v.Name, "up"); err != nil {
			return err
		}
	}
	return nil
}

// Neighbor is one IPv4 ARP table entry.
type Neighbor struct {
	Address   string `json:"address"`
	Interface string `json:"interface"`
	MAC       string `json:"mac,omitempty"`
	State     string `json:"state"`
}

// Neighbors reads the kernel's IPv4 ARP table (all interfaces and VRFs).
func (e Exec) Neighbors() ([]Neighbor, error) {
	out, err := e.run("-4", "-j", "neigh", "show")
	if err != nil {
		return nil, err
	}
	var raw []struct {
		Dst    string   `json:"dst"`
		Dev    string   `json:"dev"`
		LLAddr string   `json:"lladdr"`
		State  []string `json:"state"`
	}
	if s := strings.TrimSpace(string(out)); s != "" {
		if err := json.Unmarshal([]byte(s), &raw); err != nil {
			return nil, fmt.Errorf("reading the ARP table: %w", err)
		}
	}
	nb := make([]Neighbor, 0, len(raw))
	for _, r := range raw {
		nb = append(nb, Neighbor{Address: r.Dst, Interface: r.Dev, MAC: r.LLAddr, State: strings.Join(r.State, " ")})
	}
	return nb, nil
}
