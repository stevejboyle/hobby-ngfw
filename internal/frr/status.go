package frr

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// BGPPeer is one row of the BGP summary.
type BGPPeer struct {
	VRF      string `json:"vrf"`
	Address  string `json:"address"`
	RemoteAS uint32 `json:"remote_as"`
	State    string `json:"state"`
	Uptime   string `json:"uptime"`
	Received int    `json:"prefixes_received"`
	Sent     int    `json:"prefixes_sent"`
	Desc     string `json:"description,omitempty"`
}

// OSPFNeighbor is one OSPF adjacency.
type OSPFNeighbor struct {
	VRF       string `json:"vrf"`
	RouterID  string `json:"router_id"`
	State     string `json:"state"`
	Address   string `json:"address"`
	Interface string `json:"interface"`
}

// Route is one route from FRR's RIB.
type Route struct {
	VRF       string `json:"vrf"`
	Prefix    string `json:"prefix"`
	Protocol  string `json:"protocol"`
	NextHop   string `json:"next_hop"`
	Interface string `json:"interface"`
	Selected  bool   `json:"selected"`
}

// displayVRF shows SJB-OS VRF names, not FRR's device names.
func displayVRF(vrf string) string {
	if vrf == "" || vrf == "default" {
		return "default"
	}
	return strings.TrimPrefix(vrf, "vrf-")
}

func notRunning(out []byte, err error) bool {
	return err != nil && strings.Contains(string(out), "is not running")
}

// BGPSummary reads BGP neighbors in every VRF.
func BGPSummary(r Runner) ([]BGPPeer, error) {
	out, err := r.Show("show bgp vrf all summary json")
	if notRunning(out, err) {
		return []BGPPeer{}, nil
	}
	if err != nil {
		return nil, err
	}
	var top map[string]struct {
		IPv4 struct {
			Peers map[string]struct {
				RemoteAs   uint32 `json:"remoteAs"`
				State      string `json:"state"`
				PeerUptime string `json:"peerUptime"`
				PfxRcd     int    `json:"pfxRcd"`
				PfxSnt     int    `json:"pfxSnt"`
				Desc       string `json:"desc"`
			} `json:"peers"`
		} `json:"ipv4Unicast"`
	}
	if err := json.Unmarshal(out, &top); err != nil {
		return nil, fmt.Errorf("reading BGP summary: %w", err)
	}
	peers := []BGPPeer{}
	for vrf, v := range top {
		for addr, p := range v.IPv4.Peers {
			peers = append(peers, BGPPeer{VRF: displayVRF(vrf), Address: addr, RemoteAS: p.RemoteAs, State: p.State,
				Uptime: p.PeerUptime, Received: p.PfxRcd, Sent: p.PfxSnt, Desc: p.Desc})
		}
	}
	sort.Slice(peers, func(i, j int) bool {
		return peers[i].VRF+" "+peers[i].Address < peers[j].VRF+" "+peers[j].Address
	})
	return peers, nil
}

// OSPFNeighbors reads OSPF adjacencies in every VRF.
func OSPFNeighbors(r Runner) ([]OSPFNeighbor, error) {
	out, err := r.Show("show ip ospf vrf all neighbor json")
	if notRunning(out, err) {
		return []OSPFNeighbor{}, nil
	}
	if err != nil {
		return nil, err
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(out, &top); err != nil {
		return nil, fmt.Errorf("reading OSPF neighbors: %w", err)
	}
	nbrs := []OSPFNeighbor{}
	add := func(vrf string, raw json.RawMessage) {
		var v struct {
			Neighbors map[string][]map[string]any `json:"neighbors"`
		}
		if json.Unmarshal(raw, &v) != nil {
			return
		}
		for id, list := range v.Neighbors {
			for _, n := range list {
				nbrs = append(nbrs, OSPFNeighbor{VRF: displayVRF(vrf), RouterID: id,
					State: str(n, "nbrState", "state"), Address: str(n, "ifaceAddress", "address"),
					Interface: strings.SplitN(str(n, "ifaceName", "interface"), ":", 2)[0]})
			}
		}
	}
	if _, single := top["neighbors"]; single { // one VRF: no wrapping
		add("default", out)
	} else {
		for vrf, raw := range top {
			add(vrf, raw)
		}
	}
	sort.Slice(nbrs, func(i, j int) bool { return nbrs[i].VRF+nbrs[i].RouterID < nbrs[j].VRF+nbrs[j].RouterID })
	return nbrs, nil
}

func str(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if s, ok := m[k].(string); ok {
			return s
		}
	}
	return ""
}

// Routes reads FRR's routing table for one VRF ("" for all).
func Routes(r Runner, vrf string) ([]Route, error) {
	cmd := "show ip route vrf all json"
	if vrf != "" {
		dev := vrf
		if vrf != "default" {
			dev = "vrf-" + vrf
		}
		cmd = "show ip route vrf " + dev + " json"
	}
	out, err := r.Show(cmd)
	if err != nil {
		return nil, err
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(out, &top); err != nil {
		return nil, fmt.Errorf("reading routes: %w", err)
	}
	routes := []Route{}
	addTable := func(vrfName string, table map[string]json.RawMessage) {
		for prefix, raw := range table {
			var entries []struct {
				Protocol string `json:"protocol"`
				Selected bool   `json:"selected"`
				Nexthops []struct {
					IP            string `json:"ip"`
					InterfaceName string `json:"interfaceName"`
				} `json:"nexthops"`
			}
			if json.Unmarshal(raw, &entries) != nil {
				continue
			}
			for _, e := range entries {
				rt := Route{VRF: displayVRF(vrfName), Prefix: prefix, Protocol: e.Protocol, Selected: e.Selected}
				if len(e.Nexthops) > 0 {
					rt.NextHop, rt.Interface = e.Nexthops[0].IP, e.Nexthops[0].InterfaceName
				}
				routes = append(routes, rt)
			}
		}
	}
	// "vrf all" wraps tables in VRF names; one VRF is a bare table.
	wrapped := false
	for k, raw := range top {
		if strings.Contains(k, "/") {
			continue
		}
		var table map[string]json.RawMessage
		if json.Unmarshal(raw, &table) == nil {
			addTable(k, table)
			wrapped = true
		}
	}
	if !wrapped {
		name := vrf
		if name == "" {
			name = "default"
		}
		addTable(name, top)
	}
	sort.Slice(routes, func(i, j int) bool {
		if routes[i].VRF != routes[j].VRF {
			return routes[i].VRF < routes[j].VRF
		}
		return routes[i].Prefix < routes[j].Prefix
	})
	return routes, nil
}
