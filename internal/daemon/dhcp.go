package daemon

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/stevejboyle/hobby-ngfw/internal/config"
	"github.com/stevejboyle/hobby-ngfw/internal/dhcp"
)

// SetDHCP sets how DHCP servers are run. Call before Start.
func (d *Daemon) SetDHCP(r dhcp.Runner) { d.dhcp = r }

// syncDHCPLocked compiles the running config's DHCP servers and applies
// them to Kea if they changed. With atCommit false (ngfwd's periodic pass)
// it waits while the firewall doesn't know its own DNS servers yet (at boot
// networkd may not have them for a while), rather than restarting Kea with
// a config that lacks them. Callers hold d.mu.
func (d *Daemon) syncDHCPLocked(atCommit bool) []string {
	if d.running == nil {
		return nil
	}
	want := dhcp.Compile(d.running, d.dhcp.Options())
	if !d.dhcp.Available() {
		if want.Enabled() {
			return []string{"DHCP servers configured but Kea isn't installed yet (an upgrade installs it in the background); they start once it is"}
		}
		return nil
	}
	if !atCommit && len(want.Warnings) > 0 && d.Now().Sub(d.started) < 2*time.Minute {
		return want.Warnings
	}
	if want.Conf == d.dhcpApplied {
		return want.Warnings
	}
	if err := d.dhcp.Apply(want); err != nil {
		return append(want.Warnings, fmt.Sprintf("DHCP config not applied to Kea yet: %v; ngfwd keeps trying", err))
	}
	d.dhcpApplied = want.Conf
	d.dhcpSubnets = want.Subnets
	return want.Warnings
}

// checkDHCP has Kea check the DHCP config of cfg before a commit applies
// anything.
func (d *Daemon) checkDHCP(cfg *config.Config) error {
	if len(cfg.DHCPServers) == 0 || !d.dhcp.Available() {
		return nil
	}
	if err := d.dhcp.Check(dhcp.Compile(cfg, d.dhcp.Options()).CheckConf); err != nil {
		return fmt.Errorf("%w: DHCP config rejected by Kea, nothing applied: %v", ErrInvalid, err)
	}
	return nil
}

// DHCPServer reports one configured DHCP server as it is handed out.
type DHCPServer struct {
	Interface    string   `json:"interface"`
	Network      string   `json:"network"`
	Range        string   `json:"range"`
	Gateway      string   `json:"gateway"`
	DNS          []string `json:"dns"`
	DNSDefault   bool     `json:"dns_default"` // dns is the firewall's own
	Domain       string   `json:"domain,omitempty"`
	LeaseTime    int      `json:"lease_time"`
	Reservations int      `json:"reservations"`
	Leases       int      `json:"leases"` // active leases
}

// DHCPStatus is what `show dhcp` and the web UI show.
type DHCPStatus struct {
	Installed bool         `json:"installed"`
	Running   bool         `json:"running"`
	Error     string       `json:"error,omitempty"`
	Servers   []DHCPServer `json:"servers"`
}

// DHCPLease is an address handed out.
type DHCPLease struct {
	Interface string    `json:"interface"`
	Address   string    `json:"address"`
	MAC       string    `json:"mac"`
	Hostname  string    `json:"hostname,omitempty"`
	Expires   time.Time `json:"expires"`
	State     string    `json:"state"`              // active, declined, expired
	Reserved  string    `json:"reserved,omitempty"` // reservation name
}

// DHCP reports the running config's DHCP servers and Kea's state.
func (d *Daemon) DHCP() DHCPStatus {
	d.mu.Lock()
	cfg := d.running
	d.mu.Unlock()
	st := DHCPStatus{Installed: d.dhcp.Available(), Servers: []DHCPServer{}}
	if cfg == nil {
		return st
	}
	st.Running = st.Installed && d.dhcp.Running()
	opts := d.dhcp.Options()
	counts := map[string]int{}
	if st.Running {
		if leases, err := d.DHCPLeases(""); err != nil {
			st.Error = err.Error()
		} else {
			for _, l := range leases {
				if l.State == "active" {
					counts[l.Interface]++
				}
			}
		}
	}
	for _, s := range cfg.DHCPServers {
		addr, _ := cfg.InterfaceAddress(s.Name)
		srv := DHCPServer{Interface: s.Name, Network: addr.Masked().String(), Range: s.Range, Gateway: s.Gateway,
			DNS: s.DNS, Domain: s.Domain, LeaseTime: s.LeaseTime, Leases: counts[s.Name]}
		if srv.Gateway == "" {
			srv.Gateway = addr.Addr().String()
		}
		if len(srv.DNS) == 0 {
			srv.DNS, srv.DNSDefault = opts.DNS, true
		}
		if srv.DNS == nil {
			srv.DNS = []string{}
		}
		if srv.LeaseTime == 0 {
			srv.LeaseTime = config.DefaultLeaseTime
		}
		for _, r := range cfg.DHCPReservations {
			if r.Interface == s.Name {
				srv.Reservations++
			}
		}
		st.Servers = append(st.Servers, srv)
	}
	return st
}

// DHCPLeases returns Kea's leases, optionally for one interface, sorted by
// interface and address.
func (d *Daemon) DHCPLeases(iface string) ([]DHCPLease, error) {
	d.mu.Lock()
	cfg, subnets := d.running, d.dhcpSubnets
	d.mu.Unlock()
	if !d.dhcp.Available() {
		return nil, fmt.Errorf("%w: Kea (the DHCP server) is not installed on this appliance yet", ErrInvalid)
	}
	raw, err := d.dhcp.Leases()
	if err != nil {
		return nil, err
	}
	reserved := map[string]string{}
	if cfg != nil {
		for _, r := range cfg.DHCPReservations {
			reserved[r.Interface+" "+strings.ToLower(r.MAC)] = r.Name
		}
	}
	out := []DHCPLease{}
	for _, l := range raw {
		nic := subnets[l.SubnetID]
		if nic == "" {
			nic = fmt.Sprintf("subnet %d", l.SubnetID)
		}
		if iface != "" && nic != iface {
			continue
		}
		state := map[int]string{0: "active", 1: "declined", 2: "expired"}[l.State]
		exp := time.Unix(l.CLTT+l.Valid, 0)
		if state == "active" && exp.Before(d.Now()) {
			state = "expired"
		}
		out = append(out, DHCPLease{Interface: nic, Address: l.Address, MAC: l.MAC, Hostname: strings.TrimSuffix(l.Hostname, "."),
			Expires: exp, State: state, Reserved: reserved[nic+" "+strings.ToLower(l.MAC)]})
	}
	slices.SortFunc(out, func(a, b DHCPLease) int {
		if c := strings.Compare(a.Interface, b.Interface); c != 0 {
			return c
		}
		return compareIP(a.Address, b.Address)
	})
	return out, nil
}

func compareIP(a, b string) int {
	pa, pb := ipKey(a), ipKey(b)
	return strings.Compare(pa, pb)
}

func ipKey(s string) string {
	var b strings.Builder
	for _, p := range strings.Split(s, ".") {
		fmt.Fprintf(&b, "%03s.", p)
	}
	return b.String()
}

// ZoneOf names the zone of an interface in the running config ("" if none),
// for the traffic log.
func (d *Daemon) ZoneOf(iface string) string {
	d.mu.Lock()
	cfg := d.running
	d.mu.Unlock()
	if cfg == nil {
		return ""
	}
	for _, in := range cfg.Interfaces {
		if in.Name == iface {
			return in.Zone
		}
	}
	return ""
}
