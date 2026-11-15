// Package dhcp turns the config's DHCP servers into a Kea DHCPv4 config
// (/etc/kea/kea-dhcp4.conf), applies it, and reads leases back.
//
// Kea ships inside upgrade bundles like FRR. ngfwd owns its config file: it
// lists only the interfaces the config serves, so with no DHCP servers Kea
// is stopped and disabled. Each served interface gets one subnet bound to
// it, with an ID derived from the interface name so leases survive config
// changes.
package dhcp

import (
	"encoding/json"
	"hash/crc32"
	"net/netip"
	"sort"
	"strings"

	"github.com/stevejboyle/hobby-ngfw/internal/config"
)

// Paths Kea uses on the appliance (Debian's kea-dhcp4-server).
const (
	ConfPath    = "/etc/kea/kea-dhcp4.conf"
	SocketPath  = "/run/kea/kea4-ctrl-socket"
	LeaseFile   = "/var/lib/kea/kea-leases4.csv"
	LeaseHook   = "libdhcp_lease_cmds.so"
	DefaultHook = "/usr/lib/x86_64-linux-gnu/kea/hooks"
)

// Options are facts about the appliance the config doesn't hold.
type Options struct {
	// DNS is what clients get when a server sets no dns: the firewall's own
	// upstream DNS servers.
	DNS []string
	// HooksDir holds Kea's hook libraries (default DefaultHook).
	HooksDir string
}

// Result is a compiled Kea config.
type Result struct {
	Conf string
	// CheckConf is Conf without interface names, for kea-dhcp4 -t at commit:
	// Kea refuses interfaces that don't exist yet, and a commit may create
	// the VLAN it serves. The config package checks the interfaces instead.
	CheckConf  string
	Interfaces []string       // served interfaces, sorted
	Subnets    map[int]string // Kea subnet ID -> interface
	Warnings   []string
}

// Enabled reports whether any interface is served.
func (r *Result) Enabled() bool { return r != nil && len(r.Interfaces) > 0 }

// SubnetID is the Kea subnet ID for an interface: stable across commits,
// so a client keeps its lease when other servers change.
func SubnetID(iface string) int {
	return int(crc32.ChecksumIEEE([]byte(iface))%2147483646) + 1
}

type option struct {
	Name      string `json:"name,omitempty"`
	Code      int    `json:"code,omitempty"`
	CSVFormat *bool  `json:"csv-format,omitempty"`
	Data      string `json:"data"`
}

type reservation struct {
	HWAddress string `json:"hw-address"`
	IPAddress string `json:"ip-address"`
}

type pool struct {
	Pool string `json:"pool"`
}

type subnet struct {
	ID            int           `json:"id"`
	Subnet        string        `json:"subnet"`
	Interface     string        `json:"interface,omitempty"`
	Pools         []pool        `json:"pools"`
	ValidLifetime int           `json:"valid-lifetime"`
	OptionData    []option      `json:"option-data"`
	Reservations  []reservation `json:"reservations"`
}

type keaConf struct {
	Dhcp4 struct {
		InterfacesConfig struct {
			Interfaces     []string `json:"interfaces"`
			DHCPSocketType string   `json:"dhcp-socket-type"`
		} `json:"interfaces-config"`
		ControlSocket struct {
			SocketType string `json:"socket-type"`
			SocketName string `json:"socket-name"`
		} `json:"control-socket"`
		LeaseDatabase struct {
			Type        string `json:"type"`
			Persist     bool   `json:"persist"`
			Name        string `json:"name"`
			LFCInterval int    `json:"lfc-interval"`
		} `json:"lease-database"`
		HooksLibraries []struct {
			Library string `json:"library"`
		} `json:"hooks-libraries"`
		Authoritative     bool     `json:"authoritative"`
		CalculateTeeTimes bool     `json:"calculate-tee-times"`
		ValidLifetime     int      `json:"valid-lifetime"`
		Subnet4           []subnet `json:"subnet4"`
		Loggers           []struct {
			Name          string `json:"name"`
			OutputOptions []struct {
				Output string `json:"output"`
			} `json:"output-options"`
			Severity string `json:"severity"`
		} `json:"loggers"`
	} `json:"Dhcp4"`
}

// Compile builds the Kea config for c.
func Compile(c *config.Config, o Options) *Result {
	res := &Result{Subnets: map[int]string{}}
	var k keaConf
	d := &k.Dhcp4
	d.InterfacesConfig.Interfaces = []string{}
	// Raw sockets: Kea answers clients that have no address yet, on any
	// interface, in any VRF.
	d.InterfacesConfig.DHCPSocketType = "raw"
	d.ControlSocket.SocketType = "unix"
	d.ControlSocket.SocketName = SocketPath
	d.LeaseDatabase.Type = "memfile"
	d.LeaseDatabase.Persist = true
	d.LeaseDatabase.Name = LeaseFile
	d.LeaseDatabase.LFCInterval = 3600
	hooks := o.HooksDir
	if hooks == "" {
		hooks = DefaultHook
	}
	d.HooksLibraries = append(d.HooksLibraries, struct {
		Library string `json:"library"`
	}{hooks + "/" + LeaseHook})
	d.Authoritative = true
	d.CalculateTeeTimes = true
	d.ValidLifetime = config.DefaultLeaseTime
	d.Subnet4 = []subnet{}
	d.Loggers = append(d.Loggers, struct {
		Name          string `json:"name"`
		OutputOptions []struct {
			Output string `json:"output"`
		} `json:"output-options"`
		Severity string `json:"severity"`
	}{Name: "kea-dhcp4", OutputOptions: []struct {
		Output string `json:"output"`
	}{{"stdout"}}, Severity: "INFO"})

	servers := append([]config.DHCPServer(nil), c.DHCPServers...)
	sort.Slice(servers, func(i, j int) bool { return servers[i].Name < servers[j].Name })
	for _, s := range servers {
		addr, ok := c.InterfaceAddress(s.Name)
		if !ok {
			continue // validation refuses this
		}
		first, last, err := config.ParseDHCPRange(s.Range)
		if err != nil {
			continue
		}
		sn := subnet{
			ID: SubnetID(s.Name), Subnet: addr.Masked().String(), Interface: s.Name,
			Pools:         []pool{{first.String() + " - " + last.String()}},
			ValidLifetime: s.LeaseTime, OptionData: []option{}, Reservations: []reservation{},
		}
		if sn.ValidLifetime == 0 {
			sn.ValidLifetime = config.DefaultLeaseTime
		}
		gw := s.Gateway
		if gw == "" {
			gw = addr.Addr().String()
		}
		sn.OptionData = append(sn.OptionData, option{Name: "routers", Data: gw})
		dns := s.DNS
		if len(dns) == 0 {
			dns = ipv4Only(o.DNS)
		}
		if len(dns) > 0 {
			sn.OptionData = append(sn.OptionData, option{Name: "domain-name-servers", Data: strings.Join(dns, ", ")})
		} else {
			res.Warnings = append(res.Warnings, "dhcp server "+s.Name+": no DNS servers to hand out (the firewall has none either); set dns")
		}
		if s.Domain != "" {
			sn.OptionData = append(sn.OptionData, option{Name: "domain-name", Data: s.Domain})
		}
		if len(s.NTP) > 0 {
			sn.OptionData = append(sn.OptionData, option{Name: "ntp-servers", Data: strings.Join(s.NTP, ", ")})
		}
		for _, raw := range s.Options {
			opt, err := config.ParseDHCPOption(raw)
			if err != nil {
				continue
			}
			ko := option{Code: opt.Code, Data: opt.Data}
			if opt.Hex {
				f := false
				ko.CSVFormat = &f
			}
			sn.OptionData = append(sn.OptionData, ko)
		}
		for _, r := range c.DHCPReservations {
			if r.Interface == s.Name {
				sn.Reservations = append(sn.Reservations, reservation{HWAddress: strings.ToLower(r.MAC), IPAddress: r.Address})
			}
		}
		d.Subnet4 = append(d.Subnet4, sn)
		d.InterfacesConfig.Interfaces = append(d.InterfacesConfig.Interfaces, s.Name)
		res.Interfaces = append(res.Interfaces, s.Name)
		res.Subnets[sn.ID] = s.Name
	}
	const head = "// Written by ngfwd from the SJB-OS config (dhcp_servers). Do not edit:\n// commits replace it.\n"
	b, _ := json.MarshalIndent(k, "", "  ")
	res.Conf = head + string(b) + "\n"
	d.InterfacesConfig.Interfaces = []string{}
	subs := make([]subnet, len(d.Subnet4))
	for i, sn := range d.Subnet4 {
		sn.Interface = ""
		subs[i] = sn
	}
	d.Subnet4 = subs
	b, _ = json.MarshalIndent(k, "", "  ")
	res.CheckConf = head + string(b) + "\n"
	return res
}

func ipv4Only(in []string) []string {
	var out []string
	for _, s := range in {
		if a, err := netip.ParseAddr(s); err == nil && a.Is4() && !a.IsLoopback() {
			out = append(out, a.String())
		}
	}
	return out
}
