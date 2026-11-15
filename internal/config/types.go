// Package config defines the firewall configuration schema, loads it from
// YAML, and validates it. The policy compiler consumes a validated Config.
package config

// Any is the reserved name meaning "match everything" in rule fields.
const Any = "any"

// Config is one complete firewall configuration (candidate or running).
type Config struct {
	System        System         `yaml:"system" json:"system"`
	Zones         []Zone         `yaml:"zones" json:"zones"`
	Interfaces    []Interface    `yaml:"interfaces" json:"interfaces"`
	Addresses     []Address      `yaml:"addresses" json:"addresses"`
	AddressGroups []AddressGroup `yaml:"address_groups" json:"address_groups"`
	Services      []Service      `yaml:"services" json:"services"`
	Rules         []Rule         `yaml:"rules" json:"rules"`
	// ApplicationGroups name sets of applications and categories for rules.
	ApplicationGroups []ApplicationGroup `yaml:"application_groups,omitempty" json:"application_groups"`
	NAT               []NATRule          `yaml:"nat" json:"nat"`
	Routes            []Route            `yaml:"routes,omitempty" json:"routes"`
	VRFs              []VRF              `yaml:"vrfs,omitempty" json:"vrfs"`

	// Dynamic routing (FRR).
	Routing        []Routing       `yaml:"routing,omitempty" json:"routing"`
	BGPNeighbors   []BGPNeighbor   `yaml:"bgp_neighbors,omitempty" json:"bgp_neighbors"`
	OSPFInterfaces []OSPFInterface `yaml:"ospf_interfaces,omitempty" json:"ospf_interfaces"`
	PrefixLists    []PrefixList    `yaml:"prefix_lists,omitempty" json:"prefix_lists"`

	// DHCP server (Kea).
	DHCPServers      []DHCPServer      `yaml:"dhcp_servers,omitempty" json:"dhcp_servers"`
	DHCPReservations []DHCPReservation `yaml:"dhcp_reservations,omitempty" json:"dhcp_reservations"`

	// IPS (Suricata).
	IPSProfiles []IPSProfile `yaml:"ips_profiles,omitempty" json:"ips_profiles"`
}

// Routing turns on BGP and/or OSPF in one VRF. Name is the VRF.
type Routing struct {
	Name             string   `yaml:"name" json:"name"`
	RouterID         string   `yaml:"router_id" json:"router_id"`
	BGPASN           uint32   `yaml:"bgp_asn,omitempty" json:"bgp_asn"`                     // 0 = no BGP
	BGPNetworks      []string `yaml:"bgp_networks,omitempty" json:"bgp_networks"`           // prefixes to announce
	BGPRedistribute  []string `yaml:"bgp_redistribute,omitempty" json:"bgp_redistribute"`   // connected, static, ospf
	OSPF             bool     `yaml:"ospf,omitempty" json:"ospf"`                           // run OSPF in this VRF
	OSPFRedistribute []string `yaml:"ospf_redistribute,omitempty" json:"ospf_redistribute"` // connected, static, bgp
}

// BGPNeighbor is a BGP peer.
type BGPNeighbor struct {
	Name        string `yaml:"name" json:"name"`
	VRF         string `yaml:"vrf,omitempty" json:"vrf"` // default: default
	Address     string `yaml:"address" json:"address"`
	RemoteAS    uint32 `yaml:"remote_as" json:"remote_as"`
	Description string `yaml:"description,omitempty" json:"description"`
	Import      string `yaml:"import,omitempty" json:"import"` // prefix list for routes received
	Export      string `yaml:"export,omitempty" json:"export"` // prefix list for routes sent
	NextHopSelf bool   `yaml:"next_hop_self,omitempty" json:"next_hop_self"`
}

// OSPFInterface runs OSPF on an interface. Name is the interface.
type OSPFInterface struct {
	Name    string `yaml:"name" json:"name"`
	Area    string `yaml:"area" json:"area"`                 // 0.0.0.0 or 0
	Cost    int    `yaml:"cost,omitempty" json:"cost"`       // 0 = automatic
	Passive bool   `yaml:"passive,omitempty" json:"passive"` // announce the subnet, form no adjacencies
}

// PrefixList filters routes: entries like "permit 10.0.0.0/8 le 24", "deny any",
// checked in order; anything unmatched is denied.
type PrefixList struct {
	Name    string   `yaml:"name" json:"name"`
	Entries []string `yaml:"entries" json:"entries"`
}

// Redistribution sources.
const (
	RedistConnected = "connected"
	RedistStatic    = "static"
	RedistBGP       = "bgp"
	RedistOSPF      = "ospf"
)

// VRF is a separate routing table (Linux VRF device vrf-<name>). Interfaces
// join it with their vrf field; routes name it with theirs.
type VRF struct {
	Name  string `yaml:"name" json:"name"`
	Table int    `yaml:"table,omitempty" json:"table"` // 1001-65535; auto when 0
}

// Built-in VRFs: default is the main routing table, mgmt the management VRF.
const (
	VRFDefault = "default"
	VRFMgmt    = "mgmt"
	// MgmtTable is the management VRF's routing table (set up at first boot).
	MgmtTable = 100
	// FirstVRFTable is where automatic VRF table numbers start.
	FirstVRFTable = 1001
)

// Route is a static IPv4 route, installed by ngfwd at commit.
type Route struct {
	Name        string `yaml:"name" json:"name"`
	Destination string `yaml:"destination" json:"destination"` // prefix, e.g. 10.20.0.0/16
	Gateway     string `yaml:"gateway" json:"gateway"`         // next hop, e.g. 10.10.1.254
	Interface   string `yaml:"interface,omitempty" json:"interface"`
	// Table is "main" (forwarded traffic, the default) or "mgmt" (the
	// management VRF, for the firewall's own management traffic). Older
	// spelling of VRF; use one or the other.
	Table string `yaml:"table,omitempty" json:"table"`
	// VRF is the routing table the route goes into (default: default).
	VRF string `yaml:"vrf,omitempty" json:"vrf"`
	// NextVRF leaks the destination into another VRF's table: traffic to it
	// is routed on in that VRF. The gateway is then optional.
	NextVRF string `yaml:"next_vrf,omitempty" json:"next_vrf"`
}

// Route tables.
const (
	TableMain = "main"
	TableMgmt = "mgmt"
)

// NATRule is a source NAT rule. Only masquerade (rewrite the source to the
// egress interface's address) is supported.
type NATRule struct {
	Name   string   `yaml:"name" json:"name"`
	From   []string `yaml:"from" json:"from"`               // ingress zones
	To     []string `yaml:"to" json:"to"`                   // egress zones
	Source []string `yaml:"source,omitempty" json:"source"` // address or group names; empty = any
	Type   string   `yaml:"type" json:"type"`               // masquerade
}

// System holds device-wide settings.
type System struct {
	Hostname string `yaml:"hostname" json:"hostname"`
	// MgmtInterface is never assigned a zone and never filtered by policy.
	MgmtInterface string `yaml:"mgmt_interface" json:"mgmt_interface"`
	// AppID turns App Identification classification on or off: "on" (also when unset)
	// or "off". Step 1 is visibility only: apps show in logs, not policy.
	AppID string `yaml:"app_id,omitempty" json:"app_id"`
	// IPS turns IPS inspection on or off: "on" (also when unset) or "off".
	// Inspection runs for allow rules that name an IPS profile.
	IPS string `yaml:"ips,omitempty" json:"ips"`
	// IPSDisabledSignatures are signature IDs left out of the IPS rules
	// (false positives).
	IPSDisabledSignatures []string `yaml:"ips_disabled_signatures,omitempty" json:"ips_disabled_signatures"`
}

// AppIDOn reports whether App Identification classifies traffic.
func (s System) AppIDOn() bool { return s.AppID != "off" }

// Zone is a named security zone that interfaces belong to.
type Zone struct {
	Name string `yaml:"name" json:"name"`
}

// Interface binds a physical or virtual interface to a zone. A name like
// inside.20 is VLAN 20 on inside: ngfwd creates it, puts it in its VRF and
// gives it its address. An address on inside or outside takes over from the
// deployment settings (see internal/nicaddr); mgmt's is informational.
type Interface struct {
	Name    string `yaml:"name" json:"name"`
	Zone    string `yaml:"zone" json:"zone"`
	Address string `yaml:"address,omitempty" json:"address"` // CIDR, e.g. 10.10.1.1/24; applied (except on the mgmt interface)
	VRF     string `yaml:"vrf,omitempty" json:"vrf"`         // default: default
}

// Address is a named host or prefix.
type Address struct {
	Name string `yaml:"name" json:"name"`
	CIDR string `yaml:"cidr" json:"cidr"` // a prefix (10.0.0.0/8) or a single host (10.0.0.1)
}

// ApplicationGroup names a set of applications for rules: application
// names, "unknown", and categories ("category:video"); no nested groups.
type ApplicationGroup struct {
	Name    string   `yaml:"name" json:"name"`
	Members []string `yaml:"members" json:"members"`
}

// AddressGroup is either static (a list of address names) or dynamic (every
// IP currently registered with Tag through the tag API). Exactly one of
// Static or Tag is set.
type AddressGroup struct {
	Name   string   `yaml:"name" json:"name"`
	Static []string `yaml:"static,omitempty" json:"static"`
	Tag    string   `yaml:"tag,omitempty" json:"tag"`
}

// Service is a protocol and port set.
type Service struct {
	Name     string `yaml:"name" json:"name"`
	Protocol string `yaml:"protocol" json:"protocol"`     // tcp, udp or icmp
	Ports    string `yaml:"ports,omitempty" json:"ports"` // e.g. "80,443,8000-8080"; empty for icmp
}

// Rule is one security policy rule. An empty list in a match field means any.
type Rule struct {
	Name        string   `yaml:"name" json:"name"`
	From        []string `yaml:"from,omitempty" json:"from"`               // source zones
	To          []string `yaml:"to,omitempty" json:"to"`                   // destination zones
	Source      []string `yaml:"source,omitempty" json:"source"`           // address or group names
	Destination []string `yaml:"destination,omitempty" json:"destination"` // address or group names
	Application []string `yaml:"application,omitempty" json:"application"` // App Identification names (catalog arrives in phase 2)
	Service     []string `yaml:"service,omitempty" json:"service"`         // service names
	Action      string   `yaml:"action" json:"action"`                     // allow, deny or reset
	Log         bool     `yaml:"log,omitempty" json:"log"`
	// IPSProfile inspects the rule's traffic with the IPS (allow rules).
	IPSProfile string `yaml:"ips_profile,omitempty" json:"ips_profile"`
}
