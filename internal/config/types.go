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
	// IPSExceptions stop one signature from blocking (or being logged)
	// for some rules or addresses, rather than everywhere.
	IPSExceptions []IPSException `yaml:"ips_exceptions,omitempty" json:"ips_exceptions"`

	// TLS decryption (tlsd).
	DecryptionRules      []DecryptionRule      `yaml:"decryption_rules,omitempty" json:"decryption_rules"`
	DecryptionProfiles   []DecryptionProfile   `yaml:"decryption_profiles,omitempty" json:"decryption_profiles"`
	DecryptionExclusions []DecryptionExclusion `yaml:"decryption_exclusions,omitempty" json:"decryption_exclusions"`

	// LogServers are syslog servers (a SIEM) the logs are forwarded to.
	LogServers []LogServer `yaml:"log_servers,omitempty" json:"log_servers"`

	// SNMP agent (read-only) and where it sends traps.
	SNMP              SNMP               `yaml:"snmp,omitempty" json:"snmp"`
	SNMPTrapReceivers []SNMPTrapReceiver `yaml:"snmp_trap_receivers,omitempty" json:"snmp_trap_receivers"`
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

// NATRule is one NAT entry. Type masquerade is source NAT (rewrite the
// source to the egress interface's address) and uses From, To and Source.
// Types port-forward and static publish an inside server (destination NAT)
// and use Interface, PublicAddress, Server and, for port-forward, Protocol,
// PublicPort and ServerPort; static may also be bidirectional.
type NATRule struct {
	Name   string   `yaml:"name" json:"name"`
	From   []string `yaml:"from,omitempty" json:"from"`     // ingress zones (masquerade)
	To     []string `yaml:"to,omitempty" json:"to"`         // egress zones (masquerade)
	Source []string `yaml:"source,omitempty" json:"source"` // address or group names; empty = any (masquerade)
	Type   string   `yaml:"type" json:"type"`               // masquerade, port-forward or static

	// Interface is where published traffic arrives (port-forward, static).
	Interface string `yaml:"interface,omitempty" json:"interface"`
	// PublicAddress names a host address object: the address the outside
	// uses. Empty (port-forward only) means the interface's own address.
	PublicAddress string `yaml:"public_address,omitempty" json:"public_address"`
	Protocol      string `yaml:"protocol,omitempty" json:"protocol"`       // tcp or udp (port-forward)
	PublicPort    string `yaml:"public_port,omitempty" json:"public_port"` // "443" or "8000-8010" (port-forward)
	// Server names a host address object: the inside server.
	Server string `yaml:"server,omitempty" json:"server"`
	// ServerPort is the server's port (port-forward); empty = the public
	// port. A range can only map to the same range.
	ServerPort string `yaml:"server_port,omitempty" json:"server_port"`
	// Bidirectional (static): "on" (also when unset) sends the server's own
	// outbound traffic from its public address; "off" leaves it to the
	// source NAT rules.
	Bidirectional string `yaml:"bidirectional,omitempty" json:"bidirectional"`
	// Hairpin (port-forward, static): "on" (also when unset) lets clients
	// on SJB-OS's other zoned interfaces in the same VRF reach the server
	// by its public address too; "off" publishes it on Interface only.
	Hairpin string `yaml:"hairpin,omitempty" json:"hairpin"`
}

// NAT types.
const (
	NATMasquerade  = "masquerade"
	NATPortForward = "port-forward"
	NATStatic      = "static"
)

// Published reports whether the entry publishes a server (destination NAT).
func (n NATRule) Published() bool { return n.Type == NATPortForward || n.Type == NATStatic }

// BidirectionalOn reports whether a static entry also translates the
// server's outbound traffic.
func (n NATRule) BidirectionalOn() bool { return n.Type == NATStatic && n.Bidirectional != "off" }

// HairpinOn reports whether a published entry is also reachable by its
// public address from SJB-OS's other interfaces (on unless set off).
func (n NATRule) HairpinOn() bool { return n.Published() && n.Hairpin != "off" }

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
	// GeoIPAutoUpdate turns the daily check for a newer country database
	// on (also when unset) or off.
	GeoIPAutoUpdate string `yaml:"geoip_auto_update,omitempty" json:"geoip_auto_update"`
	// UpdateCheck turns the daily check of the update server for a newer
	// SJB-OS release on (also when unset) or off. A newer release is
	// downloaded and verified, never installed without an admin.
	UpdateCheck string `yaml:"update_check,omitempty" json:"update_check"`
	// UpdateServer is the update server's https URL; unset means
	// DefaultUpdateServer.
	UpdateServer string `yaml:"update_server,omitempty" json:"update_server"`
	// IPSDisabledSignatures are signature IDs left out of the IPS rules
	// (false positives).
	IPSDisabledSignatures []string `yaml:"ips_disabled_signatures,omitempty" json:"ips_disabled_signatures"`
	// Decryption turns TLS decryption on (also when unset), off, or to
	// "observe": log what the decryption rules would decrypt and pass
	// everything through. It runs for connections a decryption rule decrypts.
	Decryption string `yaml:"decryption,omitempty" json:"decryption"`
	// DecryptionBuiltinExclusions: "off" stops using SJB-OS's built-in list
	// of server names never decrypted (banking, payment, health, government).
	DecryptionBuiltinExclusions string `yaml:"decryption_builtin_exclusions,omitempty" json:"decryption_builtin_exclusions"`
}

// AppIDOn reports whether App Identification classifies traffic.
func (s System) AppIDOn() bool { return s.AppID != "off" }

// Zone is a named security zone that interfaces belong to.
type Zone struct {
	Name string `yaml:"name" json:"name"`
}

// Interface binds a physical or virtual interface to a zone. An interface
// with no zone (other than the management interface) is a trunk: it only
// carries VLAN subinterfaces, takes no address, and drops untagged traffic.
// A name like
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
	// SourceNegate and DestinationNegate match everything except the listed
	// addresses (countries, groups and tag groups included).
	SourceNegate      bool     `yaml:"source_negate,omitempty" json:"source_negate"`
	DestinationNegate bool     `yaml:"destination_negate,omitempty" json:"destination_negate"`
	Application       []string `yaml:"application,omitempty" json:"application"` // App Identification names (catalog arrives in phase 2)
	Service           []string `yaml:"service,omitempty" json:"service"`         // service names
	Action            string   `yaml:"action" json:"action"`                     // allow, deny or reset
	Log               bool     `yaml:"log,omitempty" json:"log"`
	// IPSProfile inspects the rule's traffic with the IPS (allow rules).
	IPSProfile string `yaml:"ips_profile,omitempty" json:"ips_profile"`
}

// GeoIPAutoUpdateOn reports whether the appliance checks daily for a newer
// country database.
func (s System) GeoIPAutoUpdateOn() bool { return s.GeoIPAutoUpdate != "off" }

// DefaultUpdateServer is where appliances look for new releases unless
// system update_server says otherwise.
const DefaultUpdateServer = "https://updates.os.sjbconsulting.ai"

// UpdateCheckOn reports whether the appliance checks daily for a newer
// release.
func (s System) UpdateCheckOn() bool { return s.UpdateCheck != "off" }

// UpdateServerURL is the update server in use.
func (s System) UpdateServerURL() string {
	if s.UpdateServer == "" {
		return DefaultUpdateServer
	}
	return s.UpdateServer
}
