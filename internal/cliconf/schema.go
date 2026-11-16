// Package cliconf is the SJB-OS CLI's configuration mode:
// set/delete/move/rename commands over a working copy of the config, and
// the completion data the line editor offers on Tab and "?".
package cliconf

import "github.com/stevejboyle/hobby-ngfw/internal/appid"

// Kind of attribute value.
type valueKind int

const (
	vStr  valueKind = iota // one string, replaced by set
	vEnum                  // one of a fixed set
	vRef                   // one name of another object
	vList                  // members; set adds, delete removes
	vBool                  // yes or no
	vInt                   // a number
)

// Attr is one settable field of an object.
type Attr struct {
	Name  string // CLI name, e.g. "mgmt-interface"
	Field string // JSON field in config.Config
	Kind  valueKind
	Enum  []string // vEnum values
	Fixed []string // built-in names a vRef also accepts (e.g. the default vrf)
	Refs  []string // JSON keys of the objects a vRef/vList names (completion, rename)
	Any   bool     // list accepts "any"
	Help  string
	Hint  string // shown by "?" when no fixed values exist, e.g. "<cidr>"
}

// Kind is an object type: zone, rule, route...
type Kind struct {
	Name      string // CLI name, e.g. "address-group"
	Key       string // JSON key in config.Config, e.g. "address_groups"
	Singleton bool   // system: no name
	Ordered   bool   // rules and NAT: order matters, move works
	Attrs     []Attr
	Help      string
	// NameRefs suggests names for new objects from other lists (an OSPF
	// interface is named after an interface); NameFixed adds built-ins.
	NameRefs  []string
	NameFixed []string
}

func (k *Kind) attr(name string) *Attr {
	for i := range k.Attrs {
		if k.Attrs[i].Name == name {
			return &k.Attrs[i]
		}
	}
	return nil
}

var (
	zones    = []string{"zones"}
	ifaces   = []string{"interfaces"}
	addrs    = []string{"addresses"}
	addrGrps = []string{"addresses", "address_groups"}
	services = []string{"services"}
	vrfKeys  = []string{"vrfs"}
	plists   = []string{"prefix_lists"}
	appGrps  = []string{"application_groups"}

	ipsProfiles = []string{"ips_profiles"}
	ipsActions  = []string{"block", "alert", "ignore"}

	decryptProfiles = []string{"decryption_profiles"}
)

// appValues are what an application list may name besides groups: every
// application, "unknown", and every category reference.
func appValues() []string {
	out := appid.Names()
	for _, c := range appid.Categories() {
		out = append(out, c.Ref)
	}
	return out
}

// Kinds is the config schema as the CLI sees it.
var Kinds = []*Kind{
	{Name: "system", Key: "system", Singleton: true, Help: "hostname and management interface", Attrs: []Attr{
		{Name: "hostname", Field: "hostname", Kind: vStr, Hint: "<name>", Help: "the firewall's host name"},
		{Name: "mgmt-interface", Field: "mgmt_interface", Kind: vRef, Refs: ifaces, Help: "never filtered by policy"},
		{Name: "app-identification", Field: "app_id", Kind: vEnum, Enum: []string{"on", "off"}, Help: "App Identification: name the application in each connection (on unless set off)"},
		{Name: "ips", Field: "ips", Kind: vEnum, Enum: []string{"on", "off"}, Help: "IPS: inspect traffic of rules with an ips-profile (on unless set off)"},
		{Name: "ips-disabled-signatures", Field: "ips_disabled_signatures", Kind: vList, Hint: "<sid>", Help: "signature IDs to leave out of the IPS (false positives; the threat log shows SIDs)"},
		{Name: "decryption", Field: "decryption", Kind: vEnum, Enum: []string{"on", "off"}, Help: "TLS decryption for connections a decryption-rule decrypts (on unless set off)"},
		{Name: "decryption-builtin-exclusions", Field: "decryption_builtin_exclusions", Kind: vEnum, Enum: []string{"on", "off"}, Help: "never decrypt SJB-OS's built-in list of banking, payment, health and government sites (on unless set off)"},
	}},
	{Name: "decryption-rule", Key: "decryption_rules", Ordered: true, Help: "which TLS connections to decrypt, first match wins (unmatched: not decrypted)", Attrs: []Attr{
		{Name: "from", Field: "from", Kind: vList, Refs: zones, Any: true, Help: "source zones"},
		{Name: "to", Field: "to", Kind: vList, Refs: zones, Any: true, Help: "destination zones"},
		{Name: "source", Field: "source", Kind: vList, Refs: addrGrps, Any: true, Help: "source addresses and groups"},
		{Name: "destination", Field: "destination", Kind: vList, Refs: addrGrps, Any: true, Help: "destination addresses and groups"},
		{Name: "service", Field: "service", Kind: vList, Refs: services, Any: true, Help: "TCP services (any: port 443)"},
		{Name: "action", Field: "action", Kind: vEnum, Enum: []string{"decrypt", "no-decrypt"}, Help: "decrypt, or no-decrypt to exempt the traffic from rules below"},
		{Name: "profile", Field: "profile", Kind: vRef, Refs: decryptProfiles, Fixed: []string{"default"}, Help: "what to do with traffic that can't be decrypted as usual (default is built in)"},
	}},
	{Name: "decryption-profile", Key: "decryption_profiles", Help: "decryption profiles: bad certificates, undecryptable and pinned traffic, QUIC (built-in: default)", NameFixed: []string{"default"}, Attrs: []Attr{
		{Name: "bad-certificate", Field: "bad_certificate", Kind: vEnum, Enum: []string{"warn", "block"}, Help: "the server's certificate fails the checks: warn (the browser shows its warning; default) or block"},
		{Name: "unsupported", Field: "unsupported", Kind: vEnum, Enum: []string{"pass", "block"}, Help: "old TLS, client certificates, not TLS: pass through undecrypted (default) or block"},
		{Name: "pinned", Field: "pinned", Kind: vEnum, Enum: []string{"exclude", "block"}, Help: "the client rejects the firewall's certificate: exclude the server from then on (default) or block"},
		{Name: "allow-quic", Field: "allow_quic", Kind: vBool, Help: "let QUIC (UDP 443, can't be decrypted) through (yes or no; default no, so browsers use TLS)"},
	}},
	{Name: "decryption-exclusion", Key: "decryption_exclusions", Help: "server names never decrypted, on top of the built-in list", Attrs: []Attr{
		{Name: "domain", Field: "domains", Kind: vList, Hint: "<name>", Help: "bank.example, or *.bank.example for everything under it"},
	}},
	{Name: "ips-profile", Key: "ips_profiles", Help: "IPS profiles: block, alert or ignore per signature severity (built-in: default)", NameFixed: []string{"default"}, Attrs: []Attr{
		{Name: "critical", Field: "critical", Kind: vEnum, Enum: ipsActions, Help: "critical signatures (default: block)"},
		{Name: "major", Field: "major", Kind: vEnum, Enum: ipsActions, Help: "major signatures (default: block)"},
		{Name: "minor", Field: "minor", Kind: vEnum, Enum: ipsActions, Help: "minor signatures (default: alert)"},
		{Name: "informational", Field: "informational", Kind: vEnum, Enum: ipsActions, Help: "informational signatures (default: ignore)"},
	}},
	{Name: "zone", Key: "zones", Help: "security zones"},
	{Name: "vrf", Key: "vrfs", Help: "VRFs: separate routing tables", Attrs: []Attr{
		{Name: "table", Field: "table", Kind: vInt, Hint: "<1001-65535>", Help: "routing table number (leave unset to pick one)"},
	}},
	{Name: "interface", Key: "interfaces", Help: "interfaces, zones and VLAN subinterfaces (inside.20 = VLAN 20 on inside)", Attrs: []Attr{
		{Name: "zone", Field: "zone", Kind: vRef, Refs: zones, Help: "zone the interface belongs to"},
		{Name: "address", Field: "address", Kind: vStr, Hint: "<cidr>", Help: "e.g. 192.168.1.20/24; applied at commit, replacing the deployment's on inside/outside (informational on mgmt)"},
		{Name: "vrf", Field: "vrf", Kind: vRef, Refs: vrfKeys, Fixed: []string{"default"}, Help: "VRF (VLAN subinterfaces only)"},
	}},
	{Name: "address", Key: "addresses", Help: "address objects", Attrs: []Attr{
		{Name: "cidr", Field: "cidr", Kind: vStr, Hint: "<ip or prefix>", Help: "e.g. 10.0.0.0/8 or 10.0.0.5"},
	}},
	{Name: "application-group", Key: "application_groups", Help: "named sets of applications and categories for rules", Attrs: []Attr{
		{Name: "member", Field: "members", Kind: vList, Enum: appValues(), Hint: "<app>", Help: "applications or categories (category:video); Tab or ? lists them"},
	}},
	{Name: "address-group", Key: "address_groups", Help: "static or tag-based address groups", Attrs: []Attr{
		{Name: "static", Field: "static", Kind: vList, Refs: addrs, Help: "member addresses"},
		{Name: "tag", Field: "tag", Kind: vStr, Hint: "<tag>", Help: "members are IPs registered with this tag"},
	}},
	{Name: "service", Key: "services", Help: "protocol and port objects", Attrs: []Attr{
		{Name: "protocol", Field: "protocol", Kind: vEnum, Enum: []string{"tcp", "udp", "icmp"}, Help: "tcp, udp or icmp"},
		{Name: "ports", Field: "ports", Kind: vStr, Hint: "<ports>", Help: "e.g. 80,443,8000-8080 (none for icmp)"},
	}},
	{Name: "rule", Key: "rules", Ordered: true, Help: "security rules, first match wins", Attrs: []Attr{
		{Name: "from", Field: "from", Kind: vList, Refs: zones, Any: true, Help: "source zones"},
		{Name: "to", Field: "to", Kind: vList, Refs: zones, Any: true, Help: "destination zones"},
		{Name: "source", Field: "source", Kind: vList, Refs: addrGrps, Any: true, Help: "source addresses and groups"},
		{Name: "destination", Field: "destination", Kind: vList, Refs: addrGrps, Any: true, Help: "destination addresses and groups"},
		{Name: "service", Field: "service", Kind: vList, Refs: services, Any: true, Help: "services"},
		{Name: "application", Field: "application", Kind: vList, Any: true, Enum: appValues(), Refs: appGrps, Hint: "<app>", Help: "applications (App Identification), categories (category:video) or application groups; Tab or ? lists them"},
		{Name: "action", Field: "action", Kind: vEnum, Enum: []string{"allow", "deny", "reset"}, Help: "allow, deny or reset"},
		{Name: "log", Field: "log", Kind: vBool, Help: "log matches (yes or no)"},
		{Name: "ips-profile", Field: "ips_profile", Kind: vRef, Refs: ipsProfiles, Fixed: []string{"default"}, Help: "inspect the rule's traffic with the IPS (allow rules); default is built in"},
	}},
	{Name: "nat", Key: "nat", Ordered: true, Help: "source NAT rules", Attrs: []Attr{
		{Name: "from", Field: "from", Kind: vList, Refs: zones, Any: true, Help: "ingress zones"},
		{Name: "to", Field: "to", Kind: vList, Refs: zones, Any: true, Help: "egress zones"},
		{Name: "source", Field: "source", Kind: vList, Refs: addrGrps, Any: true, Help: "source addresses and groups"},
		{Name: "type", Field: "type", Kind: vEnum, Enum: []string{"masquerade"}, Help: "masquerade (only type so far)"},
	}},
	{Name: "routing", Key: "routing", Help: "BGP/OSPF in a VRF (name it after the VRF, e.g. default)", NameRefs: vrfKeys, NameFixed: []string{"default"}, Attrs: []Attr{
		{Name: "router-id", Field: "router_id", Kind: vStr, Hint: "<ip>", Help: "router ID, usually one of the firewall's addresses"},
		{Name: "bgp-asn", Field: "bgp_asn", Kind: vInt, Hint: "<asn>", Help: "turn on BGP with this AS number"},
		{Name: "bgp-network", Field: "bgp_networks", Kind: vList, Hint: "<prefix>", Help: "a prefix to announce over BGP"},
		{Name: "bgp-redistribute", Field: "bgp_redistribute", Kind: vList, Enum: []string{"connected", "static", "ospf"}, Help: "routes to announce over BGP"},
		{Name: "ospf", Field: "ospf", Kind: vBool, Help: "run OSPF in this VRF (yes or no)"},
		{Name: "ospf-redistribute", Field: "ospf_redistribute", Kind: vList, Enum: []string{"connected", "static", "bgp"}, Help: "routes to announce into OSPF"},
	}},
	{Name: "bgp-neighbor", Key: "bgp_neighbors", Help: "BGP peers", Attrs: []Attr{
		{Name: "address", Field: "address", Kind: vStr, Hint: "<ip>", Help: "the peer's address"},
		{Name: "remote-as", Field: "remote_as", Kind: vInt, Hint: "<asn>", Help: "the peer's AS (same as ours for iBGP)"},
		{Name: "vrf", Field: "vrf", Kind: vRef, Refs: vrfKeys, Fixed: []string{"default"}, Help: "VRF the session runs in"},
		{Name: "description", Field: "description", Kind: vStr, Hint: "<text>", Help: "free text (quote it)"},
		{Name: "import", Field: "import", Kind: vRef, Refs: plists, Help: "prefix list for routes received"},
		{Name: "export", Field: "export", Kind: vRef, Refs: plists, Help: "prefix list for routes sent"},
		{Name: "next-hop-self", Field: "next_hop_self", Kind: vBool, Help: "set ourselves as next hop (iBGP)"},
	}},
	{Name: "ospf-interface", Key: "ospf_interfaces", Help: "OSPF on an interface (name it after the interface)", NameRefs: ifaces, Attrs: []Attr{
		{Name: "area", Field: "area", Kind: vStr, Hint: "<area>", Help: "e.g. 0 or 0.0.0.0"},
		{Name: "cost", Field: "cost", Kind: vInt, Hint: "<1-65535>", Help: "link cost (unset: automatic)"},
		{Name: "passive", Field: "passive", Kind: vBool, Help: "announce the subnet but form no adjacencies"},
	}},
	{Name: "dhcp-server", Key: "dhcp_servers", Help: "DHCP server on an interface (name it after the interface)", NameRefs: ifaces, Attrs: []Attr{
		{Name: "range", Field: "range", Kind: vStr, Hint: "<first-last>", Help: "addresses to hand out, e.g. 192.168.150.100-192.168.150.199"},
		{Name: "gateway", Field: "gateway", Kind: vStr, Hint: "<ip>", Help: "router for clients (unset: the interface's address)"},
		{Name: "dns", Field: "dns", Kind: vList, Hint: "<ip>", Help: "DNS servers for clients (unset: the firewall's own)"},
		{Name: "domain", Field: "domain", Kind: vStr, Hint: "<domain>", Help: "domain name for clients"},
		{Name: "ntp", Field: "ntp", Kind: vList, Hint: "<ip>", Help: "NTP servers for clients"},
		{Name: "lease-time", Field: "lease_time", Kind: vInt, Hint: "<seconds>", Help: "lease length (unset: a day)"},
		{Name: "option", Field: "options", Kind: vList, Hint: `"66=tftp.lab"`, Help: "another option as CODE=VALUE, quoted; 0x... for raw hex"},
	}},
	{Name: "dhcp-reservation", Key: "dhcp_reservations", Help: "a fixed DHCP address for a MAC address", Attrs: []Attr{
		{Name: "interface", Field: "interface", Kind: vRef, Refs: ifaces, Help: "interface whose DHCP server hands it out"},
		{Name: "mac", Field: "mac", Kind: vStr, Hint: "<aa:bb:cc:dd:ee:ff>", Help: "the client's MAC address"},
		{Name: "address", Field: "address", Kind: vStr, Hint: "<ip>", Help: "the address it always gets"},
	}},
	{Name: "prefix-list", Key: "prefix_lists", Help: "route filters for BGP import/export", Attrs: []Attr{
		{Name: "entry", Field: "entries", Kind: vList, Hint: `"permit 10.0.0.0/8 le 24"`, Help: "permit|deny PREFIX|any [ge N] [le N], quoted; checked in order"},
	}},
	{Name: "route", Key: "routes", Help: "static routes", Attrs: []Attr{
		{Name: "destination", Field: "destination", Kind: vStr, Hint: "<prefix>", Help: "e.g. 10.20.0.0/16"},
		{Name: "gateway", Field: "gateway", Kind: vStr, Hint: "<ip>", Help: "next hop on a connected network"},
		{Name: "interface", Field: "interface", Kind: vRef, Refs: ifaces, Help: "pin to an interface (usually leave unset)"},
		{Name: "vrf", Field: "vrf", Kind: vRef, Refs: vrfKeys, Fixed: []string{"default", "mgmt"}, Help: "routing table the route goes in (default: default)"},
		{Name: "next-vrf", Field: "next_vrf", Kind: vRef, Refs: vrfKeys, Help: "leak: route the destination on in this VRF (no gateway needed)"},
		{Name: "table", Field: "table", Kind: vEnum, Enum: []string{"main", "mgmt"}, Help: "older spelling of vrf default/mgmt"},
	}},
}

// KindByName finds a kind.
func KindByName(n string) *Kind {
	for _, k := range Kinds {
		if k.Name == n {
			return k
		}
	}
	return nil
}
