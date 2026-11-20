package config

import (
	"errors"

	"fmt"
	"github.com/stevejboyle/hobby-ngfw/internal/appid"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

var (
	nameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$`)
)

// validator collects every error instead of stopping at the first.
type validator struct{ errs []error }

func (v *validator) add(path, format string, args ...any) {
	v.errs = append(v.errs, fmt.Errorf("%s: %s", path, fmt.Sprintf(format, args...)))
}

// Validate checks the config for structural and semantic errors and returns
// all of them joined, or nil.
func (c *Config) Validate() error {
	v := &validator{}

	if strings.TrimSpace(c.System.Hostname) == "" {
		v.add("system.hostname", "required")
	}
	switch c.System.AppID {
	case "", "on", "off":
	default:
		v.add("system.app_id", "must be on or off, got %q", c.System.AppID)
	}

	zones := v.names("zones", len(c.Zones), func(i int) string { return c.Zones[i].Name })

	// Addresses and groups share one namespace: both appear in source/destination.
	addrs := map[string]bool{}
	for i, a := range c.Addresses {
		p := fmt.Sprintf("addresses[%d] %q", i, a.Name)
		v.checkName(p, a.Name)
		if addrs[a.Name] {
			v.add(p, "duplicate address or group name")
		}
		addrs[a.Name] = true
		if !validHostOrPrefix(a.CIDR) {
			v.add(p, "invalid cidr %q", a.CIDR)
		}
	}
	for i, g := range c.AddressGroups {
		p := fmt.Sprintf("address_groups[%d] %q", i, g.Name)
		v.checkName(p, g.Name)
		if addrs[g.Name] {
			v.add(p, "duplicate address or group name")
		}
		addrs[g.Name] = true
		switch {
		case len(g.Static) > 0 && g.Tag != "":
			v.add(p, "set either static or tag, not both")
		case len(g.Static) == 0 && g.Tag == "":
			v.add(p, "set static members or a tag")
		case g.Tag != "":
			if !nameRE.MatchString(g.Tag) {
				v.add(p, "invalid tag %q", g.Tag)
			}
		}
		for _, m := range g.Static {
			if !containsAddress(c.Addresses, m) {
				v.add(p, "unknown address %q (static members must be addresses)", m)
			}
		}
	}
	services := map[string]bool{}
	for i, s := range c.Services {
		p := fmt.Sprintf("services[%d] %q", i, s.Name)
		v.checkName(p, s.Name)
		if services[s.Name] {
			v.add(p, "duplicate service name")
		}
		services[s.Name] = true
		switch s.Protocol {
		case "tcp", "udp":
			if err := checkPorts(s.Ports); err != nil {
				v.add(p, "%v", err)
			}
		case "icmp":
			if s.Ports != "" {
				v.add(p, "icmp services take no ports")
			}
		default:
			v.add(p, "protocol must be tcp, udp or icmp, got %q", s.Protocol)
		}
	}

	ifaces := map[string]bool{}
	for i, in := range c.Interfaces {
		p := fmt.Sprintf("interfaces[%d] %q", i, in.Name)
		if in.Name == "" {
			v.add(p, "name required")
		}
		if ifaces[in.Name] {
			v.add(p, "duplicate interface")
		}
		ifaces[in.Name] = true
		isMgmt := in.Name == c.System.MgmtInterface
		switch {
		case isMgmt && in.Zone != "":
			v.add(p, "management interface must not be in a zone")
		case !isMgmt && !zones[in.Zone]:
			v.add(p, "unknown zone %q", in.Zone)
		}
		if in.Address != "" {
			pfx, err := netip.ParsePrefix(in.Address)
			switch {
			case err != nil:
				v.add(p, "invalid address %q (want CIDR, e.g. 10.0.0.1/24)", in.Address)
			case isMgmt:
				// Informational: the management address stays with the
				// deployment settings.
			case !pfx.Addr().Is4():
				v.add(p, "address %q must be IPv4", in.Address)
			case pfx.Bits() < 31 && pfx.Addr() == pfx.Masked().Addr():
				v.add(p, "address %q is the network address; give the interface a host address, e.g. %s", in.Address, pfx.Addr().Next().String()+"/"+strconv.Itoa(pfx.Bits()))
			}
		}
	}
	if m := c.System.MgmtInterface; m != "" && !ifaces[m] {
		v.add("system.mgmt_interface", "unknown interface %q", m)
	}

	// VRFs.
	vrfs := map[string]bool{VRFDefault: true, VRFMgmt: true}
	tables := map[int]string{}
	for i, vr := range c.VRFs {
		p := fmt.Sprintf("vrfs[%d] %q", i, vr.Name)
		v.checkName(p, vr.Name)
		switch {
		case vr.Name == VRFDefault || vr.Name == VRFMgmt:
			v.add(p, "%q is built in", vr.Name)
		case vrfs[vr.Name]:
			v.add(p, "duplicate vrf name")
		case len("vrf-"+vr.Name) > 15:
			v.add(p, "name too long (at most 11 characters: the device is vrf-<name>)")
		}
		vrfs[vr.Name] = true
		if vr.Table != 0 {
			if vr.Table < FirstVRFTable || vr.Table > 65535 {
				v.add(p, "table must be %d-65535 (or leave it out to pick one)", FirstVRFTable)
			} else if other, dup := tables[vr.Table]; dup {
				v.add(p, "table %d is already vrf %q's", vr.Table, other)
			}
			tables[vr.Table] = vr.Name
		}
	}

	// VLAN subinterfaces and interface VRFs.
	for i, in := range c.Interfaces {
		p := fmt.Sprintf("interfaces[%d] %q", i, in.Name)
		parent, id, isVLAN := ParseVLAN(in.Name)
		if isVLAN {
			_, _, isParentVLAN := ParseVLAN(parent)
			switch {
			case len(in.Name) > 15:
				v.add(p, "interface names are at most 15 characters")
			case id < 1 || id > 4094:
				v.add(p, "VLAN id must be 1-4094")
			case !ifaces[parent]:
				v.add(p, "VLAN parent %q is not an interface in the config", parent)
			case parent == c.System.MgmtInterface:
				v.add(p, "VLANs can't be on the management interface")
			case isParentVLAN:
				v.add(p, "VLANs on VLANs (QinQ) aren't supported")
			}
		}
		if in.VRF != "" && in.VRF != VRFDefault {
			switch {
			case in.VRF == VRFMgmt:
				v.add(p, "vrf mgmt is only for the management interface")
			case !vrfs[in.VRF]:
				v.add(p, "unknown vrf %q", in.VRF)
			case !isVLAN:
				v.add(p, "only VLAN subinterfaces (e.g. %s.20) can be in a VRF in this release", in.Name)
			}
		}
	}
	ifaceVRF := map[string]string{}
	for _, in := range c.Interfaces {
		ifaceVRF[in.Name] = in.VRFOf()
	}
	if m := c.System.MgmtInterface; m != "" {
		ifaceVRF[m] = VRFMgmt
	}

	appGroups := map[string]bool{}
	for i, g := range c.ApplicationGroups {
		p := fmt.Sprintf("application_groups[%d] %q", i, g.Name)
		v.checkName(p, g.Name)
		switch {
		case appGroups[g.Name]:
			v.add(p, "duplicate application group")
		case knownAppOrCategory(g.Name):
			v.add(p, "%q is an application or category already; pick another name", g.Name)
		}
		appGroups[g.Name] = true
		if len(g.Members) == 0 {
			v.add(p, "members required: applications or categories")
		}
		for _, m := range g.Members {
			if !knownAppOrCategory(m) {
				v.add(p, "members: unknown application or category %q (groups can't contain groups)", m)
			}
		}
	}

	ruleNames := map[string]bool{}
	for i, r := range c.Rules {
		p := fmt.Sprintf("rules[%d] %q", i, r.Name)
		v.checkName(p, r.Name)
		if ruleNames[r.Name] {
			v.add(p, "duplicate rule name")
		}
		ruleNames[r.Name] = true
		v.refs(p, "from", r.From, "zone", func(s string) bool { return zones[s] })
		v.refs(p, "to", r.To, "zone", func(s string) bool { return zones[s] })
		v.refs(p, "source", r.Source, "address or group", func(s string) bool { return addrs[s] })
		v.refs(p, "destination", r.Destination, "address or group", func(s string) bool { return addrs[s] })
		v.refs(p, "service", r.Service, "service", func(s string) bool { return services[s] })
		v.refs(p, "application", r.Application, "application, category or application group (show app catalog lists them)",
			func(s string) bool { return knownAppOrCategory(s) || appGroups[s] })
		switch r.Action {
		case "allow", "deny", "reset":
		default:
			v.add(p, "action must be allow, deny or reset, got %q", r.Action)
		}
	}

	v.nat(c, zones, addrs)

	routeNames := map[string]bool{}
	routeDests := map[string]bool{}
	for i, r := range c.Routes {
		p := fmt.Sprintf("routes[%d] %q", i, r.Name)
		v.checkName(p, r.Name)
		if routeNames[r.Name] {
			v.add(p, "duplicate route name")
		}
		routeNames[r.Name] = true
		switch r.Table {
		case "", TableMain, TableMgmt:
		default:
			v.add(p, "table must be main or mgmt, got %q (or use vrf)", r.Table)
		}
		if r.Table != "" && r.VRF != "" {
			v.add(p, "set vrf or table, not both")
		}
		vrf := r.VRFOf()
		switch {
		case !vrfs[vrf]:
			v.add(p, "unknown vrf %q", vrf)
		case vrf == VRFMgmt && c.System.MgmtInterface == "":
			v.add(p, "vrf mgmt needs system.mgmt_interface")
		}
		dst, err := netip.ParsePrefix(r.Destination)
		switch {
		case err != nil || !dst.Addr().Is4():
			v.add(p, "invalid destination %q (want an IPv4 prefix, e.g. 10.20.0.0/16)", r.Destination)
		case dst.Bits() == 0 && vrf == VRFMgmt:
			// A bad commit here could cut off management access, so the
			// mgmt default route stays with the deployment settings.
			v.add(p, "the management default route comes from the deployment settings (mgmt_gateway), not from routes")
		case dst.Masked() != dst:
			v.add(p, "destination %q has host bits set; did you mean %s?", r.Destination, dst.Masked())
		default:
			key := vrf + " " + dst.String()
			if routeDests[key] {
				v.add(p, "another route already covers %s in vrf %s", dst, vrf)
			}
			routeDests[key] = true
		}
		if r.NextVRF != "" {
			switch {
			case r.NextVRF == VRFDefault || r.NextVRF == VRFMgmt:
				v.add(p, "next_vrf must be a vrf you defined; to reach the default vrf, set gateway and interface instead")
			case !vrfs[r.NextVRF]:
				v.add(p, "unknown next_vrf %q", r.NextVRF)
			case r.NextVRF == vrf:
				v.add(p, "next_vrf is the route's own vrf")
			}
		}
		if r.Gateway != "" || r.NextVRF == "" {
			if gw, err := netip.ParseAddr(r.Gateway); err != nil || !gw.Is4() {
				v.add(p, "invalid gateway %q (want an IPv4 address)", r.Gateway)
			}
		}
		if r.Interface != "" {
			switch {
			case !ifaces[r.Interface]:
				v.add(p, "unknown interface %q", r.Interface)
			case r.NextVRF != "":
				v.add(p, "a next_vrf route goes to the other vrf, not out of an interface")
			case ifaceVRF[r.Interface] == VRFMgmt && vrf != VRFMgmt:
				v.add(p, "the management interface only carries vrf mgmt routes")
			case vrf == VRFMgmt && ifaceVRF[r.Interface] != VRFMgmt:
				v.add(p, "a vrf mgmt route must use the management interface %q", c.System.MgmtInterface)
			}
		}
	}

	// Dynamic routing.
	plists := v.names("prefix_lists", len(c.PrefixLists), func(i int) string { return c.PrefixLists[i].Name })
	for i, pl := range c.PrefixLists {
		p := fmt.Sprintf("prefix_lists[%d] %q", i, pl.Name)
		if len(pl.Entries) == 0 {
			v.add(p, "needs at least one entry, e.g. \"permit 10.0.0.0/8 le 24\"")
		}
		for j, e := range pl.Entries {
			if _, _, _, _, err := ParsePrefixEntry(e); err != nil {
				v.add(p, "entry %d %q: %v", j+1, e, err)
			}
		}
	}
	routingVRFs := map[string]bool{}
	for i, r := range c.Routing {
		p := fmt.Sprintf("routing[%d] %q", i, r.Name)
		switch {
		case r.Name == VRFMgmt:
			v.add(p, "no dynamic routing in the management vrf")
		case !vrfs[r.Name]:
			v.add(p, "name must be a vrf (default or one you defined)")
		case routingVRFs[r.Name]:
			v.add(p, "duplicate routing entry for vrf %s", r.Name)
		}
		routingVRFs[r.Name] = true
		if r.BGPASN == 0 && !r.OSPF {
			v.add(p, "turns on neither BGP (bgp_asn) nor OSPF (ospf: true)")
		}
		if id, err := netip.ParseAddr(r.RouterID); err != nil || !id.Is4() {
			v.add(p, "router_id must be an IPv4 address, e.g. one of the firewall's own")
		}
		if r.BGPASN == 0 && (len(r.BGPNetworks) > 0 || len(r.BGPRedistribute) > 0) {
			v.add(p, "bgp_networks and bgp_redistribute need bgp_asn")
		}
		if !r.OSPF && len(r.OSPFRedistribute) > 0 {
			v.add(p, "ospf_redistribute needs ospf: true")
		}
		for _, n := range r.BGPNetworks {
			if pr, err := netip.ParsePrefix(n); err != nil || !pr.Addr().Is4() || pr.Masked() != pr {
				v.add(p, "bgp_networks: %q is not an IPv4 prefix without host bits", n)
			}
		}
		for _, src := range r.BGPRedistribute {
			if src != RedistConnected && src != RedistStatic && src != RedistOSPF {
				v.add(p, "bgp_redistribute: %q must be connected, static or ospf", src)
			}
		}
		for _, src := range r.OSPFRedistribute {
			if src != RedistConnected && src != RedistStatic && src != RedistBGP {
				v.add(p, "ospf_redistribute: %q must be connected, static or bgp", src)
			}
		}
	}
	nbrNames := map[string]bool{}
	nbrAddrs := map[string]bool{}
	for i, n := range c.BGPNeighbors {
		p := fmt.Sprintf("bgp_neighbors[%d] %q", i, n.Name)
		v.checkName(p, n.Name)
		if nbrNames[n.Name] {
			v.add(p, "duplicate neighbor name")
		}
		nbrNames[n.Name] = true
		vrf := n.VRFOf()
		if r := c.RoutingFor(vrf); r == nil || r.BGPASN == 0 {
			v.add(p, "vrf %s has no BGP: add a routing entry for it with bgp_asn", vrf)
		}
		if a, err := netip.ParseAddr(n.Address); err != nil || !a.Is4() {
			v.add(p, "address must be an IPv4 address")
		} else if nbrAddrs[vrf+" "+a.String()] {
			v.add(p, "another neighbor in vrf %s has address %s", vrf, a)
		} else {
			nbrAddrs[vrf+" "+a.String()] = true
		}
		if n.RemoteAS == 0 {
			v.add(p, "remote_as required")
		}
		for _, pl := range []string{n.Import, n.Export} {
			if pl != "" && !plists[pl] {
				v.add(p, "unknown prefix list %q", pl)
			}
		}
	}
	ospfIfs := map[string]bool{}
	for i, o := range c.OSPFInterfaces {
		p := fmt.Sprintf("ospf_interfaces[%d] %q", i, o.Name)
		if ospfIfs[o.Name] {
			v.add(p, "duplicate ospf interface")
		}
		ospfIfs[o.Name] = true
		vrf := c.InterfaceVRF(o.Name)
		switch {
		case vrf == "":
			v.add(p, "unknown interface %q", o.Name)
		case vrf == VRFMgmt:
			v.add(p, "no OSPF on the management interface")
		default:
			if r := c.RoutingFor(vrf); r == nil || !r.OSPF {
				v.add(p, "vrf %s has no OSPF: add a routing entry for it with ospf: true", vrf)
			}
		}
		if _, ok := NormalizeArea(o.Area); !ok {
			v.add(p, "area must be a number or dotted quad, e.g. 0 or 0.0.0.0")
		}
		if o.Cost < 0 || o.Cost > 65535 {
			v.add(p, "cost must be 1-65535 (or 0 for automatic)")
		}
	}
	v.dhcp(c)
	v.ips(c)
	v.decryption(c, zones, addrs)

	return errors.Join(v.errs...)
}

// names checks a list of simple named items and returns the set of names.
func (v *validator) names(kind string, n int, name func(int) string) map[string]bool {
	set := map[string]bool{}
	for i := 0; i < n; i++ {
		nm := name(i)
		p := fmt.Sprintf("%s[%d] %q", kind, i, nm)
		v.checkName(p, nm)
		if set[nm] {
			v.add(p, "duplicate name")
		}
		set[nm] = true
	}
	return set
}

func (v *validator) checkName(path, name string) {
	switch {
	case name == "":
		v.add(path, "name required")
	case name == Any:
		v.add(path, "%q is reserved", Any)
	case !nameRE.MatchString(name):
		v.add(path, "invalid name (letters, digits, _ . - only; max 63)")
	}
}

// refs validates a rule match field: empty or ["any"] matches everything;
// otherwise every entry must resolve.
func (v *validator) refs(path, field string, vals []string, kind string, ok func(string) bool) {
	for _, s := range vals {
		if s == Any {
			if len(vals) > 1 {
				v.add(path, "%s: %q cannot be combined with other values", field, Any)
			}
			continue
		}
		if !ok(s) {
			v.add(path, "%s: unknown %s %q", field, kind, s)
		}
	}
}

// knownApp reports whether an application name is in App Identification's catalog (any
// case), or is "unknown" (connections App Identification couldn't identify).
func knownApp(s string) bool {
	if strings.EqualFold(s, appid.Unknown) {
		return true
	}
	_, ok := appid.Lookup(s)
	return ok
}

// knownAppOrCategory accepts an application or a category reference.
func knownAppOrCategory(s string) bool {
	if knownApp(s) {
		return true
	}
	_, ok := appid.CategoryApps(s)
	return ok
}

func validHostOrPrefix(s string) bool {
	if _, err := netip.ParsePrefix(s); err == nil {
		return true
	}
	_, err := netip.ParseAddr(s)
	return err == nil
}

func containsAddress(as []Address, name string) bool {
	for _, a := range as {
		if a.Name == name {
			return true
		}
	}
	return false
}

// checkPorts validates "80,443,8000-8080".
func checkPorts(s string) error {
	if strings.TrimSpace(s) == "" {
		return errors.New("ports required")
	}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		lo, hi, isRange := strings.Cut(part, "-")
		a, err := port(lo)
		if err != nil {
			return err
		}
		if isRange {
			b, err := port(hi)
			if err != nil {
				return err
			}
			if a > b {
				return fmt.Errorf("port range %q is reversed", part)
			}
		}
	}
	return nil
}

func port(s string) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("invalid port %q (1-65535)", s)
	}
	return n, nil
}
