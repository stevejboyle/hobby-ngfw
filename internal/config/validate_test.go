package config

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func base() *Config {
	return &Config{
		System:     System{Hostname: "fw1", MgmtInterface: "mgmt0"},
		Zones:      []Zone{{Name: "users"}, {Name: "internet"}},
		Interfaces: []Interface{{Name: "mgmt0"}, {Name: "eth1", Zone: "users", Address: "10.0.0.1/24"}},
		Addresses:  []Address{{Name: "lan", CIDR: "10.0.0.0/24"}, {Name: "h1", CIDR: "10.0.0.5"}},
		AddressGroups: []AddressGroup{
			{Name: "quarantine", Tag: "quarantine"},
			{Name: "hosts", Static: []string{"h1"}},
		},
		Services: []Service{{Name: "web", Protocol: "tcp", Ports: "80,443,8000-8080"}},
		Rules: []Rule{{
			Name: "r1", From: []string{"users"}, To: []string{"internet"},
			Source: []string{"quarantine"}, Service: []string{"web"},
			Application: []string{"bittorrent"}, Action: "deny",
		}},
	}
}

func rt(name, dst, gw, iface, table string) Route {
	return Route{Name: name, Destination: dst, Gateway: gw, Interface: iface, Table: table}
}

func TestValidRoutes(t *testing.T) {
	c := base()
	c.Routes = []Route{
		rt("lab", "10.20.0.0/16", "10.0.0.254", "", ""),
		rt("lab-host", "10.30.0.5/32", "10.0.0.254", "eth1", "main"),
		rt("same-dest-other-table", "10.20.0.0/16", "192.168.10.1", "mgmt0", "mgmt"),
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("routes should be valid: %v", err)
	}
}

func TestValidVRFs(t *testing.T) {
	c := base()
	c.VRFs = []VRF{{Name: "blue"}, {Name: "red", Table: 1001}, {Name: "green"}}
	c.Interfaces = append(c.Interfaces,
		Interface{Name: "eth1.20", Zone: "users", VRF: "blue", Address: "10.20.0.1/24"},
		Interface{Name: "eth1.30", Zone: "users", VRF: "red", Address: "10.20.0.1/24"}, // overlap across VRFs is fine
	)
	c.Routes = []Route{
		{Name: "blue-net", Destination: "10.40.0.0/16", Gateway: "10.20.0.254", VRF: "blue"},
		{Name: "blue-default", Destination: "0.0.0.0/0", Gateway: "10.20.0.254", VRF: "blue"},
		{Name: "leak", Destination: "10.30.0.0/16", VRF: "blue", NextVRF: "red"},
		{Name: "same-dest-red", Destination: "10.40.0.0/16", Gateway: "10.20.0.253", VRF: "red"},
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("vrf config should be valid: %v", err)
	}
	tabs := c.VRFTables()
	if tabs["default"] != 0 || tabs["mgmt"] != 100 || tabs["red"] != 1001 || tabs["blue"] != 1002 || tabs["green"] != 1003 {
		t.Fatalf("tables: %v", tabs)
	}
	for name, want := range map[string]bool{"inside.20": true, "inside": false, "a.b.30": true, "x.": false, ".5": false, "x.05": false} {
		if _, _, ok := ParseVLAN(name); ok != want {
			t.Errorf("ParseVLAN(%q) = %v", name, ok)
		}
	}
}

func TestValidBase(t *testing.T) {
	if err := base().Validate(); err != nil {
		t.Fatalf("base config should be valid: %v", err)
	}
}

func TestInvalid(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{"no hostname", func(c *Config) { c.System.Hostname = "" }, "system.hostname: required"},
		{"dup zone", func(c *Config) { c.Zones = append(c.Zones, Zone{Name: "users"}) }, "duplicate name"},
		{"reserved any", func(c *Config) { c.Zones[0].Name = "any" }, `"any" is reserved`},
		{"bad name", func(c *Config) { c.Zones[0].Name = "bad name" }, "invalid name"},
		{"bad cidr", func(c *Config) { c.Addresses[0].CIDR = "10.0.0.0/33" }, "invalid cidr"},
		{"addr group clash", func(c *Config) { c.AddressGroups[0].Name = "lan" }, "duplicate address or group name"},
		{"dup group", func(c *Config) { c.AddressGroups[1].Name = "quarantine" }, "duplicate address or group name"},
		{"group both", func(c *Config) { c.AddressGroups[0].Static = []string{"h1"} }, "not both"},
		{"group neither", func(c *Config) { c.AddressGroups[0].Tag = "" }, "set static members or a tag"},
		{"group unknown member", func(c *Config) { c.AddressGroups[1].Static = []string{"nope"} }, `unknown address "nope"`},
		{"bad protocol", func(c *Config) { c.Services[0].Protocol = "gre" }, "protocol must be tcp, udp or icmp"},
		{"icmp with ports", func(c *Config) { c.Services[0].Protocol = "icmp" }, "icmp services take no ports"},
		{"bad port", func(c *Config) { c.Services[0].Ports = "70000" }, "invalid port"},
		{"reversed range", func(c *Config) { c.Services[0].Ports = "90-80" }, "reversed"},
		{"iface unknown zone", func(c *Config) { c.Interfaces[1].Zone = "dmz" }, `unknown zone "dmz"`},
		{"mgmt in zone", func(c *Config) { c.Interfaces[0].Zone = "users" }, "management interface must not be in a zone"},
		{"mgmt missing", func(c *Config) { c.System.MgmtInterface = "eth9" }, `unknown interface "eth9"`},
		{"iface bad addr", func(c *Config) { c.Interfaces[1].Address = "10.0.0.1" }, "want CIDR"},
		{"bad app_id", func(c *Config) { c.System.AppID = "yes" }, "must be on or off"},
		{"iface network addr", func(c *Config) { c.Interfaces[1].Address = "10.0.0.0/24" }, "is the network address"},
		{"iface ipv6 addr", func(c *Config) { c.Interfaces[1].Address = "fd00::1/64" }, "must be IPv4"},
		{"rule unknown zone", func(c *Config) { c.Rules[0].To = []string{"dmz"} }, `to: unknown zone "dmz"`},
		{"rule unknown source", func(c *Config) { c.Rules[0].Source = []string{"nope"} }, `source: unknown address or group "nope"`},
		{"rule any mixed", func(c *Config) { c.Rules[0].From = []string{"any", "users"} }, "cannot be combined"},
		{"rule bad app", func(c *Config) { c.Rules[0].Application = []string{"BitTorrent!"} }, `unknown application, category or application group (show app catalog lists them) "BitTorrent!"`},
		{"rule bad category", func(c *Config) { c.Rules[0].Application = []string{"category:nope"} }, `"category:nope"`},
		{"group bad member", func(c *Config) {
			c.ApplicationGroups = []ApplicationGroup{{Name: "streaming", Members: []string{"youtube", "flixnet"}}}
		}, `unknown application or category "flixnet"`},
		{"group named like an app", func(c *Config) {
			c.ApplicationGroups = []ApplicationGroup{{Name: "youtube", Members: []string{"netflix"}}}
		}, "is an application or category already"},
		{"group nested", func(c *Config) {
			c.ApplicationGroups = []ApplicationGroup{{Name: "a1", Members: []string{"youtube"}}, {Name: "a2", Members: []string{"a1"}}}
		}, "groups can't contain groups"},
		{"rule made-up app", func(c *Config) { c.Rules[0].Application = []string{"youtub"} }, `unknown application, category or application group (show app catalog lists them) "youtub"`},
		{"rule bad action", func(c *Config) { c.Rules[0].Action = "permit" }, "action must be allow, deny or reset"},
		{"dup rule", func(c *Config) { c.Rules = append(c.Rules, c.Rules[0]) }, "duplicate rule name"},
		{"nat bad type", func(c *Config) { c.NAT = []NATRule{{Name: "n", Type: "dnat"}} }, "type must be masquerade"},
		{"nat unknown zone", func(c *Config) {
			c.NAT = []NATRule{{Name: "n", To: []string{"dmz"}, Type: "masquerade"}}
		}, `to: unknown zone "dmz"`},
		{"nat dup", func(c *Config) {
			c.NAT = []NATRule{{Name: "n", Type: "masquerade"}, {Name: "n", Type: "masquerade"}}
		}, "duplicate nat rule name"},
		{"route bad table", func(c *Config) { c.Routes = []Route{rt("r", "10.20.0.0/16", "10.0.0.254", "", "vrf2")} }, "table must be main or mgmt"},
		{"route bad dest", func(c *Config) { c.Routes = []Route{rt("r", "10.20.0.0", "10.0.0.254", "", "")} }, "invalid destination"},
		{"route mgmt default", func(c *Config) { c.Routes = []Route{rt("r", "0.0.0.0/0", "10.0.0.254", "mgmt0", "mgmt")} }, "management default route comes from the deployment settings"},
		{"route host bits", func(c *Config) { c.Routes = []Route{rt("r", "10.20.1.0/16", "10.0.0.254", "", "")} }, "did you mean 10.20.0.0/16"},
		{"route bad gw", func(c *Config) { c.Routes = []Route{rt("r", "10.20.0.0/16", "10.0.0.256", "", "")} }, "invalid gateway"},
		{"route ipv6 gw", func(c *Config) { c.Routes = []Route{rt("r", "10.20.0.0/16", "fe80::1", "", "")} }, "invalid gateway"},
		{"route unknown iface", func(c *Config) { c.Routes = []Route{rt("r", "10.20.0.0/16", "10.0.0.254", "eth9", "")} }, `unknown interface "eth9"`},
		{"route mgmt iface in main", func(c *Config) { c.Routes = []Route{rt("r", "10.20.0.0/16", "10.0.0.254", "mgmt0", "")} }, "only carries vrf mgmt routes"},
		{"route mgmt table wrong iface", func(c *Config) { c.Routes = []Route{rt("r", "10.20.0.0/16", "10.0.0.254", "eth1", "mgmt")} }, "must use the management interface"},
		{"route dup dest", func(c *Config) {
			c.Routes = []Route{rt("a", "10.20.0.0/16", "10.0.0.254", "", ""), rt("b", "10.20.0.0/16", "10.0.0.253", "", "main")}
		}, "another route already covers 10.20.0.0/16"},
		{"vrf builtin", func(c *Config) { c.VRFs = []VRF{{Name: "mgmt"}} }, "is built in"},
		{"vrf dup", func(c *Config) { c.VRFs = []VRF{{Name: "blue"}, {Name: "blue"}} }, "duplicate vrf name"},
		{"vrf long", func(c *Config) { c.VRFs = []VRF{{Name: "averylongname"}} }, "name too long"},
		{"vrf table range", func(c *Config) { c.VRFs = []VRF{{Name: "blue", Table: 100}} }, "table must be 1001-65535"},
		{"vrf table dup", func(c *Config) { c.VRFs = []VRF{{Name: "blue", Table: 1100}, {Name: "red", Table: 1100}} }, "already vrf \"blue\"'s"},
		{"vlan bad id", func(c *Config) { c.Interfaces = append(c.Interfaces, Interface{Name: "eth1.5000", Zone: "users"}) }, "VLAN id must be 1-4094"},
		{"vlan no parent", func(c *Config) { c.Interfaces = append(c.Interfaces, Interface{Name: "eth7.20", Zone: "users"}) }, `VLAN parent "eth7"`},
		{"vlan on mgmt", func(c *Config) { c.Interfaces = append(c.Interfaces, Interface{Name: "mgmt0.20", Zone: "users"}) }, "can't be on the management interface"},
		{"vlan qinq", func(c *Config) {
			c.Interfaces = append(c.Interfaces, Interface{Name: "eth1.20", Zone: "users"}, Interface{Name: "eth1.20.30", Zone: "users"})
		}, "QinQ"},
		{"iface unknown vrf", func(c *Config) {
			c.Interfaces = append(c.Interfaces, Interface{Name: "eth1.20", Zone: "users", VRF: "red"})
		}, `unknown vrf "red"`},
		{"physical iface in vrf", func(c *Config) { c.VRFs = []VRF{{Name: "blue"}}; c.Interfaces[1].VRF = "blue" }, "only VLAN subinterfaces"},
		{"iface in mgmt vrf", func(c *Config) {
			c.Interfaces = append(c.Interfaces, Interface{Name: "eth1.20", Zone: "users", VRF: "mgmt"})
		}, "only for the management interface"},
		{"route unknown vrf", func(c *Config) {
			c.Routes = []Route{{Name: "r", Destination: "10.20.0.0/16", Gateway: "10.0.0.254", VRF: "red"}}
		}, `unknown vrf "red"`},
		{"route vrf and table", func(c *Config) {
			c.Routes = []Route{{Name: "r", Destination: "10.20.0.0/16", Gateway: "10.0.0.254", VRF: "default", Table: "main"}}
		}, "not both"},
		{"route next_vrf default", func(c *Config) {
			c.VRFs = []VRF{{Name: "blue"}}
			c.Routes = []Route{{Name: "r", Destination: "10.20.0.0/16", VRF: "blue", NextVRF: "default"}}
		}, "next_vrf must be a vrf you defined"},
		{"route next_vrf self", func(c *Config) {
			c.VRFs = []VRF{{Name: "blue"}}
			c.Routes = []Route{{Name: "r", Destination: "10.20.0.0/16", VRF: "blue", NextVRF: "blue"}}
		}, "route's own vrf"},
		{"route no gateway", func(c *Config) { c.Routes = []Route{{Name: "r", Destination: "10.20.0.0/16"}} }, "invalid gateway"},
		{"route dup name", func(c *Config) {
			c.Routes = []Route{rt("a", "10.20.0.0/16", "10.0.0.254", "", ""), rt("a", "10.30.0.0/16", "10.0.0.254", "", "")}
		}, "duplicate route name"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := base()
			tc.mutate(c)
			err := c.Validate()
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected error containing %q, got:\n%v", tc.want, err)
			}
		})
	}
}

func TestReportsAllErrors(t *testing.T) {
	c := base()
	c.System.Hostname = ""
	c.Rules[0].Action = "permit"
	err := c.Validate()
	if err == nil || strings.Count(err.Error(), "\n") < 1 {
		t.Fatalf("expected two joined errors, got %v", err)
	}
}

func TestParseRejectsUnknownKeys(t *testing.T) {
	_, err := Parse([]byte("system:\n  hostname: fw1\n  colour: blue\n"))
	if err == nil || !strings.Contains(err.Error(), "colour") {
		t.Fatalf("expected unknown-field error, got %v", err)
	}
}

func TestParseEmpty(t *testing.T) {
	if _, err := Parse(nil); err == nil {
		t.Fatal("expected error for empty config")
	}
}

func TestExamplesValidate(t *testing.T) {
	files, err := filepath.Glob("../../examples/*.yaml")
	if err != nil || len(files) == 0 {
		t.Fatalf("no examples found: %v", err)
	}
	for _, f := range files {
		if _, err := Load(f); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
}

func TestRoutingValidation(t *testing.T) {
	good, err := Load("../../examples/routing.yaml")
	if err != nil {
		t.Fatalf("routing example: %v", err)
	}
	cases := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{"routing in mgmt", func(c *Config) { c.Routing[1].Name = "mgmt" }, "no dynamic routing in the management vrf"},
		{"routing unknown vrf", func(c *Config) { c.Routing[1].Name = "nope" }, "name must be a vrf"},
		{"routing nothing on", func(c *Config) { c.Routing[1].BGPASN = 0 }, "neither BGP"},
		{"routing bad id", func(c *Config) { c.Routing[0].RouterID = "x" }, "router_id must be an IPv4"},
		{"bad redistribute", func(c *Config) { c.Routing[0].BGPRedistribute = []string{"bgp"} }, "must be connected, static or ospf"},
		{"bad network", func(c *Config) { c.Routing[0].BGPNetworks = []string{"10.10.1.0/16"} }, "not an IPv4 prefix without host bits"},
		{"neighbor vrf no bgp", func(c *Config) { c.Routing[1].BGPASN = 0; c.Routing[1].OSPF = true }, "vrf lab has no BGP"},
		{"neighbor dup address", func(c *Config) { c.BGPNeighbors[1].Address = "192.0.2.1" }, "another neighbor in vrf default"},
		{"neighbor no as", func(c *Config) { c.BGPNeighbors[0].RemoteAS = 0 }, "remote_as required"},
		{"neighbor bad plist", func(c *Config) { c.BGPNeighbors[0].Import = "nope" }, `unknown prefix list "nope"`},
		{"ospf unknown iface", func(c *Config) { c.OSPFInterfaces[0].Name = "eth9" }, `unknown interface "eth9"`},
		{"ospf on mgmt", func(c *Config) { c.OSPFInterfaces[0].Name = "mgmt" }, "management interface"},
		{"ospf vrf without ospf", func(c *Config) {
			c.OSPFInterfaces = append(c.OSPFInterfaces, OSPFInterface{Name: "inside.20", Area: "0"})
		}, "vrf lab has no OSPF"},
		{"ospf bad area", func(c *Config) { c.OSPFInterfaces[0].Area = "backbone" }, "area must be"},
		{"plist bad entry", func(c *Config) { c.PrefixLists[0].Entries = []string{"allow 10.0.0.0/8"} }, "permit or deny"},
		{"plist bad le", func(c *Config) { c.PrefixLists[0].Entries = []string{"permit 10.0.0.0/16 le 8"} }, "prefix length < ge <= le"},
		{"plist empty", func(c *Config) { c.PrefixLists[0].Entries = nil }, "at least one entry"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := Load("../../examples/routing.yaml")
			tc.mutate(c)
			err := c.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q, got: %v", tc.want, err)
			}
		})
	}
	if a, _ := NormalizeArea("1"); a != "0.0.0.1" {
		t.Fatalf("area: %s", a)
	}
	_ = good
}

func TestAppGroupsAndCategories(t *testing.T) {
	c := base()
	c.ApplicationGroups = []ApplicationGroup{{Name: "streaming", Members: []string{"YouTube", "netflix", "category:video"}}}
	c.Rules[0].Application = []string{"streaming", "category:socialnetwork", "unknown", "bittorrent"}
	if err := c.Validate(); err != nil {
		t.Fatalf("valid: %v", err)
	}
}

func TestIPSValidation(t *testing.T) {
	c := base()
	c.System.IPS = "maybe"
	c.System.IPSDisabledSignatures = []string{"2100498", "abc"}
	c.IPSProfiles = []IPSProfile{{Name: "p", Critical: "drop"}, {Name: "p"}}
	c.Rules = []Rule{
		{Name: "a", Action: "deny", IPSProfile: "default"},
		{Name: "b", Action: "allow", IPSProfile: "nope"},
		{Name: "c", Action: "allow", IPSProfile: "default"},
	}
	err := c.Validate()
	for _, want := range []string{
		"system.ips: must be on or off",
		`"abc" is not a signature ID`,
		"critical must be block, alert or ignore",
		"duplicate IPS profile name",
		"ips_profile applies to allow rules only",
		`unknown IPS profile "nope"`,
	} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("want %q in %v", want, err)
		}
	}
	if strings.Contains(err.Error(), `rules[2]`) {
		t.Errorf("the built-in default profile is valid: %v", err)
	}
	p, _ := c.IPSProfile("default")
	if p.Action("critical") != IPSBlock || p.Action("minor") != IPSAlert || p.Action("informational") != IPSIgnore {
		t.Errorf("default profile: %+v", p)
	}
	if (IPSProfile{Minor: IPSBlock}).Action("major") != IPSBlock {
		t.Error("unset severities fall back to the default's action")
	}
}

func TestIPSExceptions(t *testing.T) {
	c := base()
	c.Rules = append(c.Rules,
		Rule{Name: "web-in", From: []string{"internet"}, To: []string{"users"}, Action: "allow", IPSProfile: "default"},
		Rule{Name: "plain", From: []string{"users"}, To: []string{"internet"}, Action: "allow"},
	)
	c.IPSExceptions = []IPSException{
		{Name: "scanner", SID: "2019876", Source: []string{"h1"}},
		{Name: "web", SID: "2019876", Rules: []string{"web-in"}, Destination: []string{"lan", "quarantine"}, Action: "ignore"},
		{Name: "other", SID: "9900001", Rules: []string{"web-in"}, Action: "alert"},
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("exceptions should be valid: %v", err)
	}
	if got := c.IPSExceptionSIDs(); len(got) != 2 || got[0] != 2019876 || got[1] != 9900001 {
		t.Errorf("IPSExceptionSIDs = %v", got)
	}
	if c.IPSExceptions[0].ActionOf() != IPSAlert || c.IPSExceptions[1].ActionOf() != IPSIgnore {
		t.Error("ActionOf: alert by default")
	}
	c.IPSExceptions = []IPSException{
		{Name: "no-scope", SID: "1"},
		{Name: "bad-sid", SID: "ET-1", Source: []string{"h1"}},
		{Name: "bad-rule", SID: "2", Rules: []string{"nope", "plain"}},
		{Name: "bad-addr", SID: "3", Source: []string{"nowhere"}, Destination: []string{"any"}},
		{Name: "bad-action", SID: "4", Source: []string{"h1"}, Action: "block"},
		{Name: "bad-action", SID: "5", Source: []string{"h1"}},
	}
	err := c.Validate()
	for _, want := range []string{
		`ips_exceptions[0] "no-scope": give rules, source or destination`,
		`"bad-sid": sid must be a signature ID`,
		`rules: unknown rule "nope"`,
		`rules: rule "plain" has no ips_profile`,
		`source: unknown address or group "nowhere"`,
		`destination: leave it out rather than "any"`,
		`action must be alert or ignore, got "block"`,
		"duplicate IPS exception name",
	} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("want %q in %v", want, err)
		}
	}
	c.IPSExceptions = nil
	for i := 0; i <= MaxIPSExceptionSIDs; i++ {
		c.IPSExceptions = append(c.IPSExceptions, IPSException{Name: fmt.Sprintf("e%d", i), SID: fmt.Sprint(1000 + i), Source: []string{"h1"}})
	}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "at most 35 can have exceptions") {
		t.Errorf("want the SID limit, got %v", err)
	}
}

func TestTrunkInterfaces(t *testing.T) {
	c := base()
	c.Interfaces = append(c.Interfaces,
		Interface{Name: "eth2"}, // trunk: no zone
		Interface{Name: "eth2.150", Zone: "users", Address: "10.0.150.1/24"},
	)
	if err := c.Validate(); err != nil {
		t.Fatalf("a trunk carrying a VLAN should be valid: %v", err)
	}
	if got := c.Trunks(); len(got) != 1 || got[0] != "eth2" || !c.IsTrunk("eth2") || c.IsTrunk("mgmt0") {
		t.Errorf("Trunks() = %v", got)
	}
	cases := []struct {
		name string
		mod  func(c *Config)
		want string
	}{
		{"no zone, no VLANs", func(c *Config) { c.Interfaces = append(c.Interfaces, Interface{Name: "eth3"}) }, "zone required"},
		{"VLAN without zone", func(c *Config) {
			c.Interfaces = append(c.Interfaces, Interface{Name: "eth2"}, Interface{Name: "eth2.150"})
		}, `interfaces[3] "eth2.150": zone required`},
		{"trunk with address", func(c *Config) {
			c.Interfaces = append(c.Interfaces, Interface{Name: "eth2", Address: "10.0.9.1/24"}, Interface{Name: "eth2.150", Zone: "users"})
		}, "takes no address"},
		{"published on a trunk", func(c *Config) {
			c.Interfaces = append(c.Interfaces, Interface{Name: "eth2"}, Interface{Name: "eth2.150", Zone: "users"})
			c.Addresses = append(c.Addresses, Address{Name: "srv", CIDR: "10.0.0.20"})
			c.NAT = []NATRule{{Name: "n", Type: NATPortForward, Interface: "eth2", Protocol: "tcp", PublicPort: "80", Server: "srv"}}
		}, "is a trunk"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := base()
			tc.mod(c)
			if err := c.Validate(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q, got %v", tc.want, err)
			}
		})
	}
}
