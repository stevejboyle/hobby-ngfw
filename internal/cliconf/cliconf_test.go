package cliconf

import (
	"os"
	"strings"
	"testing"
)

func lab(t *testing.T) *Model {
	t.Helper()
	data, err := os.ReadFile("../../examples/basic.yaml")
	if err != nil {
		t.Fatal(err)
	}
	m, err := LoadYAML(data)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func run(t *testing.T, m *Model, lines ...string) {
	t.Helper()
	for _, l := range lines {
		w := strings.Fields(l)
		var err error
		switch w[0] {
		case "set":
			err = m.Set(w[1:])
		case "delete":
			err = m.Delete(w[1:])
		case "move":
			err = m.Move(w[1:])
		case "rename":
			err = m.Rename(w[1:])
		}
		if err != nil {
			t.Fatalf("%s: %v", l, err)
		}
	}
}

func valid(t *testing.T, m *Model) {
	t.Helper()
	c, err := m.Config()
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("config should be valid:\n%v", err)
	}
}

func TestSetBuildsValidObjects(t *testing.T) {
	m := lab(t)
	run(t, m,
		"set address web-srv cidr 10.10.1.80",
		"set service ssh protocol tcp ports 22",
		"set rule allow-ssh from users to internet source [ users-net web-srv ] service ssh action allow log yes",
		"set route lab2 destination 10.30.0.0/16 gateway 10.10.1.254",
		"set system hostname sjb-lab",
	)
	valid(t, m)
	c, _ := m.Config()
	r := c.Rules[len(c.Rules)-1]
	if r.Name != "allow-ssh" || strings.Join(r.Source, ",") != "users-net,web-srv" || r.Action != "allow" || !r.Log {
		t.Fatalf("rule: %+v", r)
	}
	if c.System.Hostname != "sjb-lab" || c.Routes[len(c.Routes)-1].Gateway != "10.10.1.254" {
		t.Fatalf("system/route: %+v %+v", c.System, c.Routes)
	}
}

func TestListSemantics(t *testing.T) {
	m := lab(t)
	run(t, m, "set rule allow-web service dns") // adds
	c, _ := m.Config()
	if got := strings.Join(c.Rules[3].Service, ","); got != "web,dns" {
		t.Fatalf("set should add members: %s", got)
	}
	run(t, m, "delete rule allow-web service web")
	c, _ = m.Config()
	if got := strings.Join(c.Rules[3].Service, ","); got != "dns" {
		t.Fatalf("delete member: %s", got)
	}
	run(t, m, "set rule allow-web service any")
	c, _ = m.Config()
	if got := strings.Join(c.Rules[3].Service, ","); got != "any" {
		t.Fatalf("any replaces: %s", got)
	}
	run(t, m, "set rule allow-web service web")
	c, _ = m.Config()
	if got := strings.Join(c.Rules[3].Service, ","); got != "web" {
		t.Fatalf("a member replaces any: %s", got)
	}
	run(t, m, "delete rule allow-web service")
	c, _ = m.Config()
	if len(c.Rules[3].Service) != 0 {
		t.Fatalf("clearing: %v", c.Rules[3].Service)
	}
	valid(t, m)
}

func TestMoveAndRename(t *testing.T) {
	m := lab(t)
	run(t, m, "move rule allow-web top", "move rule block-p2p after allow-dns")
	if got := strings.Join(m.Names("rules"), ","); got != "allow-web,block-quarantined,allow-dns,block-p2p" {
		t.Fatalf("order: %s", got)
	}
	run(t, m, "rename zone users staff", "rename address users-net staff-net", "rename service web http")
	valid(t, m)
	c, _ := m.Config()
	r := c.Rules[0]
	if strings.Join(r.From, ",") != "staff" || strings.Join(r.Source, ",") != "staff-net" || strings.Join(r.Service, ",") != "http" {
		t.Fatalf("references not renamed: %+v", r)
	}
	if c.Interfaces[1].Zone != "staff" {
		t.Fatalf("interface zone not renamed: %+v", c.Interfaces[1])
	}
}

func TestErrors(t *testing.T) {
	m := lab(t)
	for _, l := range []string{
		"set", "set bogus x", "set rule", "set rule r1 colour red", "set rule r1 action permit",
		"set rule r1 log maybe", "set rule r1 source [ a b", "set rule r1 source [ ]",
		"set address-group g1 static any", "delete rule nope", "delete rule allow-web service nope",
		"delete rule allow-web action allow", "delete system", "move zone users top", "move rule allow-web sideways",
		"move rule allow-web before nope", "rename address users-net dns-quad9", "rename system x",
		"set rule any action allow",
	} {
		w := strings.Fields(l)
		var err error
		switch w[0] {
		case "set":
			err = m.Set(w[1:])
		case "delete":
			err = m.Delete(w[1:])
		case "move":
			err = m.Move(w[1:])
		case "rename":
			err = m.Rename(w[1:])
		}
		if err == nil {
			t.Errorf("%q: expected an error", l)
		}
	}
}

func TestShow(t *testing.T) {
	m := lab(t)
	out, err := m.Show([]string{"rule", "allow-web"})
	if err != nil || !strings.Contains(out, "allow-web") || strings.Contains(out, "allow-dns") {
		t.Fatalf("show rule: %v\n%s", err, out)
	}
	if out, _ := m.Show(nil); !strings.Contains(out, "hostname: fw1") {
		t.Fatalf("show all:\n%s", out)
	}
}

func words(cs []Candidate) string {
	var out []string
	for _, c := range cs {
		out = append(out, c.Word)
	}
	return strings.Join(out, " ")
}

func TestConfigCandidates(t *testing.T) {
	m := lab(t)
	tests := []struct {
		line, partial, want string
	}{
		{"", "s", "set show"},
		{"set", "ad", "address address-group"},
		{"set rule", "allow-", "allow-dns allow-web <name>"},
		{"set rule allow-web", "", "from to source source-negate destination destination-negate service application action log ips-profile"},
		{"set rule allow-web action", "", "allow deny reset"},
		{"set rule allow-web from", "", "users internet any ["},
		{"set rule allow-web source [ users-net", "", "dns-quad9 quarantine dns-servers ] <country:XX>"},
		{"set rule allow-web source", "country:C", "country:CA country:CC country:CD country:CF country:CG country:CH country:CI country:CK country:CL country:CM country:CN country:CO country:CR country:CU country:CV country:CW country:CX country:CY country:CZ <country:XX>"},
		{"set address-group g1 static", "country:U", "country:UA country:UG country:UM country:US country:UY country:UZ <country:XX>"},
		{"set rule allow-web source [ users-net ]", "a", "application action"},
		{"set rule allow-web log", "", "yes no"},
		{"set route r1 destination", "", "<prefix>"},
		{"delete rule allow-web service", "", "web ["},
		{"set system", "", "hostname mgmt-interface app-identification ips geoip-auto-update ips-disabled-signatures decryption decryption-builtin-exclusions"},
		{"move rule allow-web", "", "top bottom before after"},
		{"move rule allow-web before", "", "block-quarantined block-p2p allow-dns"},
		{"run show", "ro", "routes roles role"},
		{"rename address", "", "users-net dns-quad9"},
	}
	for _, tt := range tests {
		got := words(Filter(ConfigCandidates(m, strings.Fields(tt.line)), tt.partial))
		if got != tt.want {
			t.Errorf("%q + %q: got %q, want %q", tt.line, tt.partial, got, tt.want)
		}
	}
	if got := words(Filter(OperationalCandidates([]string{"show"}), "r")); got != "running ruleset revisions revision routes rib roles role" {
		t.Errorf("operational show r: %q", got)
	}
}

func TestVRFsInConfigureMode(t *testing.T) {
	m := lab(t)
	run(t, m,
		"set vrf blue",
		"set vrf red table 1100",
		"set interface veth-users.20 zone users vrf blue address 10.20.0.1/24",
		"set route blue-net vrf blue destination 10.40.0.0/16 gateway 10.20.0.254",
		"set route leak vrf blue destination 10.50.0.0/16 next-vrf red",
	)
	valid(t, m)
	run(t, m, "rename vrf blue green")
	valid(t, m)
	c, _ := m.Config()
	if c.VRFs[1].Table != 1100 || c.Interfaces[len(c.Interfaces)-1].VRF != "green" || c.Routes[len(c.Routes)-1].VRF != "green" {
		t.Fatalf("after rename: %+v %+v %+v", c.VRFs, c.Interfaces, c.Routes)
	}
	if err := m.Set([]string{"vrf", "x", "table", "lots"}); err == nil {
		t.Fatal("table must be a number")
	}
	if got := words(Filter(ConfigCandidates(m, []string{"set", "route", "r9", "vrf"}), "")); got != "default mgmt green red" {
		t.Fatalf("vrf completion: %q", got)
	}
}

func TestRoutingInConfigureMode(t *testing.T) {
	m := lab(t)
	if err := m.Set([]string{"prefix-list", "from-isp", "entry", "[", "permit 0.0.0.0/0", "deny any", "]"}); err != nil {
		t.Fatal(err)
	}
	run(t, m,
		"set routing default router-id 10.10.1.1 bgp-asn 65010 bgp-network 10.10.0.0/16 bgp-redistribute connected ospf yes",
		"set bgp-neighbor isp address 203.0.113.254 remote-as 64500 import from-isp",
		"set ospf-interface veth-users area 0 cost 10",
	)
	valid(t, m)
	c, _ := m.Config()
	if c.Routing[0].BGPASN != 65010 || !c.Routing[0].OSPF || c.BGPNeighbors[0].RemoteAS != 64500 || c.PrefixLists[0].Entries[1] != "deny any" {
		t.Fatalf("routing: %+v %+v %+v", c.Routing, c.BGPNeighbors, c.PrefixLists)
	}
	if err := m.Set([]string{"routing", "default", "bgp-redistribute", "bgp"}); err == nil {
		t.Fatal("bgp can't redistribute into bgp")
	}
	if got := words(Filter(ConfigCandidates(m, []string{"set", "routing", "default", "bgp-redistribute"}), "")); got != "connected static ospf [" {
		t.Fatalf("redistribute completion: %q", got)
	}
	if got := words(Filter(ConfigCandidates(m, []string{"set", "ospf-interface"}), "")); got != "veth-users mgmt0 veth-inet <name>" {
		t.Fatalf("ospf-interface names: %q", got)
	}
}

func TestDecryptionInConfigureMode(t *testing.T) {
	m := lab(t)
	run(t, m,
		"set service tls protocol tcp ports 443",
		"set decryption-profile strict bad-certificate block unsupported block pinned block allow-quic no",
		"set decryption-exclusion banks domain [ bank.example *.pay.example ]",
		"set decryption-rule users-out from users to internet service tls action decrypt profile strict",
		"set decryption-rule skip-web source dns-quad9 action no-decrypt",
		"move decryption-rule skip-web top",
		"set system decryption on decryption-builtin-exclusions off",
	)
	valid(t, m)
	c, _ := m.Config()
	if len(c.DecryptionRules) != 2 || c.DecryptionRules[0].Name != "skip-web" || c.DecryptionRules[1].Profile != "strict" {
		t.Fatalf("decryption rules: %+v", c.DecryptionRules)
	}
	if p := c.DecryptionProfiles[0]; p.BadCertificate != "block" || p.Pinned != "block" || p.AllowQUIC {
		t.Fatalf("profile: %+v", p)
	}
	if strings.Join(c.DecryptionExclusions[0].Domains, ",") != "bank.example,*.pay.example" || c.System.DecryptionBuiltinExclusions != "off" {
		t.Fatalf("exclusions/system: %+v %+v", c.DecryptionExclusions, c.System)
	}
	if got := words(Filter(ConfigCandidates(m, []string{"set", "decryption-rule", "users-out", "action"}), "")); got != "decrypt no-decrypt" {
		t.Fatalf("action completion: %q", got)
	}
	if got := words(Filter(ConfigCandidates(m, []string{"set", "decryption-rule", "users-out", "profile"}), "")); got != "default strict" {
		t.Fatalf("profile completion: %q", got)
	}
}

func TestSetPublishedNAT(t *testing.T) {
	m := lab(t)
	run(t, m,
		"set address web-srv cidr 10.10.1.80",
		"set address web-pub cidr 198.51.100.80",
		"set nat web-in type port-forward interface veth-inet protocol tcp public-port 443 server web-srv server-port 8443",
		"set nat web-1to1 type static interface veth-inet public-address web-pub server web-srv bidirectional off",
	)
	valid(t, m)
	c, _ := m.Config()
	n := c.NAT[len(c.NAT)-2]
	if n.Type != "port-forward" || n.Interface != "veth-inet" || n.PublicPort != "443" || n.ServerPort != "8443" || n.Server != "web-srv" {
		t.Fatalf("port forward: %+v", n)
	}
	if s := c.NAT[len(c.NAT)-1]; s.PublicAddress != "web-pub" || s.BidirectionalOn() {
		t.Fatalf("static: %+v", s)
	}
}

func TestTrunkInConfigureMode(t *testing.T) {
	m := lab(t)
	run(t, m,
		"set interface veth-users.150 zone users address 10.10.150.1/24",
		"delete interface veth-users address",
		"delete interface veth-users zone",
	)
	valid(t, m)
	c, _ := m.Config()
	if !c.IsTrunk("veth-users") {
		t.Fatalf("veth-users should be a trunk: %+v", c.Interfaces)
	}
}

func TestLogServerInConfigureMode(t *testing.T) {
	m := lab(t)
	run(t, m,
		"set log-server siem address 10.0.0.50",
		"set log-server siem-udp address 192.0.2.10 transport udp format cef port 5140 vrf default type threat type system",
	)
	valid(t, m)
	c, _ := m.Config()
	if len(c.LogServers) != 2 {
		t.Fatalf("log servers: %+v", c.LogServers)
	}
	if u := c.LogServers[1]; u.Transport != "udp" || u.Format != "cef" || u.Port != 5140 || u.VRF != "default" || len(u.Types) != 2 {
		t.Fatalf("udp server: %+v", u)
	}
	run(t, m, "delete log-server siem-udp type threat")
	c, _ = m.Config()
	if got := c.LogServers[1].Types; len(got) != 1 || got[0] != "system" {
		t.Fatalf("types after delete: %v", got)
	}
	if err := m.Set(strings.Fields("set log-server x transport relp")[1:]); err == nil {
		t.Fatal("transport relp accepted")
	}
}

func TestSNMPInConfigureMode(t *testing.T) {
	m := lab(t)
	run(t, m,
		"set snmp enabled on",
		"set snmp location rack-1",
		"set snmp v3-users nms",
		"set snmp v2c-communities lab-ro",
		"set snmp managers 192.168.1.0/24",
		"set snmp-trap-receiver graylog address 192.168.1.62 credential nms inform on",
		"set snmp-trap-receiver old port 1162 address 192.168.1.63 credential lab-ro",
	)
	valid(t, m)
	c, _ := m.Config()
	if !c.SNMP.On() || c.SNMP.Location != "rack-1" || len(c.SNMP.V3Users) != 1 || len(c.SNMP.Managers) != 1 {
		t.Fatalf("snmp: %+v", c.SNMP)
	}
	if len(c.SNMPTrapReceivers) != 2 || c.SNMPTrapReceivers[0].Inform != "on" || c.SNMPTrapReceivers[1].Port != 1162 {
		t.Fatalf("receivers: %+v", c.SNMPTrapReceivers)
	}
	run(t, m, "delete snmp managers 192.168.1.0/24")
	if c, _ := m.Config(); c.Validate() == nil {
		t.Fatal("v2c without managers validated")
	}
	if err := m.Set(strings.Fields("set snmp enabled maybe")[1:]); err == nil {
		t.Fatal("enabled maybe accepted")
	}
}

func TestIPSExceptionInConfigureMode(t *testing.T) {
	m := lab(t)
	run(t, m,
		"set rule allow-web ips-profile default",
		"set address scanner cidr 10.10.1.50",
		"set ips-exception scanner-ok sid 2019876 rule allow-web source scanner",
		"set ips-exception quiet sid 2027758 source users-net action ignore",
	)
	valid(t, m)
	c, _ := m.Config()
	e := c.IPSExceptions[0]
	if e.SID != "2019876" || strings.Join(e.Rules, ",") != "allow-web" || strings.Join(e.Source, ",") != "scanner" || e.ActionOf() != "alert" {
		t.Fatalf("exception: %+v", e)
	}
	if c.IPSExceptions[1].Action != "ignore" {
		t.Fatalf("second: %+v", c.IPSExceptions[1])
	}
	// Renaming the rule renames it in the exception.
	run(t, m, "rename rule allow-web web-out")
	c, _ = m.Config()
	if strings.Join(c.IPSExceptions[0].Rules, ",") != "web-out" {
		t.Fatalf("rule not renamed in the exception: %+v", c.IPSExceptions[0])
	}
	if got := words(Filter(ConfigCandidates(m, []string{"set", "ips-exception", "quiet", "action"}), "")); got != "alert ignore" {
		t.Fatalf("action completion: %q", got)
	}
}
