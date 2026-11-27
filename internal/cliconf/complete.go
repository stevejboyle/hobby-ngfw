package cliconf

import (
	"slices"
	"sort"
	"strings"

	"github.com/stevejboyle/sjb-os/internal/accounts"
	"github.com/stevejboyle/sjb-os/internal/config"
	"github.com/stevejboyle/sjb-os/internal/geoip"
	"github.com/stevejboyle/sjb-os/internal/logs"
)

// Candidate is one possible next word. Words starting with "<" are hints
// ("<cidr>"): shown by "?" but never inserted by Tab.
type Candidate struct {
	Word string
	Help string
}

// IsHint reports whether c only describes what to type.
func (c Candidate) IsHint() bool { return strings.HasPrefix(c.Word, "<") }

type cands []Candidate

func (c *cands) add(word, help string) { *c = append(*c, Candidate{word, help}) }

// Filter keeps candidates that start with partial (hints are kept, so "?"
// can still explain what goes here), sorted with hints last.
func Filter(all []Candidate, partial string) []Candidate {
	var out []Candidate
	for _, c := range all {
		// The 250 countries are offered once two characters are typed
		// ("co"), so they don't flood every address list.
		if strings.HasPrefix(c.Word, config.CountryPrefix) && len(partial) < 2 {
			continue
		}
		if c.IsHint() || strings.HasPrefix(c.Word, partial) {
			out = append(out, c)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return !out[i].IsHint() && out[j].IsHint() })
	return out
}

var operational = []Candidate{
	{"show", "show status, config, history, tags, routes..."},
	{"configure", "enter configuration mode (set, delete, move, rename)"},
	{"load", "paste a whole config (YAML)"},
	{"revert", "discard uncommitted changes"},
	{"commit", "apply the candidate config"},
	{"confirm", "accept a commit waiting for confirmation"},
	{"rollback", "commit an earlier revision again"},
	{"tags", "register or unregister tagged hosts"},
	{"request", "request ips update, request decryption ca generate..."},
	{"ping", "ping a host through the forwarding table"},
	{"passwd", "change your password (SSH, console, web UI)"},
	{"ssh-key", "add or delete your own SSH keys"},
	{"sjb", "a word from the border guard"},
	{"help", "list commands"},
	{"exit", "log out"},
}

var showWhat = []Candidate{
	{"status", "running revision and pending confirmation"},
	{"version", "SJB-OS version and upgrade history"},
	{"running", "the running config"},
	{"candidate", "the candidate config"},
	{"diff", "running vs candidate"},
	{"ruleset", "nftables ruleset the candidate compiles to"},
	{"revisions", "commit history"},
	{"revision", "the config of one revision"},
	{"tags", "tag registrations"},
	{"interfaces", "interface addresses"},
	{"arp", "ARP table (IPv4 neighbours)"},
	{"routes", "static routes and routing tables"},
	{"vrf", "VRFs, their tables and interfaces"},
	{"bgp", "BGP neighbors: state, uptime, prefixes"},
	{"ospf", "OSPF neighbors"},
	{"rib", "the routing table as FRR sees it, with protocols"},
	{"app", "applications seen so far (show app catalog: all it knows)"},
	{"dhcp", "DHCP servers, or their leases (show dhcp leases)"},
	{"ips", "IPS engine, signatures and inspected rules"},
	{"decryption", "TLS decryption: state, CA (show decryption ca), learned servers"},
	{"statistics", "traffic, applications, hosts and threats over 1h, 24h or 7d"},
	{"management-certificate", "the web UI and tag API certificate"},
	{"api-keys", "API keys for the tag API and Prometheus (superusers)"},
	{"metrics", "the Prometheus metrics (what a scrape of /metrics gets)"},
	{"snmp", "the SNMP agent: state, polling, trap receivers"},
	{"log", "traffic (data plane), threat (IPS) or system (management) log"},
	{"whoami", "your user name, role and what it allows"},
	{"ssh-keys", "your SSH keys"},
	{"users", "SJB-OS users (superusers)"},
	{"user", "one user (superusers)"},
	{"roles", "roles and who has them (superusers)"},
	{"role", "one role's permissions (superusers)"},
}

func areaCandidates() []Candidate {
	var out []Candidate
	for _, a := range accounts.Areas {
		out = append(out, Candidate{string(a.Area), a.Covers})
	}
	return out
}

var roleNames = []Candidate{{"superuser", "everything"}, {"admin", "config, commits, tags; not users or upgrades"}, {"read-only", "see, don't change"}, {"<role>", "a custom role (show roles)"}}

var commitFlags = []Candidate{
	{"-m", "commit message (quote it)"},
	{"-confirm", "roll back unless confirmed in time, e.g. 5m"},
}

// OperationalCandidates lists what may follow words in operational mode.
func OperationalCandidates(words []string) []Candidate {
	switch {
	case len(words) == 0:
		return operational
	case words[0] == "show" && len(words) == 1:
		return showWhat
	case words[0] == "show" && len(words) == 2 && words[1] == "rib":
		return []Candidate{{"vrf", "one VRF's routes"}}
	case words[0] == "show" && len(words) == 3 && words[1] == "rib" && words[2] == "vrf":
		return []Candidate{{"default", ""}, {"<name>", "a VRF you defined"}}
	case words[0] == "show" && len(words) == 2 && words[1] == "routes":
		return []Candidate{{"vrf", "one VRF's routing table"}}
	case words[0] == "show" && len(words) == 3 && words[1] == "routes" && words[2] == "vrf":
		return []Candidate{{"default", ""}, {"mgmt", ""}, {"<name>", "a VRF you defined"}}
	case words[0] == "show" && len(words) == 2 && words[1] == "log":
		return []Candidate{{"traffic", "data plane: connections matching rules with logging on"}, {"threat", "IPS: signature matches, blocked or alerted"}, {"decryption", "TLS decryption: what happened to each connection"}, {"system", "management: commits, logins, tags, upgrades"}}
	case words[0] == "show" && len(words) >= 4 && words[1] == "log" && (words[2] == "traffic" || words[2] == "threat" || words[2] == "decryption") && words[len(words)-1] == "columns":
		out := []Candidate{{"<col,col,...>", "comma-separated, in this order"}}
		cols := logs.TrafficColumns
		switch words[2] {
		case "threat":
			cols = logs.ThreatColumns
		case "decryption":
			cols = logs.DecryptionColumns
		}
		for _, c := range cols {
			out = append(out, Candidate{c.Name, c.Help})
		}
		return out
	case words[0] == "show" && len(words) >= 3 && words[1] == "log" && slices.Contains(words[3:], "where"):
		schema := logs.TrafficSchema
		switch words[2] {
		case "system":
			schema = logs.SystemSchema
		case "threat":
			schema = logs.ThreatSchema
		case "decryption":
			schema = logs.DecryptionSchema
		}
		out := []Candidate{{"<field op value>", "e.g. zone = inside; join with and, or, not, ( )"}, {"and", ""}, {"or", ""}, {"not", ""}}
		for _, f := range schema.Fields() {
			out = append(out, Candidate{f.Name, f.Help})
		}
		return out
	case words[0] == "show" && len(words) >= 3 && words[1] == "log" && words[2] == "traffic":
		return []Candidate{{"<N>", "how many entries (default 50)"}, {"<text>", "only entries containing this"}, {"columns", "choose the columns: columns src,sport,dst,dport,app"}, {"where", "filter: where zone = inside and dst = 4.2.2.2"}}
	case words[0] == "show" && len(words) >= 3 && words[1] == "log" && words[2] == "threat":
		return []Candidate{{"<N>", "how many entries (default 50)"}, {"<text>", "only entries containing this"}, {"columns", "choose the columns: columns rule,severity,signature,src"}, {"where", "filter: where severity = critical and action = block"}}
	case words[0] == "show" && len(words) >= 3 && words[1] == "log" && words[2] == "decryption":
		return []Candidate{{"<N>", "how many entries (default 50)"}, {"<text>", "only entries containing this"}, {"columns", "choose the columns: columns decision,server_name,src"}, {"where", "filter: where decision = learned and src = 10.10.1.50"}}
	case words[0] == "show" && len(words) == 2 && words[1] == "decryption":
		return []Candidate{{"ca", "the CA's certificate, to install on clients"}, {"learned", "servers passed through because clients rejected the firewall's certificate"}}
	case words[0] == "show" && len(words) == 2 && words[1] == "statistics":
		return []Candidate{{"1h", "the last hour (default)"}, {"24h", "the last day"}, {"7d", "the last week"}}
	case words[0] == "request" && len(words) == 1:
		return []Candidate{{"ips", "the IPS"}, {"decryption", "TLS decryption"}, {"management-certificate", "the web UI and tag API certificate"}, {"user", "add, change or delete users (superusers)"}, {"role", "add, change or delete custom roles (superusers)"}, {"snmp", "SNMP credentials (superusers)"}, {"api-key", "add or delete API keys (superusers)"}, {"system", "reboot the appliance"}}
	case words[0] == "request" && len(words) == 2 && words[1] == "system":
		return []Candidate{{"reboot", "restart the appliance (traffic stops for about a minute)"}}
	case words[0] == "request" && len(words) == 2 && words[1] == "snmp":
		return []Candidate{{"credential", "v3 users and v2c communities"}}
	case words[0] == "request" && len(words) == 3 && words[1] == "snmp" && words[2] == "credential":
		return []Candidate{{"add", "add NAME v3|v2c ... (asks for the secrets)"}, {"change", "change NAME v3|v2c ...: new secrets"}, {"delete", "delete NAME"}}
	case words[0] == "request" && len(words) == 4 && words[1] == "snmp":
		return []Candidate{{"<name>", "credential name"}}
	case words[0] == "request" && len(words) == 5 && words[1] == "snmp" && (words[3] == "add" || words[3] == "change"):
		return []Candidate{{"v3", "an SNMPv3 user: authenticated and encrypted"}, {"v2c", "a v2c community (clear text; managers only)"}}
	case words[0] == "request" && len(words) >= 6 && words[1] == "snmp" && words[5] == "v3" && len(words)%2 == 0:
		return []Candidate{{"auth", "sha256 (default) or sha512"}, {"priv", "aes (default) or aes256"}}
	case words[0] == "request" && len(words) >= 7 && words[1] == "snmp" && words[len(words)-1] == "auth":
		return []Candidate{{"sha256", ""}, {"sha512", ""}}
	case words[0] == "request" && len(words) >= 7 && words[1] == "snmp" && words[len(words)-1] == "priv":
		return []Candidate{{"aes", ""}, {"aes256", ""}}
	case words[0] == "request" && len(words) == 2 && words[1] == "api-key":
		return []Candidate{{"add", "add NAME scopes metrics:read|tags:read|tags:write"}, {"delete", "delete NAME"}}
	case words[0] == "request" && len(words) == 4 && words[1] == "api-key" && words[2] == "add":
		return []Candidate{{"scopes", "what the key may do"}}
	case words[0] == "request" && len(words) == 5 && words[1] == "api-key" && words[4] == "scopes":
		return []Candidate{{"metrics:read", "Prometheus: GET /metrics"}, {"tags:read", "read tag registrations"}, {"tags:write", "register and unregister tags"}}
	case words[0] == "request" && len(words) == 2 && words[1] == "user":
		return []Candidate{{"add", "add NAME role ROLE (asks for the password)"}, {"set", "set NAME role ROLE | disabled yes|no"}, {"password", "password NAME: set someone's password"},
			{"unlock", "unlock NAME after failed logins"}, {"delete", "delete NAME"}, {"ssh-key", "ssh-key add|delete NAME ..."}}
	case words[0] == "request" && len(words) == 3 && words[1] == "user" && words[2] == "ssh-key":
		return []Candidate{{"add", "add NAME, then paste the key"}, {"delete", "delete NAME N|FINGERPRINT"}}
	case words[0] == "request" && len(words) == 3 && words[1] == "user":
		return []Candidate{{"<name>", "user name (show users)"}}
	case words[0] == "request" && len(words) == 4 && words[1] == "user" && (words[2] == "add" || words[2] == "set"):
		if words[2] == "add" {
			return []Candidate{{"role", "the user's role"}}
		}
		return []Candidate{{"role", "give them another role"}, {"disabled", "yes: no logins; no: allowed again"}}
	case words[0] == "request" && len(words) == 5 && words[1] == "user" && words[4] == "role":
		return roleNames
	case words[0] == "request" && len(words) == 5 && words[1] == "user" && words[4] == "disabled":
		return []Candidate{{"yes", "lock the account and end its sessions"}, {"no", "allow logins again"}}
	case words[0] == "request" && len(words) == 2 && words[1] == "role":
		return []Candidate{{"add", "add NAME [description \"TEXT\"]"}, {"set", "set NAME AREA view|change|none, or NAME description \"TEXT\""}, {"delete", "delete NAME (nobody may have it)"}}
	case words[0] == "request" && len(words) == 3 && words[1] == "role":
		return []Candidate{{"<name>", "custom role name"}}
	case words[0] == "request" && len(words) == 4 && words[1] == "role" && words[2] == "set":
		return append(areaCandidates(), Candidate{"description", "what the role is for"})
	case words[0] == "request" && len(words) == 5 && words[1] == "role" && words[2] == "set" && words[4] != "description":
		return []Candidate{{"view", "see it"}, {"change", "see and change it"}, {"none", "neither"}}
	case words[0] == "ssh-key" && len(words) == 1:
		return []Candidate{{"add", "paste a public key (ssh-ed25519 AAAA... comment)"}, {"delete", "delete N or FINGERPRINT (show ssh-keys)"}}
	case words[0] == "show" && len(words) == 2 && (words[1] == "user" || words[1] == "role"):
		return []Candidate{{"<name>", ""}}
	case words[0] == "request" && len(words) == 2 && words[1] == "decryption":
		return []Candidate{{"ca", "the decryption CA"}, {"learned", "the learned (pinned) servers"}}
	case words[0] == "request" && len(words) == 3 && words[1] == "decryption" && words[2] == "ca":
		return []Candidate{{"generate", "make a new CA (replaces the current one)"}, {"import", "paste your own CA certificate and key"}}
	case words[0] == "request" && len(words) == 3 && words[1] == "decryption" && words[2] == "learned":
		return []Candidate{{"clear", "decrypt them again"}}
	case words[0] == "request" && len(words) == 2 && words[1] == "management-certificate":
		return []Candidate{{"import", "paste your certificate, its intermediates and key"}, {"self-signed", "back to a new self-signed certificate"}}
	case words[0] == "show" && len(words) == 2 && words[1] == "management-certificate":
		return []Candidate{{"pem", "also print the certificate and chain (PEM)"}}
	case words[0] == "request" && len(words) == 2 && words[1] == "ips":
		return []Candidate{{"update", "download the latest signatures now"}}
	case words[0] == "show" && len(words) >= 3 && words[1] == "log":
		return []Candidate{{"<N>", "how many entries (default 50)"}, {"<text>", "only entries containing this"}, {"where", "filter: where source = sshd and message ~ failed"}}
	case words[0] == "show" && len(words) == 2 && words[1] == "arp":
		return []Candidate{{"mgmt", ""}, {"inside", ""}, {"outside", ""}, {"<interface>", "e.g. inside.20"}}
	case words[0] == "show" && len(words) == 2 && words[1] == "app":
		return []Candidate{{"catalog", "identifiable applications"}, {"categories", "application categories (category:video in rules)"}}
	case words[0] == "show" && len(words) == 3 && words[1] == "app" && words[2] == "catalog":
		return []Candidate{{"<text>", "only names or categories containing this, e.g. video"}}
	case words[0] == "show" && len(words) == 2 && words[1] == "dhcp":
		return []Candidate{{"leases", "addresses handed out"}}
	case words[0] == "show" && len(words) == 3 && words[1] == "dhcp" && words[2] == "leases":
		return []Candidate{{"<interface>", "only this interface's leases"}}
	case words[0] == "show" && len(words) == 2 && words[1] == "revision":
		return []Candidate{{"<N>", "revision number (see show revisions)"}}
	case words[0] == "tags" && len(words) == 1:
		return []Candidate{{"register", "add an IP to tags"}, {"unregister", "remove an IP from tags"}}
	case words[0] == "tags" && len(words) == 2:
		return []Candidate{{"<ip>", "IPv4 address"}}
	case words[0] == "tags" && len(words) >= 3:
		return []Candidate{{"<tag>", "tag name"}, {"-ttl", "expiry, e.g. 1h (register only)"}}
	case words[0] == "commit":
		return commitFlags
	case words[0] == "rollback" && len(words) == 1:
		return []Candidate{{"<N>", "revision number (see show revisions)"}}
	case words[0] == "ping" && len(words) == 1:
		return []Candidate{{"<host>", "IP address or host name"}}
	case words[0] == "ping" && len(words) == 2:
		return []Candidate{{"<count>", "number of pings (default 4)"}}
	}
	return nil
}

var configCmds = []Candidate{
	{"set", "create an object or set its attributes"},
	{"delete", "delete an object, an attribute, or list members"},
	{"show", "show the working config (all, a type, or one object)"},
	{"move", "reorder rules and NAT rules"},
	{"rename", "rename an object and every reference to it"},
	{"commit", "save the working config and apply it"},
	{"revert", "throw away changes since the last commit"},
	{"run", "run an operational command, e.g. run show routes"},
	{"exit", "leave configuration mode"},
	{"help", "list configuration commands"},
}

// ConfigCandidates lists what may follow words in configuration mode.
func ConfigCandidates(m *Model, words []string) []Candidate {
	words = tokens(words)
	if len(words) == 0 {
		return configCmds
	}
	cmd, rest := words[0], words[1:]
	switch cmd {
	case "set", "delete", "show":
		return objectCandidates(m, cmd, rest)
	case "move":
		return moveCandidates(m, rest)
	case "rename":
		var c cands
		switch len(rest) {
		case 0:
			for _, k := range Kinds {
				if !k.Singleton {
					c.add(k.Name, k.Help)
				}
			}
		case 1:
			if k := KindByName(rest[0]); k != nil {
				for _, n := range m.Names(k.Key) {
					c.add(n, "")
				}
			}
		case 2:
			c.add("<new-name>", "the new name; references follow")
		}
		return c
	case "commit":
		return commitFlags
	case "run":
		return OperationalCandidates(rest)
	}
	return nil
}

func objectCandidates(m *Model, cmd string, rest []string) []Candidate {
	var c cands
	if len(rest) == 0 {
		for _, k := range Kinds {
			c.add(k.Name, k.Help)
		}
		return c
	}
	k := KindByName(rest[0])
	if k == nil {
		return nil
	}
	rest = rest[1:]
	var obj map[string]any
	if !k.Singleton {
		if len(rest) == 0 {
			existing := m.Names(k.Key)
			for _, n := range existing {
				c.add(n, "existing "+k.Name)
			}
			if cmd == "set" {
				for _, n := range append(slices.Clone(k.NameFixed), m.Names(k.NameRefs...)...) {
					if !slices.Contains(existing, n) {
						c.add(n, "")
					}
				}
			}
			if cmd == "set" {
				c.add("<name>", "a new "+k.Name)
			}
			return c
		}
		obj, _ = m.find(k, rest[0])
		rest = rest[1:]
	} else {
		obj, _ = m.find(k, "")
	}
	if cmd == "show" {
		return nil
	}

	// Walk attribute/value pairs to see what comes next.
	var cur *Attr
	inList := false
	var listed []string
	for _, w := range rest {
		switch {
		case cur == nil:
			cur = k.attr(w)
			if cur == nil {
				return nil
			}
			listed = nil
		case w == "[" && cur.Kind == vList && !inList:
			inList = true
		case w == "]" && inList:
			inList, cur = false, nil
		case inList:
			listed = append(listed, w)
		default:
			cur = nil // a single value ends the pair
		}
	}
	if cur == nil {
		for _, a := range k.Attrs {
			c.add(a.Name, a.Help)
		}
		return c
	}
	return valueCandidates(m, cmd, cur, obj, inList, listed)
}

func valueCandidates(m *Model, cmd string, a *Attr, obj map[string]any, inList bool, listed []string) []Candidate {
	var c cands
	if cmd == "delete" {
		if a.Kind == vList && obj != nil {
			for _, v := range strList(obj[a.Field]) {
				if !slices.Contains(listed, v) {
					c.add(v, "current member")
				}
			}
			if !inList {
				c.add("[", "remove several members")
			} else {
				c.add("]", "end of list")
			}
		}
		return c
	}
	switch a.Kind {
	case vEnum:
		for _, e := range a.Enum {
			c.add(e, "")
		}
	case vBool:
		c.add("yes", "")
		c.add("no", "")
	case vStr:
		c.add(a.Hint, a.Help)
	case vInt:
		c.add(a.Hint, a.Help)
	case vRef, vList:
		for _, n := range a.Enum {
			if !slices.Contains(listed, n) {
				c.add(n, "")
			}
		}
		for _, n := range a.Fixed {
			c.add(n, "built in")
		}
		for _, n := range m.Names(a.Refs...) {
			if !slices.Contains(listed, n) {
				c.add(n, "")
			}
		}
		if a.Countries {
			codes := make([]string, 0, len(geoip.Names))
			for cc := range geoip.Names {
				codes = append(codes, cc)
			}
			slices.Sort(codes)
			for _, cc := range codes {
				if ref := config.CountryPrefix + cc; !slices.Contains(listed, ref) {
					c.add(ref, geoip.Names[cc])
				}
			}
			c.add("<country:XX>", "a country by its two-letter code (type co and Tab to list them)")
		}
		if a.Any && !inList {
			c.add("any", "match everything")
		}
		if a.Hint != "" {
			c.add(a.Hint, a.Help)
		}
		if a.Kind == vList {
			if inList {
				c.add("]", "end of list")
			} else {
				c.add("[", "several values: [ a b c ]")
			}
		}
	}
	return c
}

func moveCandidates(m *Model, rest []string) []Candidate {
	var c cands
	switch len(rest) {
	case 0:
		for _, k := range Kinds {
			if k.Ordered {
				c.add(k.Name, k.Help)
			}
		}
	case 1:
		if k := KindByName(rest[0]); k != nil && k.Ordered {
			for _, n := range m.Names(k.Key) {
				c.add(n, "")
			}
		}
	case 2:
		c.add("top", "first")
		c.add("bottom", "last")
		c.add("before", "before another")
		c.add("after", "after another")
	case 3:
		if rest[2] == "before" || rest[2] == "after" {
			if k := KindByName(rest[0]); k != nil {
				for _, n := range m.Names(k.Key) {
					if n != rest[1] {
						c.add(n, "")
					}
				}
			}
		}
	}
	return c
}
