package cliconf

import (
	"slices"
	"sort"
	"strings"

	"github.com/stevejboyle/hobby-ngfw/internal/logs"
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
	{"request", "request ips update: download the latest IPS signatures"},
	{"ping", "ping a host through the forwarding table"},
	{"passwd", "change your password (SSH, console, web UI)"},
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
	{"statistics", "traffic, applications, hosts and threats over 1h, 24h or 7d"},
	{"api-keys", "tag API keys"},
	{"log", "traffic (data plane), threat (IPS) or system (management) log"},
}

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
		return []Candidate{{"traffic", "data plane: connections matching rules with logging on"}, {"threat", "IPS: signature matches, blocked or alerted"}, {"system", "management: commits, logins, tags, upgrades"}}
	case words[0] == "show" && len(words) >= 4 && words[1] == "log" && (words[2] == "traffic" || words[2] == "threat") && words[len(words)-1] == "columns":
		out := []Candidate{{"<col,col,...>", "comma-separated, in this order"}}
		cols := logs.TrafficColumns
		if words[2] == "threat" {
			cols = logs.ThreatColumns
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
	case words[0] == "show" && len(words) == 2 && words[1] == "statistics":
		return []Candidate{{"1h", "the last hour (default)"}, {"24h", "the last day"}, {"7d", "the last week"}}
	case words[0] == "request" && len(words) == 1:
		return []Candidate{{"ips", "the IPS"}}
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
