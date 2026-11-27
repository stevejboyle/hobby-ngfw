package logs

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

// Log queries: conditions on named fields, joined with and/or/not and
// grouped with parentheses, e.g.
//
//	zone = inside and dst = 4.2.2.2
//	app ~ tube or (dport = 443 and bytes > 1000000)
//	not action = allow
//
// Operators: = (also eq), != (ne), ~ (contains), !~, > < >= <= (gt lt ge le).
// Addresses compare as an IP or a CIDR (dst = 10.0.0.0/8); numbers also
// accept a range (dport = 1000-2000); text compares without case. A word
// that isn't part of a condition matches anywhere in the entry, so plain
// searches ("allow-web") work as before. Adjacent conditions mean "and".

// ErrQuery marks a query that doesn't parse.
var ErrQuery = errors.New("log query")

type kind int

const (
	kText kind = iota
	kAddr
	kNum
)

// field is one queryable field: its kind and the columns it reads (more
// than one for aliases such as zone = from or to).
type field struct {
	kind kind
	cols []string
	help string
}

// Schema maps field names to fields; a log type has one.
type Schema map[string]field

// TrafficSchema is the traffic log's query fields: its columns plus aliases.
var TrafficSchema = withGeo(Schema{
	"rule":      {kText, []string{"rule"}, "rule name"},
	"action":    {kText, []string{"action"}, "allow, deny, reset"},
	"type":      {kText, []string{"type"}, "start or end"},
	"from":      {kText, []string{"from"}, "source zone"},
	"to":        {kText, []string{"to"}, "destination zone"},
	"zone":      {kText, []string{"from", "to"}, "either zone"},
	"in":        {kText, []string{"in"}, "ingress interface"},
	"out":       {kText, []string{"out"}, "egress interface"},
	"interface": {kText, []string{"in", "out"}, "either interface"},
	"src":       {kAddr, []string{"src"}, "source address or CIDR"},
	"dst":       {kAddr, []string{"dst"}, "destination address or CIDR"},
	"addr":      {kAddr, []string{"src", "dst"}, "either address"},
	"sport":     {kNum, []string{"sport"}, "source port"},
	"dport":     {kNum, []string{"dport"}, "destination port"},
	"port":      {kNum, []string{"sport", "dport"}, "either port"},
	"proto":     {kText, []string{"proto"}, "tcp, udp, icmp, ..."},
	"app":       {kText, []string{"app"}, "application (end entries)"},
	"category":  {kText, []string{"category"}, "application category"},
	"bytes":     {kNum, []string{"bytes"}, "bytes, both directions"},
	"packets":   {kNum, []string{"packets"}, "packets, both directions"},
	"duration":  {kNum, []string{"duration"}, "seconds"},
	"len":       {kNum, []string{"len"}, "IP packet length"},
	"ttl":       {kNum, []string{"ttl"}, "IP time to live"},
	"flags":     {kText, []string{"flags"}, "TCP flags, e.g. flags ~ SYN"},
	"icmp":      {kText, []string{"icmp"}, "ICMP type/code, e.g. 8/0"},
})

// SystemSchema is the system log's query fields.
var SystemSchema = Schema{
	"source":  {kText, []string{"source"}, "ngfwd, sshd, upgrade, dhcp, ..."},
	"level":   {kText, []string{"level"}, "info, warn, error"},
	"message": {kText, []string{"message"}, "the message"},
	"fields":  {kText, []string{"fields"}, "key=value details"},
}

// Fields lists the schema's field names, sorted, with their help.
func (s Schema) Fields() []Column {
	var out []Column
	for name, f := range s {
		out = append(out, Column{Name: name, Help: f.help})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Getter returns a column's value ("" when the entry has none).
type Getter func(col string) string

// Query is a parsed log query.
type Query struct {
	root node
	src  string
}

// String returns the query as written.
func (q *Query) String() string {
	if q == nil {
		return ""
	}
	return q.src
}

// Match reports whether an entry (its columns via get, and every value via
// all for bare words) satisfies the query. A nil query matches everything.
func (q *Query) Match(get Getter, all []string) bool {
	if q == nil || q.root == nil {
		return true
	}
	return q.root.match(get, all)
}

type node interface {
	match(get Getter, all []string) bool
}

type andNode struct{ a, b node }
type orNode struct{ a, b node }
type notNode struct{ n node }
type wordNode struct{ w string }
type condNode struct {
	f       field
	op      string
	text    string       // lower-cased, for text
	prefix  netip.Prefix // for addresses
	lo, hi  float64      // for numbers (= with a range)
	isRange bool
}

func (n andNode) match(g Getter, all []string) bool { return n.a.match(g, all) && n.b.match(g, all) }
func (n orNode) match(g Getter, all []string) bool  { return n.a.match(g, all) || n.b.match(g, all) }
func (n notNode) match(g Getter, all []string) bool { return !n.n.match(g, all) }
func (n wordNode) match(_ Getter, all []string) bool {
	for _, v := range all {
		if strings.Contains(strings.ToLower(v), n.w) {
			return true
		}
	}
	return false
}

// match: positive operators hold if any of the field's columns satisfies
// them; negative ones (!=, !~) only if none matches the positive form, so
// "zone != inside" means neither zone is inside.
func (n condNode) match(g Getter, _ []string) bool {
	switch n.op {
	case "!=":
		m := n
		m.op = "="
		return !m.match(g, nil)
	case "!~":
		m := n
		m.op = "~"
		return !m.match(g, nil)
	}
	for _, c := range n.f.cols {
		if n.one(g(c)) {
			return true
		}
	}
	return false
}

func (n condNode) one(v string) bool {
	switch n.f.kind {
	case kAddr:
		if n.op == "~" {
			return v != "" && strings.Contains(v, n.text)
		}
		a, err := netip.ParseAddr(v)
		return err == nil && n.prefix.Contains(a)
	case kNum:
		if n.op == "~" {
			return v != "" && strings.Contains(v, n.text)
		}
		x, err := strconv.ParseFloat(strings.TrimSuffix(v, "s"), 64)
		if err != nil {
			return false
		}
		switch n.op {
		case "=":
			if n.isRange {
				return x >= n.lo && x <= n.hi
			}
			return x == n.lo
		case ">":
			return x > n.lo
		case "<":
			return x < n.lo
		case ">=":
			return x >= n.lo
		case "<=":
			return x <= n.lo
		}
	default:
		v = strings.ToLower(v)
		switch n.op {
		case "=":
			return v == n.text
		case "~":
			return strings.Contains(v, n.text)
		case ">", "<", ">=", "<=":
			return false
		}
	}
	return false
}

// ---- parsing ---------------------------------------------------------------

type token struct {
	s      string
	quoted bool
}

var opWords = map[string]string{"eq": "=", "==": "=", "ne": "!=", "neq": "!=", "contains": "~", "gt": ">", "lt": "<", "ge": ">=", "le": "<="}

func isOp(t token) (string, bool) {
	if t.quoted {
		return "", false
	}
	switch t.s {
	case "=", "!=", "~", "!~", ">", "<", ">=", "<=":
		return t.s, true
	}
	if op, ok := opWords[strings.ToLower(t.s)]; ok {
		return op, true
	}
	return "", false
}

func tokenize(s string) ([]token, error) {
	var out []token
	r := []rune(s)
	for i := 0; i < len(r); {
		c := r[i]
		switch {
		case unicode.IsSpace(c):
			i++
		case c == '(' || c == ')':
			out = append(out, token{s: string(c)})
			i++
		case c == '"' || c == '\'':
			j := i + 1
			for j < len(r) && r[j] != c {
				j++
			}
			if j == len(r) {
				return nil, fmt.Errorf("%w: unterminated quote", ErrQuery)
			}
			out = append(out, token{s: string(r[i+1 : j]), quoted: true})
			i = j + 1
		case strings.ContainsRune("=!~<>", c):
			j := i + 1
			if j < len(r) && (r[j] == '=' || (c == '!' && r[j] == '~')) {
				j++
			}
			out = append(out, token{s: string(r[i:j])})
			i = j
		default:
			j := i
			for j < len(r) && !unicode.IsSpace(r[j]) && !strings.ContainsRune("()=!~<>\"'", r[j]) {
				j++
			}
			out = append(out, token{s: string(r[i:j])})
			i = j
		}
	}
	return out, nil
}

type parser struct {
	toks   []token
	pos    int
	schema Schema
}

func (p *parser) peek() (token, bool) {
	if p.pos < len(p.toks) {
		return p.toks[p.pos], true
	}
	return token{}, false
}

func (p *parser) keyword(t token, w string) bool { return !t.quoted && strings.EqualFold(t.s, w) }

// ParseQuery parses a log query against a schema. An empty query is nil.
func ParseQuery(s string, schema Schema) (*Query, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	toks, err := tokenize(s)
	if err != nil {
		return nil, err
	}
	p := &parser{toks: toks, schema: schema}
	n, err := p.or()
	if err != nil {
		return nil, err
	}
	if t, ok := p.peek(); ok {
		return nil, fmt.Errorf("%w: unexpected %q", ErrQuery, t.s)
	}
	return &Query{root: n, src: s}, nil
}

func (p *parser) or() (node, error) {
	n, err := p.and()
	if err != nil {
		return nil, err
	}
	for {
		t, ok := p.peek()
		if !ok || !p.keyword(t, "or") {
			return n, nil
		}
		p.pos++
		m, err := p.and()
		if err != nil {
			return nil, err
		}
		n = orNode{n, m}
	}
}

func (p *parser) and() (node, error) {
	n, err := p.unary()
	if err != nil {
		return nil, err
	}
	for {
		t, ok := p.peek()
		if !ok || t.s == ")" && !t.quoted || p.keyword(t, "or") {
			return n, nil
		}
		if p.keyword(t, "and") {
			p.pos++
		}
		m, err := p.unary()
		if err != nil {
			return nil, err
		}
		n = andNode{n, m}
	}
}

func (p *parser) unary() (node, error) {
	t, ok := p.peek()
	if !ok {
		return nil, fmt.Errorf("%w: the query ends too early", ErrQuery)
	}
	switch {
	case p.keyword(t, "not"):
		p.pos++
		n, err := p.unary()
		if err != nil {
			return nil, err
		}
		return notNode{n}, nil
	case t.s == "(" && !t.quoted:
		p.pos++
		n, err := p.or()
		if err != nil {
			return nil, err
		}
		if c, ok := p.peek(); !ok || c.s != ")" || c.quoted {
			return nil, fmt.Errorf("%w: missing )", ErrQuery)
		}
		p.pos++
		return n, nil
	case t.s == ")" && !t.quoted:
		return nil, fmt.Errorf("%w: unexpected )", ErrQuery)
	}
	if _, isop := isOp(t); isop {
		return nil, fmt.Errorf("%w: %q needs a field before it, e.g. dst %s 4.2.2.2", ErrQuery, t.s, t.s)
	}
	p.pos++
	// FIELD OP VALUE, or a bare word.
	if p.pos+1 < len(p.toks) {
		if op, isop := isOp(p.toks[p.pos]); isop {
			name := strings.ToLower(t.s)
			f, known := p.schema[name]
			if !known {
				return nil, fmt.Errorf("%w: unknown field %q; fields: %s", ErrQuery, t.s, p.names())
			}
			val := p.toks[p.pos+1]
			p.pos += 2
			return cond(name, f, op, val.s)
		}
	}
	if c, ok := p.peek(); ok {
		if _, isop := isOp(c); isop {
			return nil, fmt.Errorf("%w: %s %s needs a value", ErrQuery, t.s, c.s)
		}
	}
	return wordNode{strings.ToLower(t.s)}, nil
}

func (p *parser) names() string {
	var n []string
	for _, c := range p.schema.Fields() {
		n = append(n, c.Name)
	}
	return strings.Join(n, ", ")
}

func cond(name string, f field, op, val string) (node, error) {
	n := condNode{f: f, op: op, text: strings.ToLower(val)}
	switch f.kind {
	case kAddr:
		if op == "~" || op == "!~" {
			return n, nil
		}
		if op != "=" && op != "!=" {
			return nil, fmt.Errorf("%w: %s takes =, != or ~ (an address or CIDR)", ErrQuery, name)
		}
		if pfx, err := netip.ParsePrefix(val); err == nil {
			n.prefix = pfx.Masked()
		} else if a, err := netip.ParseAddr(val); err == nil {
			n.prefix = netip.PrefixFrom(a, a.BitLen())
		} else {
			return nil, fmt.Errorf("%w: %s %s: %q is not an address or CIDR", ErrQuery, name, op, val)
		}
	case kNum:
		if op == "~" || op == "!~" {
			return n, nil
		}
		if lo, hi, ok := strings.Cut(val, "-"); ok && (op == "=" || op == "!=") {
			a, err1 := strconv.ParseFloat(lo, 64)
			b, err2 := strconv.ParseFloat(hi, 64)
			if err1 != nil || err2 != nil || b < a {
				return nil, fmt.Errorf("%w: %s %s: %q is not a range like 1000-2000", ErrQuery, name, op, val)
			}
			n.lo, n.hi, n.isRange = a, b, true
			return n, nil
		}
		x, err := strconv.ParseFloat(val, 64)
		if err != nil {
			return nil, fmt.Errorf("%w: %s %s: %q is not a number", ErrQuery, name, op, val)
		}
		n.lo = x
	default:
		if op != "=" && op != "!=" && op != "~" && op != "!~" {
			return nil, fmt.Errorf("%w: %s is text: use =, != or ~ (contains)", ErrQuery, name)
		}
	}
	return n, nil
}
