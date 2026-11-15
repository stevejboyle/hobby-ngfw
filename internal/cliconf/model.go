package cliconf

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/stevejboyle/hobby-ngfw/internal/config"
)

// Model is the configuration-mode working copy. Edits may leave it invalid
// for a while (a new rule has no action yet); it is validated when it is
// pushed to the candidate and at commit.
type Model struct {
	root map[string]any
}

// Load starts a working copy from a config.
func Load(cfg *config.Config) (*Model, error) {
	b, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	m := &Model{}
	if err := json.Unmarshal(b, &m.root); err != nil {
		return nil, err
	}
	return m, nil
}

// LoadYAML starts a working copy from config YAML (empty is allowed).
func LoadYAML(data []byte) (*Model, error) {
	cfg := &config.Config{}
	if len(bytes.TrimSpace(data)) > 0 {
		var err error
		if cfg, err = config.Parse(data); err != nil {
			return nil, err
		}
	}
	return Load(cfg)
}

// Config returns the working copy as a config (not validated).
func (m *Model) Config() (*config.Config, error) {
	b, err := json.Marshal(m.root)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var c config.Config
	if err := dec.Decode(&c); err != nil {
		return nil, err
	}
	return &c, nil
}

// YAML renders the working copy as config YAML.
func (m *Model) YAML() ([]byte, error) {
	c, err := m.Config()
	if err != nil {
		return nil, err
	}
	return yaml.Marshal(c)
}

func (m *Model) list(key string) []any {
	l, _ := m.root[key].([]any)
	return l
}

// Names lists the names of objects stored under the JSON keys.
func (m *Model) Names(keys ...string) []string {
	var out []string
	for _, key := range keys {
		for _, it := range m.list(key) {
			if o, ok := it.(map[string]any); ok {
				if n, _ := o["name"].(string); n != "" {
					out = append(out, n)
				}
			}
		}
	}
	return out
}

func (m *Model) find(k *Kind, name string) (map[string]any, int) {
	if k.Singleton {
		o, _ := m.root[k.Key].(map[string]any)
		if o == nil {
			o = map[string]any{}
			m.root[k.Key] = o
		}
		return o, 0
	}
	for i, it := range m.list(k.Key) {
		if o, ok := it.(map[string]any); ok && o["name"] == name {
			return o, i
		}
	}
	return nil, -1
}

// tokens splits brackets off words, so "[a" "b]" and "[ a b ]" both work.
func tokens(words []string) []string {
	var out []string
	for _, w := range words {
		for strings.HasPrefix(w, "[") && w != "[" {
			out = append(out, "[")
			w = w[1:]
		}
		closing := 0
		for strings.HasSuffix(w, "]") && w != "]" {
			closing++
			w = w[:len(w)-1]
		}
		if w != "" {
			out = append(out, w)
		}
		for ; closing > 0; closing-- {
			out = append(out, "]")
		}
	}
	return out
}

// target parses "<kind> [<name>]" and returns the rest.
func target(words []string) (*Kind, string, []string, error) {
	if len(words) == 0 {
		return nil, "", nil, fmt.Errorf("what? one of: %s", strings.Join(kindNames(), ", "))
	}
	k := KindByName(words[0])
	if k == nil {
		return nil, "", nil, fmt.Errorf("unknown object %q; one of: %s", words[0], strings.Join(kindNames(), ", "))
	}
	if k.Singleton {
		return k, "", words[1:], nil
	}
	if len(words) < 2 {
		return nil, "", nil, fmt.Errorf("%s needs a name", k.Name)
	}
	name := words[1]
	if name == "[" || name == "]" || name == config.Any {
		return nil, "", nil, fmt.Errorf("%q is not a valid %s name", name, k.Name)
	}
	return k, name, words[2:], nil
}

func kindNames() []string {
	var out []string
	for _, k := range Kinds {
		out = append(out, k.Name)
	}
	return out
}

// values reads one value, or a bracketed list, from the front of rest.
func values(rest []string) ([]string, []string, error) {
	if len(rest) == 0 {
		return nil, nil, fmt.Errorf("missing value")
	}
	if rest[0] != "[" {
		if rest[0] == "]" {
			return nil, nil, fmt.Errorf("unexpected ]")
		}
		return rest[:1], rest[1:], nil
	}
	for i := 1; i < len(rest); i++ {
		if rest[i] == "]" {
			if i == 1 {
				return nil, nil, fmt.Errorf("empty list")
			}
			return rest[1:i], rest[i+1:], nil
		}
		if rest[i] == "[" {
			return nil, nil, fmt.Errorf("nested [")
		}
	}
	return nil, nil, fmt.Errorf("missing ]")
}

func strList(v any) []string {
	var out []string
	l, _ := v.([]any)
	for _, x := range l {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func anyList(s []string) []any {
	out := make([]any, len(s))
	for i, x := range s {
		out[i] = x
	}
	return out
}

// atomic runs an edit and undoes it if it fails, so a bad value never
// leaves a half-made object behind.
func (m *Model) atomic(edit func() error) error {
	snap, err := json.Marshal(m.root)
	if err != nil {
		return err
	}
	if err := edit(); err != nil {
		var back map[string]any
		json.Unmarshal(snap, &back)
		m.root = back
		return err
	}
	return nil
}

// Set creates an object if needed and sets attributes:
//
//	set rule allow-web from inside to outside service [ web dns ] action allow
//
// Lists gain members (delete removes them); "any" replaces a list.
func (m *Model) Set(words []string) error { return m.atomic(func() error { return m.set(words) }) }

func (m *Model) set(words []string) error {
	k, name, rest, err := target(tokens(words))
	if err != nil {
		return err
	}
	o, _ := m.find(k, name)
	if o == nil {
		o = map[string]any{"name": name}
		m.root[k.Key] = append(m.list(k.Key), o)
	}
	for len(rest) > 0 {
		a := k.attr(rest[0])
		if a == nil {
			return fmt.Errorf("%s has no %q; it has: %s", k.Name, rest[0], strings.Join(attrNames(k), ", "))
		}
		vals, more, err := values(rest[1:])
		if err != nil {
			return fmt.Errorf("%s %s: %w", k.Name, a.Name, err)
		}
		rest = more
		if a.Kind != vList && len(vals) != 1 {
			return fmt.Errorf("%s %s takes one value", k.Name, a.Name)
		}
		switch a.Kind {
		case vStr, vRef:
			o[a.Field] = vals[0]
		case vEnum:
			if !slices.Contains(a.Enum, vals[0]) {
				return fmt.Errorf("%s %s must be one of: %s", k.Name, a.Name, strings.Join(a.Enum, ", "))
			}
			o[a.Field] = vals[0]
		case vInt:
			n, err := strconv.Atoi(vals[0])
			if err != nil {
				return fmt.Errorf("%s %s must be a number", k.Name, a.Name)
			}
			o[a.Field] = n
		case vBool:
			switch vals[0] {
			case "yes", "true":
				o[a.Field] = true
			case "no", "false":
				o[a.Field] = false
			default:
				return fmt.Errorf("%s %s is yes or no", k.Name, a.Name)
			}
		case vList:
			cur := strList(o[a.Field])
			for _, v := range vals {
				if len(a.Enum) > 0 && v != config.Any && !slices.Contains(a.Enum, v) && !slices.Contains(m.Names(a.Refs...), v) {
					if len(a.Enum) > 20 {
						return fmt.Errorf("%s %s: no %q (Tab or ? lists them)", k.Name, a.Name, v)
					}
					return fmt.Errorf("%s %s must be from: %s", k.Name, a.Name, strings.Join(a.Enum, ", "))
				}
				switch {
				case v == config.Any && !a.Any:
					return fmt.Errorf("%s %s does not take any", k.Name, a.Name)
				case v == config.Any:
					cur = []string{config.Any}
				default:
					cur = slices.DeleteFunc(cur, func(s string) bool { return s == config.Any })
					if !slices.Contains(cur, v) {
						cur = append(cur, v)
					}
				}
			}
			o[a.Field] = anyList(cur)
		}
	}
	return nil
}

func attrNames(k *Kind) []string {
	var out []string
	for _, a := range k.Attrs {
		out = append(out, a.Name)
	}
	if len(out) == 0 {
		return []string{"(nothing: just the name)"}
	}
	return out
}

// Delete removes an object, clears an attribute, or removes list members:
//
//	delete rule allow-web
//	delete rule allow-web source            (back to any)
//	delete rule allow-web service [ dns ]
func (m *Model) Delete(words []string) error {
	return m.atomic(func() error { return m.delete(words) })
}

func (m *Model) delete(words []string) error {
	k, name, rest, err := target(tokens(words))
	if err != nil {
		return err
	}
	o, i := m.find(k, name)
	if o == nil {
		return fmt.Errorf("no %s %q", k.Name, name)
	}
	if len(rest) == 0 {
		if k.Singleton {
			return fmt.Errorf("system can't be deleted; delete one of its settings")
		}
		l := m.list(k.Key)
		m.root[k.Key] = append(l[:i:i], l[i+1:]...)
		return nil
	}
	a := k.attr(rest[0])
	if a == nil {
		return fmt.Errorf("%s has no %q; it has: %s", k.Name, rest[0], strings.Join(attrNames(k), ", "))
	}
	if len(rest) == 1 {
		switch a.Kind {
		case vList:
			o[a.Field] = []any{}
		case vBool:
			o[a.Field] = false
		case vInt:
			o[a.Field] = 0
		default:
			o[a.Field] = ""
		}
		return nil
	}
	if a.Kind != vList {
		return fmt.Errorf("%s %s is not a list; use: delete %s %s %s", k.Name, a.Name, k.Name, name, a.Name)
	}
	vals, more, err := values(rest[1:])
	if err != nil {
		return err
	}
	if len(more) > 0 {
		return fmt.Errorf("unexpected %q", more[0])
	}
	cur := strList(o[a.Field])
	for _, v := range vals {
		if !slices.Contains(cur, v) {
			return fmt.Errorf("%s %s has no member %q", k.Name, a.Name, v)
		}
		cur = slices.DeleteFunc(cur, func(s string) bool { return s == v })
	}
	o[a.Field] = anyList(cur)
	return nil
}

// Move reorders rules and NAT rules:
//
//	move rule NAME top|bottom|before OTHER|after OTHER
func (m *Model) Move(words []string) error { return m.atomic(func() error { return m.move(words) }) }

func (m *Model) move(words []string) error {
	k, name, rest, err := target(words)
	if err != nil {
		return err
	}
	if !k.Ordered {
		return fmt.Errorf("only rule and nat can be moved; order doesn't matter for %s", k.Name)
	}
	_, i := m.find(k, name)
	if i < 0 {
		return fmt.Errorf("no %s %q", k.Name, name)
	}
	if len(rest) == 0 {
		return fmt.Errorf("move where? top, bottom, before NAME or after NAME")
	}
	l := slices.Clone(m.list(k.Key))
	item := l[i]
	l = slices.Delete(l, i, i+1)
	switch {
	case rest[0] == "top" && len(rest) == 1:
		l = slices.Insert(l, 0, item)
	case rest[0] == "bottom" && len(rest) == 1:
		l = append(l, item)
	case (rest[0] == "before" || rest[0] == "after") && len(rest) == 2:
		j := -1
		for x, it := range l {
			if o, ok := it.(map[string]any); ok && o["name"] == rest[1] {
				j = x
			}
		}
		if j < 0 {
			return fmt.Errorf("no %s %q", k.Name, rest[1])
		}
		if rest[0] == "after" {
			j++
		}
		l = slices.Insert(l, j, item)
	default:
		return fmt.Errorf("move where? top, bottom, before NAME or after NAME")
	}
	m.root[k.Key] = l
	return nil
}

// Rename renames an object and every reference to it.
func (m *Model) Rename(words []string) error {
	return m.atomic(func() error { return m.rename(words) })
}

func (m *Model) rename(words []string) error {
	k, old, rest, err := target(words)
	if err != nil {
		return err
	}
	if k.Singleton {
		return fmt.Errorf("system has no name")
	}
	if len(rest) != 1 {
		return fmt.Errorf("usage: rename %s OLD NEW", k.Name)
	}
	nw := rest[0]
	o, _ := m.find(k, old)
	if o == nil {
		return fmt.Errorf("no %s %q", k.Name, old)
	}
	if other, _ := m.find(k, nw); other != nil {
		return fmt.Errorf("%s %q already exists", k.Name, nw)
	}
	o["name"] = nw
	for _, rk := range Kinds {
		for _, a := range rk.Attrs {
			if !slices.Contains(a.Refs, k.Key) {
				continue
			}
			var objs []map[string]any
			if rk.Singleton {
				if so, ok := m.root[rk.Key].(map[string]any); ok {
					objs = append(objs, so)
				}
			} else {
				for _, it := range m.list(rk.Key) {
					if ro, ok := it.(map[string]any); ok {
						objs = append(objs, ro)
					}
				}
			}
			for _, ro := range objs {
				switch a.Kind {
				case vRef:
					if ro[a.Field] == old {
						ro[a.Field] = nw
					}
				case vList:
					cur := strList(ro[a.Field])
					for x := range cur {
						if cur[x] == old {
							cur[x] = nw
						}
					}
					if cur != nil {
						ro[a.Field] = anyList(cur)
					}
				}
			}
		}
	}
	return nil
}

// Show renders the working copy, one kind, or one object, as YAML.
func (m *Model) Show(words []string) (string, error) {
	full, err := m.YAML()
	if err != nil {
		return "", err
	}
	if len(words) == 0 {
		return string(full), nil
	}
	k := KindByName(words[0])
	if k == nil {
		return "", fmt.Errorf("unknown object %q; one of: %s", words[0], strings.Join(kindNames(), ", "))
	}
	// Work on yaml.Node so fields keep the config's own order (name first).
	var doc yaml.Node
	if err := yaml.Unmarshal(full, &doc); err != nil {
		return "", err
	}
	top := doc.Content[0]
	var val *yaml.Node
	for i := 0; i+1 < len(top.Content); i += 2 {
		if top.Content[i].Value == k.Key {
			val = top.Content[i+1]
		}
	}
	if val == nil {
		return fmt.Sprintf("# no %s configured\n", k.Name), nil
	}
	if len(words) > 1 && !k.Singleton {
		var hit *yaml.Node
		for _, item := range val.Content {
			for i := 0; i+1 < len(item.Content); i += 2 {
				if item.Content[i].Value == "name" && item.Content[i+1].Value == words[1] {
					hit = item
				}
			}
		}
		if hit == nil {
			return "", fmt.Errorf("no %s %q", k.Name, words[1])
		}
		val = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Content: []*yaml.Node{hit}}
	}
	out, err := yaml.Marshal(&yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", Content: []*yaml.Node{
		{Kind: yaml.ScalarNode, Tag: "!!str", Value: k.Key}, val,
	}})
	return string(out), err
}
