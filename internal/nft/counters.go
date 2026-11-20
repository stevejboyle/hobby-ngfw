package nft

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

// Counter is the packets and bytes counted by the rules with one comment.
type Counter struct {
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

// Counters reads the counters of the rules in table's chains, summed per
// rule comment (e.g. "nat:web"). A chain that doesn't exist is skipped.
func (e Exec) Counters(table string, chains ...string) (map[string]map[string]Counter, error) {
	path := e.Path
	if path == "" {
		path = "nft"
	}
	fam, name, ok := strings.Cut(table, " ")
	if !ok {
		return nil, fmt.Errorf("table %q: want \"family name\"", table)
	}
	out := map[string]map[string]Counter{}
	for _, ch := range chains {
		data, err := exec.Command(path, "-j", "list", "chain", fam, name, ch).Output()
		if err != nil {
			continue // no such chain (nothing of that kind configured)
		}
		got, err := ParseCounters(data)
		if err != nil {
			return nil, err
		}
		out[ch] = got
	}
	return out, nil
}

// ParseCounters sums the counters in `nft -j list` output per rule comment.
func ParseCounters(data []byte) (map[string]Counter, error) {
	var doc struct {
		Nftables []struct {
			Rule *struct {
				Comment string            `json:"comment"`
				Expr    []json.RawMessage `json:"expr"`
			} `json:"rule"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("reading nft counters: %w", err)
	}
	out := map[string]Counter{}
	for _, it := range doc.Nftables {
		if it.Rule == nil || it.Rule.Comment == "" {
			continue
		}
		for _, x := range it.Rule.Expr {
			var e struct {
				Counter *Counter `json:"counter"`
			}
			if json.Unmarshal(x, &e) == nil && e.Counter != nil {
				c := out[it.Rule.Comment]
				c.Packets += e.Counter.Packets
				c.Bytes += e.Counter.Bytes
				out[it.Rule.Comment] = c
			}
		}
	}
	return out, nil
}
