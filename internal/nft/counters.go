package nft

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// Counter is the packets and bytes counted by the rules with one comment.
type Counter struct {
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

// CounterTimeout bounds one `nft -j list chain` (monitoring must never hang
// on a stuck nft).
var CounterTimeout = 5 * time.Second

// ErrCounters wraps a failure to read counters: nft failed, timed out or
// printed something unreadable. A chain that doesn't exist is not one (the
// config simply has nothing of that kind): it is left out of the result.
var ErrCounters = errors.New("nft counters unavailable")

// Counters reads the counters of the rules in table's chains, summed per
// rule comment (e.g. "nat:web"). A chain that doesn't exist is skipped. On
// any other failure the chains read so far are returned with an error
// wrapping ErrCounters, so callers can tell "no such counters" (absent),
// "zero" (present, nothing counted) and "unknown" (an error) apart.
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
	var errs []error
	for _, ch := range chains {
		ctx, cancel := context.WithTimeout(context.Background(), CounterTimeout)
		cmd := exec.CommandContext(ctx, path, "-j", "list", "chain", fam, name, ch)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		data, err := cmd.Output()
		timedOut := ctx.Err() != nil
		cancel()
		switch {
		case timedOut:
			errs = append(errs, fmt.Errorf("%w: chain %s: nft timed out after %v", ErrCounters, ch, CounterTimeout))
			continue
		case err != nil && chainAbsent(stderr.String()):
			continue // nothing of that kind configured
		case err != nil:
			errs = append(errs, fmt.Errorf("%w: chain %s: %v: %s", ErrCounters, ch, err, strings.TrimSpace(firstLine(stderr.String()))))
			continue
		}
		got, err := ParseCounters(data)
		if err != nil {
			errs = append(errs, fmt.Errorf("%w: chain %s: %v", ErrCounters, ch, err))
			continue
		}
		out[ch] = got
	}
	return out, errors.Join(errs...)
}

// chainAbsent reports whether nft's error says the chain (or its table)
// doesn't exist.
func chainAbsent(stderr string) bool {
	return strings.Contains(stderr, "No such file or directory") || strings.Contains(stderr, "does not exist")
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(s, "\n")
	return s
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
