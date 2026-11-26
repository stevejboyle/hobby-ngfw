package nft

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseCounters(t *testing.T) {
	data := []byte(`{"nftables": [{"metainfo": {"version": "1.0.9"}},
 {"chain": {"family": "inet", "table": "ngfw", "name": "prerouting_nat"}},
 {"rule": {"chain": "prerouting_nat", "comment": "nat:web", "expr": [{"match": {}}, {"counter": {"packets": 3, "bytes": 180}}, {"dnat": {}}]}},
 {"rule": {"chain": "prerouting_nat", "comment": "nat:web", "expr": [{"counter": {"packets": 2, "bytes": 120}}]}},
 {"rule": {"chain": "prerouting_nat", "expr": [{"counter": {"packets": 9, "bytes": 9}}]}}]}`)
	got, err := ParseCounters(data)
	if err != nil {
		t.Fatal(err)
	}
	if c := got["nat:web"]; c.Packets != 5 || c.Bytes != 300 || len(got) != 1 {
		t.Errorf("got %+v", got)
	}
}

// fakeNFT writes a script standing in for nft: per chain (the last
// argument) it prints canned output, fails, or hangs.
func fakeNFT(t *testing.T, body string) Exec {
	t.Helper()
	path := filepath.Join(t.TempDir(), "nft")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nchain=\"$6\"\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	return Exec{Path: path}
}

func TestCountersAbsentZeroAndFailures(t *testing.T) {
	ok := `{"nftables": [{"rule": {"comment": "rule:web", "expr": [{"counter": {"packets": 0, "bytes": 0}}]}}]}`
	e := fakeNFT(t, `case "$chain" in
forward) echo '`+ok+`' ;;
missing) echo "Error: No such file or directory; did you mean chain 'x' in table inet 'ngfw'?" >&2; exit 1 ;;
broken) echo "Error: Operation not permitted" >&2; exit 1 ;;
garbled) echo "not json" ;;
esac
`)
	// Present with a zero counter: a real zero, no error.
	got, err := e.Counters("inet ngfw", "forward", "missing")
	if err != nil {
		t.Fatalf("absent chain reported as an error: %v", err)
	}
	if c, ok := got["forward"]["rule:web"]; !ok || c != (Counter{}) {
		t.Errorf("zero counter: %+v", got)
	}
	if _, ok := got["missing"]; ok {
		t.Error("absent chain in the result")
	}
	// Execution and parse failures are errors, and say which chain;
	// what was read still comes back.
	got, err = e.Counters("inet ngfw", "forward", "broken", "garbled")
	if !errors.Is(err, ErrCounters) || !strings.Contains(err.Error(), "chain broken") || !strings.Contains(err.Error(), "Operation not permitted") || !strings.Contains(err.Error(), "chain garbled") {
		t.Errorf("failures: %v", err)
	}
	if _, ok := got["forward"]; !ok {
		t.Error("the readable chain was lost with the failures")
	}
	// A missing binary is a failure, not an absent chain.
	if _, err := (Exec{Path: filepath.Join(t.TempDir(), "no-nft")}).Counters("inet ngfw", "forward"); !errors.Is(err, ErrCounters) {
		t.Errorf("missing nft: %v", err)
	}
}

func TestCountersTimeout(t *testing.T) {
	old := CounterTimeout
	CounterTimeout = 200 * time.Millisecond
	defer func() { CounterTimeout = old }()
	e := fakeNFT(t, "exec sleep 30\n")
	start := time.Now()
	_, err := e.Counters("inet ngfw", "forward")
	if !errors.Is(err, ErrCounters) || !strings.Contains(err.Error(), "timed out") {
		t.Errorf("hung nft: %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Errorf("a hung nft held the read for %v", time.Since(start))
	}
}
