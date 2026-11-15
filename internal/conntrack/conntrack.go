// Package conntrack clears connection-tracking entries so existing flows
// are re-evaluated against current policy. Without this, a host that gets
// quarantined keeps every session it already had, because the ruleset
// accepts established traffic before any rule runs.
//
// After a flush, the kernel picks up mid-stream TCP again as a new flow
// (nf_conntrack_tcp_loose, on by default), so flows policy still allows
// carry on; flows it now denies stop.
package conntrack

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
	"sync"
)

// Flusher clears conntrack entries.
type Flusher interface {
	// FlushAll clears every entry.
	FlushAll() error
	// FlushIP clears entries where ip is the source or destination.
	FlushIP(ip netip.Addr) error
}

// Exec uses the conntrack binary from conntrack-tools.
type Exec struct{ Path string }

func (e Exec) run(args ...string) error {
	path := e.Path
	if path == "" {
		path = "conntrack"
	}
	cmd := exec.Command(path, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	var exit *exec.ExitError
	// conntrack -D exits 1 when nothing matched; that is success for us.
	if errors.As(err, &exit) && exit.ExitCode() == 1 && strings.Contains(stderr.String(), "0 flow entries") {
		return nil
	}
	if err != nil {
		return fmt.Errorf("conntrack %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// FlushAll implements Flusher.
func (e Exec) FlushAll() error { return e.run("-F") }

// FlushIP implements Flusher.
func (e Exec) FlushIP(ip netip.Addr) error {
	if err := e.run("-D", "-s", ip.String()); err != nil {
		return err
	}
	return e.run("-D", "-d", ip.String())
}

// Fake records calls. For tests.
type Fake struct {
	mu      sync.Mutex
	All     int
	Flushed []netip.Addr
}

// FlushAll implements Flusher.
func (f *Fake) FlushAll() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.All++
	return nil
}

// Count reports how many times FlushAll ran.
func (f *Fake) Count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.All
}

// FlushIP implements Flusher.
func (f *Fake) FlushIP(ip netip.Addr) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Flushed = append(f.Flushed, ip)
	return nil
}
