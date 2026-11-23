package daemon

import (
	"github.com/stevejboyle/sjb-os/internal/compiler"
	"github.com/stevejboyle/sjb-os/internal/config"
	"github.com/stevejboyle/sjb-os/internal/nft"
)

// NATEntry is one running NAT entry with its live counters, for show nat
// and the NAT page.
type NATEntry struct {
	config.NATRule
	// PublicIP and ServerIP resolve the address objects ("" for the
	// interface's own address).
	PublicIP string `json:"public_ip"`
	ServerIP string `json:"server_ip"`
	// Hits counts new connections translated: inbound for published
	// servers, outbound for masquerade. OutHits counts a bidirectional
	// static entry's outbound ones. nil when counters can't be read.
	Hits    *uint64 `json:"hits"`
	OutHits *uint64 `json:"out_hits,omitempty"`
	// HairpinHits counts connections from SJB-OS's other interfaces to the
	// public address (hairpin on only).
	HairpinHits *uint64 `json:"hairpin_hits,omitempty"`
	// AddressApplied: the public address is on the interface (published
	// entries with a public address only).
	AddressApplied *bool  `json:"address_applied,omitempty"`
	AddressError   string `json:"address_error,omitempty"`
}

type counterReader interface {
	Counters(table string, chains ...string) (map[string]map[string]nft.Counter, error)
}

// NAT reports the running config's NAT entries, in order, with their
// counters and whether their public addresses are in place.
func (d *Daemon) NAT() []NATEntry {
	d.mu.Lock()
	cfg := d.running
	states := d.natIPStates
	reader, _ := d.nft.(counterReader)
	d.mu.Unlock()
	out := []NATEntry{}
	if cfg == nil {
		return out
	}
	var counters map[string]map[string]nft.Counter
	if reader != nil {
		counters, _ = reader.Counters(compiler.Table, "prerouting_nat", "postrouting")
	}
	hits := func(chain, name string) *uint64 {
		if counters == nil {
			return nil
		}
		n := counters[chain]["nat:"+name].Packets
		return &n
	}
	for _, n := range cfg.NAT {
		e := NATEntry{NATRule: n}
		if ip, ok := cfg.HostAddress(n.Server); ok {
			e.ServerIP = ip.String()
		}
		if ip, ok := cfg.HostAddress(n.PublicAddress); ok {
			e.PublicIP = ip.String()
			for _, s := range states {
				if s.Dev == n.Interface && s.IP == ip {
					ok := s.Applied
					e.AddressApplied, e.AddressError = &ok, s.Error
				}
			}
		}
		switch {
		case n.Type == config.NATMasquerade:
			e.Hits = hits("postrouting", n.Name)
		case n.Published():
			e.Hits = hits("prerouting_nat", n.Name)
			if n.BidirectionalOn() {
				e.OutHits = hits("postrouting", n.Name)
			}
			if n.HairpinOn() {
				e.HairpinHits = hits("prerouting_nat", n.Name+" hairpin")
			}
		}
		out = append(out, e)
	}
	return out
}
