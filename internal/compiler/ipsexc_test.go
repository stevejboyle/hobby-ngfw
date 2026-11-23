package compiler

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stevejboyle/sjb-os/internal/config"
)

func TestIPSExceptionCodes(t *testing.T) {
	if len(ipsCodes) != config.MaxIPSExceptionSIDs {
		t.Fatalf("%d codes, config allows %d", len(ipsCodes), config.MaxIPSExceptionSIDs)
	}
	codes := map[uint32]bool{}
	for _, c := range ipsCodes {
		if c&^IPSExcMask != 0 {
			t.Fatalf("code %#x outside bits 17-23", c)
		}
		codes[c] = true
	}
	// Two signatures with exceptions on one packet: the OR is never a code,
	// so neither exception applies (fail closed).
	for _, a := range ipsCodes {
		for _, b := range ipsCodes {
			if a != b && codes[a|b] {
				t.Fatalf("%#x | %#x = %#x is a code", a, b, a|b)
			}
		}
	}
	// The bits are free: no VRF mark, severity or decryption bit.
	if ipsClearMask&(IPSMarkMask|IPSExcMask|IPSPlainBit) != ipsClearMask || IPSExcMask&(vrfMarkBase|IPSMarkMask|DecryptMark) != 0 || IPSPlainBit&(IPSMarkMask|DecryptMark) != 0 {
		t.Fatal("exception bits overlap other packet mark uses")
	}
}

func ipsExcCfg() *config.Config {
	c := base()
	c.Rules = []config.Rule{
		{Name: "in", From: []string{"b"}, To: []string{"a"}, Action: "allow", IPSProfile: "default"},
		{Name: "out", From: []string{"a"}, To: []string{"b"}, Action: "allow", IPSProfile: "default"},
		{Name: "plain", From: []string{"a"}, Action: "allow"},
	}
	return c
}

func TestIPSExceptionLines(t *testing.T) {
	c := ipsExcCfg()
	c.System.IPSDisabledSignatures = []string{"300"}
	c.IPSExceptions = []config.IPSException{
		{Name: "two-rules", SID: "200", Rules: []string{"in", "out"}},
		{Name: "tagged", SID: "100", Source: []string{"bad", "h1"}},
		{Name: "off-too", SID: "300", Source: []string{"h1"}},
	}
	res := compile(t, c)
	codes := IPSExceptionCodes(c)
	for _, want := range []string{
		// SIDs in numeric order get the codes: 100, 200, 300.
		fmt.Sprintf("meta mark and 0x80fe0000 == 0x%08x ct mark and 0xffff0000 { 0x00010000, 0x00020000 } meta mark set", codes[200]),
		// An address list with a tag group: one line per term.
		fmt.Sprintf("meta mark and 0x80fe0000 == 0x%08x ct original ip saddr 10.0.0.1 meta mark set", codes[100]),
		fmt.Sprintf("meta mark and 0x80fe0000 == 0x%08x ct original ip saddr @dag_bad_actors meta mark set", codes[100]),
	} {
		if !strings.Contains(res.Ruleset, want) {
			t.Errorf("missing %q in:\n%s", want, res.Ruleset)
		}
	}
	if codes[100] != ipsCodes[0] || codes[200] != ipsCodes[1] {
		t.Errorf("codes %v", codes)
	}
	if !strings.Contains(strings.Join(res.Warnings, "\n"), `ips exception "off-too": signature 300 is disabled system-wide`) {
		t.Errorf("warnings %v", res.Warnings)
	}
	// Exception lines come before the profiles act.
	if strings.Index(res.Ruleset, "ips-exception:two-rules") > strings.Index(res.Ruleset, "vmap { 0x00010000 : jump") {
		t.Error("exceptions must come before the profile jump")
	}
}

func TestIPSExceptionIPSOff(t *testing.T) {
	c := ipsExcCfg()
	c.System.IPS = "off"
	c.IPSExceptions = []config.IPSException{{Name: "e", SID: "1", Rules: []string{"in"}}}
	if res := compile(t, c); strings.Contains(res.Ruleset, "ips-exception") {
		t.Error("IPS off: no exception lines")
	}
}

func TestAssignIPSCodesIsStable(t *testing.T) {
	cfg := func(sids ...string) *config.Config {
		c := &config.Config{}
		for _, s := range sids {
			c.IPSExceptions = append(c.IPSExceptions, config.IPSException{Name: "e" + s, SID: s})
		}
		return c
	}
	first := AssignIPSCodes(nil, cfg("500", "700"))
	// A lower SID arrives: the others keep their codes, and the newcomer
	// gets a code nobody had.
	second := AssignIPSCodes(first, cfg("100", "500", "700"))
	if second[500] != first[500] || second[700] != first[700] {
		t.Fatalf("codes moved: %v -> %v", first, second)
	}
	if second[100] == first[500] || second[100] == first[700] || second[100] == 0 {
		t.Fatalf("new SID took a used code: %v", second)
	}
	// 500 goes away and 900 arrives at once: 900 doesn't inherit 500's code
	// (Suricata may still mark 500's matches with it for a while).
	third := AssignIPSCodes(second, cfg("100", "700", "900"))
	if third[900] == second[500] {
		t.Fatalf("900 took 500's code while others were free: %v", third)
	}
	// Full: codes are reused rather than refused.
	var many []string
	for i := 0; i < config.MaxIPSExceptionSIDs; i++ {
		many = append(many, fmt.Sprint(1000+i))
	}
	full := AssignIPSCodes(third, cfg(many...))
	seen := map[uint32]bool{}
	for _, c := range full {
		if seen[c] {
			t.Fatal("a code given twice")
		}
		seen[c] = true
	}
	if len(full) != config.MaxIPSExceptionSIDs {
		t.Fatalf("%d codes for %d SIDs", len(full), config.MaxIPSExceptionSIDs)
	}
}
