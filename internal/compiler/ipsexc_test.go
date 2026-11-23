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

func excCfg(sids ...string) *config.Config {
	c := &config.Config{}
	for _, s := range sids {
		c.IPSExceptions = append(c.IPSExceptions, config.IPSException{Name: "e" + s, SID: s})
	}
	return c
}

func TestAssignIPSCodesIsStable(t *testing.T) {
	first, none := AssignIPSCodes(nil, nil, excCfg("500", "700"))
	if len(none) != 0 || len(first) != 2 {
		t.Fatalf("first: %v, without code %v", first, none)
	}
	// A lower SID arrives, with first's rules file still live: the others
	// keep their codes, and the newcomer gets a code nobody had.
	second, _ := AssignIPSCodes(first, []map[int]uint32{first}, excCfg("100", "500", "700"))
	if second[500] != first[500] || second[700] != first[700] {
		t.Fatalf("codes moved: %v -> %v", first, second)
	}
	if second[100] == first[500] || second[100] == first[700] || second[100] == 0 {
		t.Fatalf("new SID took a used code: %v", second)
	}
}

// ChatGPT's review: remove 9900001's exception and commit, then add
// 9900002's before Suricata has loaded the rules file without 9900001.
// Both files are live, so 9900002 must not take 9900001's code.
func TestAssignIPSCodesAcrossSuccessiveCommits(t *testing.T) {
	a, _ := AssignIPSCodes(nil, nil, excCfg("9900001"))
	live := []map[int]uint32{a}
	none1, _ := AssignIPSCodes(a, live, excCfg()) // exception removed
	live = append(live, none1)                    // its file written, not yet loaded
	b, without := AssignIPSCodes(none1, live, excCfg("9900002"))
	if len(without) != 0 || b[9900002] == 0 {
		t.Fatalf("9900002 got no code: %v %v", b, without)
	}
	if b[9900002] == a[9900001] {
		t.Fatalf("9900002 took code %#x, which Suricata may still give 9900001", b[9900002])
	}
	// Once Suricata confirms the newer file, 9900001's file is released
	// and its code may be given again.
	c, _ := AssignIPSCodes(nil, []map[int]uint32{b}, excCfg("9900002", "9900003"))
	if c[9900002] != b[9900002] {
		t.Fatalf("9900002 moved: %v", c)
	}
	if c[9900003] != a[9900001] {
		t.Fatalf("after release, the first free code is reusable: got %#x, want %#x", c[9900003], a[9900001])
	}
	// A signature may keep a code only it ever had, from an older file.
	d, _ := AssignIPSCodes(nil, []map[int]uint32{a, none1}, excCfg("9900001"))
	if d[9900001] != a[9900001] {
		t.Fatalf("9900001 came back with another code: %v", d)
	}
}

// ChatGPT's review: all 35 codes in use, then every signature replaced
// while the old file is live. Nothing may be reused: the new exceptions
// get no code (inactive) until the old file is released.
func TestAssignIPSCodesExhausted(t *testing.T) {
	var old, repl []string
	for i := 0; i < config.MaxIPSExceptionSIDs; i++ {
		old = append(old, fmt.Sprint(1000+i))
		repl = append(repl, fmt.Sprint(5000+i))
	}
	full, none := AssignIPSCodes(nil, nil, excCfg(old...))
	if len(full) != config.MaxIPSExceptionSIDs || len(none) != 0 {
		t.Fatalf("%d codes, %d without", len(full), len(none))
	}
	live := []map[int]uint32{full}
	got, without := AssignIPSCodes(full, live, excCfg(repl...))
	if len(got) != 0 || len(without) != config.MaxIPSExceptionSIDs {
		t.Fatalf("codes reused while the old file is live: %v (without %d)", got, len(without))
	}
	// Half replaced: the kept half keep their codes, the new half wait.
	mixed := append(append([]string{}, old[:17]...), repl[:18]...)
	got, without = AssignIPSCodes(full, live, excCfg(mixed...))
	if len(got) != 17 || len(without) != 18 {
		t.Fatalf("mixed: %d codes, %d without", len(got), len(without))
	}
	for _, sid := range old[:17] {
		n := 0
		fmt.Sscan(sid, &n)
		if got[n] != full[n] {
			t.Fatalf("%d moved", n)
		}
	}
	// After release every new signature gets a code, all distinct.
	got, without = AssignIPSCodes(nil, nil, excCfg(repl...))
	seen := map[uint32]bool{}
	for _, c := range got {
		if seen[c] {
			t.Fatal("a code given twice")
		}
		seen[c] = true
	}
	if len(got) != config.MaxIPSExceptionSIDs || len(without) != 0 {
		t.Fatalf("after release: %d codes, %d without", len(got), len(without))
	}
}

// A code two live files give different signatures is never handed out.
func TestAssignIPSCodesNeverMixesMeanings(t *testing.T) {
	a, _ := AssignIPSCodes(nil, nil, excCfg("1", "2"))
	b, _ := AssignIPSCodes(nil, []map[int]uint32{a}, excCfg("3"))
	live := []map[int]uint32{a, b}
	for _, sids := range [][]string{{"1"}, {"3"}, {"4"}, {"1", "3", "4"}, {"2", "4", "5"}} {
		got, _ := AssignIPSCodes(nil, live, excCfg(sids...))
		for sid, c := range got {
			for _, m := range live {
				for o, oc := range m {
					if oc == c && o != sid {
						t.Fatalf("%v: %d got %#x, which a live file gives %d", sids, sid, c, o)
					}
				}
			}
		}
	}
}
