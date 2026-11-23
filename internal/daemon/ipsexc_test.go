package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stevejboyle/hobby-ngfw/internal/compiler"
	"github.com/stevejboyle/hobby-ngfw/internal/ips"
	"github.com/stevejboyle/hobby-ngfw/internal/logs"
)

func TestIPSExceptions(t *testing.T) {
	dir := t.TempDir()
	d, nf := setupAt(t, dir)
	fs := &fakeSuricata{mem: 8 << 30}
	e := testEngine(t, d)
	d.SetIPS(fs, e)
	var lines []string
	d.ips.emit = func(s string) { lines = append(lines, s) }
	b, err := os.ReadFile("../../examples/ips.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err := d.SetCandidate(b); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Commit("t", "ips exceptions", 0); err != nil {
		t.Fatal(err)
	}
	// The ruleset and the rules file agree on the codes.
	codes := d.ipsCodes
	rules, _ := os.ReadFile(filepath.Join(e.Dir, ips.RulesFile))
	crit := compiler.IPSSeverityMark("critical")
	if !strings.Contains(string(rules), fmt.Sprintf("nfq_set_mark:0x%08x/", crit|compiler.IPSPlainBit)) {
		t.Errorf("test signatures without exceptions carry the plain bit:\n%s", rules)
	}
	if !strings.Contains(nf.Last(), fmt.Sprintf("== 0x%08x ct mark and 0xffff0000 == 0x00010000 ct original ip saddr 10.10.1.50", codes[2019876])) {
		t.Errorf("ruleset lacks scanner-to-web with code %#x:\n%s", codes[2019876], nf.Last())
	}

	fs.mark = 1 << compiler.RuleShift // web-in (strict)
	alert := func(sid int, sev, client, server string) (logs.Threat, bool) {
		n := len(lines)
		d.IPSAlert(ips.Alert{SID: sid, Severity: sev, Proto: "tcp", Src: client, Dst: server, Client: client, Server: server})
		if len(lines) == n {
			return logs.Threat{}, false
		}
		th, _ := logs.ParseThreat(lines[len(lines)-1])
		return th, true
	}
	if th, ok := alert(2019876, "major", "10.10.1.50", "172.16.20.10"); !ok || th.Action != "alert" || th.Exception != "scanner-to-web" {
		t.Errorf("the scanner's match: %+v", th)
	}
	if th, ok := alert(2019876, "major", "10.10.1.51", "172.16.20.10"); !ok || th.Action != "block" || th.Exception != "" {
		t.Errorf("another client is still blocked: %+v", th)
	}
	if th, ok := alert(2019877, "major", "10.10.1.50", "172.16.20.10"); !ok || th.Action != "block" {
		t.Errorf("another signature is still blocked: %+v", th)
	}
	// build-downloads: ignore, any rule (inside-out uses the default profile).
	fs.mark = 2 << compiler.RuleShift
	if th, ok := alert(2027758, "critical", "10.10.1.70", "93.184.216.34"); ok {
		t.Errorf("an ignore exception isn't logged: %+v", th)
	}
	if th, ok := alert(2027758, "critical", "10.10.1.90", "93.184.216.34"); !ok || th.Action != "block" {
		t.Errorf("outside build-hosts: %+v", th)
	}

	// show ips lists the exceptions.
	st := d.IPS()
	if len(st.Exceptions) != 2 || st.Exceptions[0].Name != "scanner-to-web" || st.Exceptions[1].Action != "ignore" {
		t.Fatalf("status exceptions %+v", st.Exceptions)
	}

	// A restart keeps the codes.
	d2, _ := setupAt(t, dir)
	if fmt.Sprint(d2.ipsCodes) != fmt.Sprint(codes) {
		t.Errorf("codes after restart %v, want %v", d2.ipsCodes, codes)
	}
}
