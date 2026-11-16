package decrypt

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMatcher(t *testing.T) {
	m := NewMatcher(map[string][]string{
		"banks":  {"bank.example", "*.pay.example", " Upper.Example "},
		"health": {"clinic.example", "bank.example"},
	})
	for name, want := range map[string]string{
		"bank.example": "banks", "www.bank.example": "banks", "a.b.bank.example": "banks",
		"pay.example": "", "x.pay.example": "banks", "upper.example": "banks", "WWW.CLINIC.EXAMPLE.": "health",
		"notbank.example": "", "example": "", "": "", "bank.example.evil": "",
	} {
		if got := m.Match(name); got != want {
			t.Errorf("Match(%q) = %q, want %q", name, got, want)
		}
	}
	var none *Matcher
	if none.Match("x.example") != "" {
		t.Error("nil matcher excludes nothing")
	}
}

func TestReadList(t *testing.T) {
	got := ReadList(strings.NewReader("# banks\nBank.Example\n\n  *.pay.example  # cards\n"))
	if strings.Join(got, ",") != "bank.example,*.pay.example" {
		t.Fatalf("ReadList: %q", got)
	}
}

func TestPolicyRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	p := Policy{Mode: ModeDecrypt, Builtin: true, Rules: []PolicyRule{{Name: "r", Profile: "default", BadCertificate: "warn"}},
		Exclusions: []Exclusion{{Name: "e", Domains: []string{"a.example"}}}}
	if err := WritePolicy(path, p); err != nil {
		t.Fatal(err)
	}
	got, err := ReadPolicy(path)
	if err != nil || got.Mode != ModeDecrypt || !got.Builtin || got.Rules[0].BadCertificate != "warn" || got.Exclusions[0].Domains[0] != "a.example" {
		t.Fatalf("policy: %+v %v", got, err)
	}
}

func TestLearned(t *testing.T) {
	path := filepath.Join(t.TempDir(), "learned.json")
	t0 := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	l := OpenLearned(path, time.Hour)
	l.Add("app.example", "203.0.113.5", t0)
	l.Add("old.example", "203.0.113.6", t0.Add(-50*time.Minute))
	if !l.Has("app.example", "203.0.113.5", t0) || l.Has("app.example", "203.0.113.9", t0) {
		t.Fatal("learned by name and address")
	}
	if l.Has("old.example", "203.0.113.6", t0.Add(11*time.Minute)) {
		t.Fatal("entries expire")
	}
	reopened := OpenLearned(path, time.Hour)
	if es := reopened.List(t0); len(es) != 2 || es[0].ServerName != "old.example" {
		t.Fatalf("persisted list: %+v", es)
	}
	if n := reopened.Clear(t0); n != 2 || len(OpenLearned(path, time.Hour).List(t0)) != 0 {
		t.Fatalf("clear: %d", n)
	}
}

// The shipped list parses, holds only valid names, and covers what the
// guide says it does.
func TestBuiltinList(t *testing.T) {
	f, err := os.Open("../../deploy/appliance/rootfs" + BuiltinExclusionsFile)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	list := ReadList(f)
	if len(list) < 50 {
		t.Fatalf("only %d names", len(list))
	}
	for _, d := range list {
		if !validServerName(strings.TrimPrefix(d, "*.")) {
			t.Errorf("invalid name %q", d)
		}
	}
	m := NewMatcher(map[string][]string{"builtin": list})
	for _, n := range []string{"www.irs.gov", "login.chase.com", "www.paypal.com", "mychart.example.mychart.com", "www.nhs.uk"} {
		if m.Match(n) == "" {
			t.Errorf("%s should be excluded", n)
		}
	}
	if m.Match("www.example.com") != "" {
		t.Error("example.com isn't a bank")
	}
}
