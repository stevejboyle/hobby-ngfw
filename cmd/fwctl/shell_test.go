package main

import (
	"strings"
	"testing"

	"github.com/stevejboyle/hobby-ngfw/internal/cliconf"
)

func TestSplitWords(t *testing.T) {
	tests := map[string][]string{
		`show status`:                            {"show", "status"},
		`  commit   -m "two words" -confirm 5m `: {"commit", "-m", "two words", "-confirm", "5m"},
		`commit -m ""`:                           {"commit", "-m", ""},
		``:                                       nil,
	}
	for in, want := range tests {
		got, err := splitWords(in)
		if err != nil || strings.Join(got, "|") != strings.Join(want, "|") || len(got) != len(want) {
			t.Errorf("splitWords(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := splitWords(`commit -m "open`); err == nil {
		t.Error("unterminated quote should fail")
	}
}

// Commands that would leave the CLI or run arbitrary programs are refused
// before anything is executed.
func TestShellRefuses(t *testing.T) {
	for _, line := range []string{
		"bash", "sh -c id", "sudo -i", "upgrade apply /tmp/x", "web-passwd", "validate /etc/shadow",
		"compile /etc/shadow", "show running extra", "show /etc/shadow", "load /etc/passwd",
		"ping", "ping ;id", "ping $(id)", "ping -f 10.0.0.1", "ping 10.0.0.1 1000", "ping 10.0.0.1 x",
		"passwd root", "show revision ../1", "show revision 0",
	} {
		err := runShellLine(line, strings.NewReader(""))
		if err == nil {
			t.Errorf("%q: expected an error", line)
		}
	}
}

func TestPasswdMismatch(t *testing.T) {
	err := runShellLine("passwd", strings.NewReader("old password\nnew password 1\nnew password 2\n"))
	if err == nil || !strings.Contains(err.Error(), "do not match") {
		t.Fatalf("got %v", err)
	}
	if err := runShellLine("passwd", strings.NewReader("only one line\n")); err == nil {
		t.Fatal("short input should fail")
	}
}

func TestSessionCompletion(t *testing.T) {
	s := &session{}
	partial, c := s.complete("sh")
	if partial != "sh" || len(c) != 1 || c[0].Word != "show" {
		t.Fatalf("operational: %q %+v", partial, c)
	}
	_, c = s.complete("show rev")
	if len(c) != 2 {
		t.Fatalf("show rev: %+v", c)
	}
	if _, c := s.complete(`commit -m "half `); c != nil {
		t.Fatal("no completion inside quotes")
	}
}

func TestConfigModeOffline(t *testing.T) {
	// Without ngfwd, edits apply to the working copy; saving reports the
	// unreachable daemon as an error rather than losing the edit.
	m, err := cliconf.LoadYAML([]byte("system:\n  hostname: fw1\n"))
	if err != nil {
		t.Fatal(err)
	}
	socket = "/nonexistent/ngfwd.sock"
	s := &session{cfg: m}
	if err := s.runConfig("set zone dmz"); err != nil {
		t.Fatal(err) // save failure is a note, not an error
	}
	if names := m.Names("zones"); len(names) != 1 || names[0] != "dmz" {
		t.Fatalf("working copy: %v", names)
	}
	if err := s.runConfig("commit"); err == nil || !strings.Contains(err.Error(), "isn't valid yet") {
		t.Fatalf("commit with an unsaved working copy: %v", err)
	}
	if err := s.runConfig("exit"); err == nil {
		t.Fatal("first exit should warn")
	}
	if err := s.runConfig("exit"); err != nil || s.cfg != nil {
		t.Fatalf("second exit should leave: %v", err)
	}
	_, c := (&session{cfg: m}).complete("set z")
	if len(c) != 1 || c[0].Word != "zone" {
		t.Fatalf("config completion: %+v", c)
	}
}

func TestRoleHelp(t *testing.T) {
	reader := &me{Name: "reader", Role: "read-only", ConfigView: true,
		Permissions: map[string]string{"policy": "view", "monitoring": "view", "tags": "view", "revisions": "view"}}
	h := roleHelp(reader, shellHelp)
	for _, want := range []string{"show running", "show log traffic", "show tags", "passwd", "show whoami", "ssh-key add"} {
		if !strings.Contains(h, want) {
			t.Errorf("read-only help lacks %q", want)
		}
	}
	for _, not := range []string{"\n  commit [", "\n  configure ", "tags register", "request user add", "show users", "show api-keys",
		"request ips update", "rollback N", "add a user (asks"} {
		if strings.Contains(h, not) {
			t.Errorf("read-only help shows %q", not)
		}
	}
	su := &me{Superuser: true}
	if roleHelp(su, shellHelp) != shellHelp {
		t.Error("a superuser should see the whole help")
	}
	if !allowedCommand(reader, "show app catalog video") || allowedCommand(reader, "show api-keys") || !allowedCommand(nil, "commit") {
		t.Error("allowedCommand")
	}
}
