package lineedit

import (
	"bufio"
	"bytes"
	"io"
	"strings"
	"testing"
)

// completer offers "show", "set", "status" and a hint, like the CLI.
func completer(head string) (string, []Candidate) {
	i := strings.LastIndex(head, " ")
	partial := head[i+1:]
	if i < 0 {
		return partial, []Candidate{{"show", "show things"}, {"set", "set things"}, {"status", ""}}
	}
	if strings.HasPrefix(head, "set address a1 cidr ") {
		return partial, []Candidate{{"<cidr>", "an address"}}
	}
	return partial, []Candidate{{"routes", ""}, {"running", ""}, {"revisions", ""}}
}

func read(t *testing.T, input string) (string, string, error) {
	t.Helper()
	var out bytes.Buffer
	e := New(bufio.NewReader(strings.NewReader(input)), &out, completer)
	line, err := e.ReadLine("> ")
	return line, out.String(), err
}

func TestTyping(t *testing.T) {
	tests := []struct{ in, want string }{
		{"show status\r", "show status"},
		{"shw\x7f\x7fhow\r", "show"},                    // backspace
		{"how\x01s\r", "show"},                          // Ctrl-A then insert
		{"show status\x17\x17x\r", "x"},                 // Ctrl-W twice
		{"abc\x1b[D\x1b[DX\r", "aXbc"},                  // left arrows
		{"show me\x1b[H\x1b[3~S\r", "Show me"},          // Home, Delete
		{"wrong\x15right\r", "right"},                   // Ctrl-U
		{"ab\x02\x0b\r", "a"},                           // Ctrl-B, Ctrl-K
		{"sh\t\r", "show "},                             // unique completion
		{"show ro\t\r", "show routes "},                 // unique completion of a later word
		{"show r\t\r", "show r"},                        // ambiguous, no longer prefix: lists
		{"show ru\t\r", "show running "},                // unique
		{`commit -m "why?"` + "\r", `commit -m "why?"`}, // ? inside quotes is text
	}
	for _, tt := range tests {
		got, _, err := read(t, tt.in)
		if err != nil || got != tt.want {
			t.Errorf("%q: got %q, %v; want %q", tt.in, got, err, tt.want)
		}
	}
}

func TestCompletionListsAndHelp(t *testing.T) {
	_, out, _ := read(t, "s\t\r")
	if !strings.Contains(out, "show") || !strings.Contains(out, "set") || !strings.Contains(out, "status") {
		t.Fatalf("ambiguous Tab should list candidates:\n%q", out)
	}
	_, out, _ = read(t, "s?\r")
	if !strings.Contains(out, "show things") || !strings.Contains(out, "set things") {
		t.Fatalf("? should list candidates with help:\n%q", out)
	}
	line, out, _ := read(t, "set address a1 cidr \t\r")
	if !strings.Contains(out, "<cidr>") || !strings.Contains(out, "an address") || line != "set address a1 cidr " {
		t.Fatalf("Tab on a hint should explain, not insert: %q\n%q", line, out)
	}
}

func TestControl(t *testing.T) {
	if _, _, err := read(t, "\x04"); err != io.EOF {
		t.Fatalf("Ctrl-D on empty line: %v", err)
	}
	if _, _, err := read(t, "half\x03"); err != ErrInterrupt {
		t.Fatalf("Ctrl-C: %v", err)
	}
	if line, _, err := read(t, "no newline"); err != nil || line != "no newline" {
		t.Fatalf("EOF with text: %q %v", line, err)
	}
}

func TestHistory(t *testing.T) {
	var out bytes.Buffer
	e := New(bufio.NewReader(strings.NewReader("first\rsecond\r\x1b[A\x1b[A\r\x1b[A\x1b[B\r")), &out, nil)
	for _, want := range []string{"first", "second", "first", ""} {
		got, err := e.ReadLine("> ")
		if err != nil || got != want {
			t.Fatalf("history: got %q %v, want %q", got, err, want)
		}
	}
}
