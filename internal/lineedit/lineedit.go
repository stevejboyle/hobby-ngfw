// Package lineedit is a small line editor for the SJB-OS CLI: Tab
// completion, "?" help, history, arrow keys and the usual Ctrl keys. It
// needs the terminal in raw mode while reading (see Raw); no dependencies.
package lineedit

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"unicode"
)

// Candidate is one completion. Words starting with "<" are hints: listed by
// "?" but never inserted.
type Candidate struct {
	Word string
	Help string
}

// Completer gets the text before the cursor and returns the partial word
// being typed and what may go there.
type Completer func(head string) (partial string, cands []Candidate)

// Editor reads lines from a raw-mode terminal.
type Editor struct {
	R        *bufio.Reader
	W        io.Writer
	Complete Completer
	history  []string
}

// New returns an editor on r and w.
func New(r *bufio.Reader, w io.Writer, c Completer) *Editor {
	return &Editor{R: r, W: w, Complete: c}
}

// ErrInterrupt is returned for Ctrl-C (the caller shows a fresh prompt).
var ErrInterrupt = fmt.Errorf("interrupted")

type line struct {
	buf    []rune
	cur    int
	prompt string
	w      io.Writer
}

func (l *line) redraw() {
	fmt.Fprintf(l.w, "\r%s%s\x1b[K", l.prompt, string(l.buf))
	if back := len(l.buf) - l.cur; back > 0 {
		fmt.Fprintf(l.w, "\x1b[%dD", back)
	}
}

func (l *line) insert(s string) {
	r := []rune(s)
	l.buf = append(l.buf[:l.cur], append(r, l.buf[l.cur:]...)...)
	l.cur += len(r)
}

// ReadLine shows prompt and returns the edited line. io.EOF on Ctrl-D at an
// empty line; ErrInterrupt on Ctrl-C.
func (e *Editor) ReadLine(prompt string) (string, error) {
	l := &line{prompt: prompt, w: e.W}
	hist := len(e.history)
	saved := ""
	fmt.Fprint(e.W, prompt)
	for {
		r, _, err := e.R.ReadRune()
		if err != nil {
			if len(l.buf) > 0 && err == io.EOF {
				fmt.Fprint(e.W, "\r\n")
				return string(l.buf), nil
			}
			return "", err
		}
		switch r {
		case '\r', '\n':
			fmt.Fprint(e.W, "\r\n")
			s := string(l.buf)
			if t := strings.TrimSpace(s); t != "" && (len(e.history) == 0 || e.history[len(e.history)-1] != t) {
				e.history = append(e.history, t)
			}
			return s, nil
		case 3: // Ctrl-C
			fmt.Fprint(e.W, "^C\r\n")
			return "", ErrInterrupt
		case 4: // Ctrl-D
			if len(l.buf) == 0 {
				fmt.Fprint(e.W, "\r\n")
				return "", io.EOF
			}
			if l.cur < len(l.buf) {
				l.buf = append(l.buf[:l.cur], l.buf[l.cur+1:]...)
			}
		case 127, 8: // Backspace
			if l.cur > 0 {
				l.buf = append(l.buf[:l.cur-1], l.buf[l.cur:]...)
				l.cur--
			}
		case 1: // Ctrl-A
			l.cur = 0
		case 5: // Ctrl-E
			l.cur = len(l.buf)
		case 2: // Ctrl-B
			if l.cur > 0 {
				l.cur--
			}
		case 6: // Ctrl-F
			if l.cur < len(l.buf) {
				l.cur++
			}
		case 21: // Ctrl-U
			l.buf, l.cur = append([]rune{}, l.buf[l.cur:]...), 0
		case 11: // Ctrl-K
			l.buf = l.buf[:l.cur]
		case 23: // Ctrl-W
			i := l.cur
			for i > 0 && l.buf[i-1] == ' ' {
				i--
			}
			for i > 0 && l.buf[i-1] != ' ' {
				i--
			}
			l.buf, l.cur = append(l.buf[:i], l.buf[l.cur:]...), i
		case 12: // Ctrl-L
			fmt.Fprint(e.W, "\x1b[H\x1b[2J")
		case '\t':
			e.tab(l)
		case '?':
			if strings.Count(string(l.buf[:l.cur]), `"`)%2 == 1 {
				l.insert("?") // inside a quoted message
				break
			}
			e.help(l)
		case 27: // escape sequences: arrows, Home, End, Delete
			seq := e.escape()
			switch seq {
			case "[A", "OA": // up
				if hist > 0 {
					if hist == len(e.history) {
						saved = string(l.buf)
					}
					hist--
					l.buf = []rune(e.history[hist])
					l.cur = len(l.buf)
				}
			case "[B", "OB": // down
				if hist < len(e.history) {
					hist++
					if hist == len(e.history) {
						l.buf = []rune(saved)
					} else {
						l.buf = []rune(e.history[hist])
					}
					l.cur = len(l.buf)
				}
			case "[C", "OC":
				if l.cur < len(l.buf) {
					l.cur++
				}
			case "[D", "OD":
				if l.cur > 0 {
					l.cur--
				}
			case "[H", "OH", "[1~":
				l.cur = 0
			case "[F", "OF", "[4~":
				l.cur = len(l.buf)
			case "[3~":
				if l.cur < len(l.buf) {
					l.buf = append(l.buf[:l.cur], l.buf[l.cur+1:]...)
				}
			}
		default:
			if unicode.IsPrint(r) {
				l.insert(string(r))
			}
		}
		l.redraw()
	}
}

// escape reads the rest of an escape sequence after ESC.
func (e *Editor) escape() string {
	var b strings.Builder
	r, _, err := e.R.ReadRune()
	if err != nil || (r != '[' && r != 'O') {
		return ""
	}
	b.WriteRune(r)
	for i := 0; i < 4; i++ {
		r, _, err := e.R.ReadRune()
		if err != nil {
			break
		}
		b.WriteRune(r)
		if (r >= 'A' && r <= 'Z') || r == '~' {
			break
		}
	}
	return b.String()
}

func words(cands []Candidate, partial string) []string {
	var out []string
	for _, c := range cands {
		if !strings.HasPrefix(c.Word, "<") && strings.HasPrefix(c.Word, partial) {
			out = append(out, c.Word)
		}
	}
	return out
}

func commonPrefix(ws []string) string {
	if len(ws) == 0 {
		return ""
	}
	p := ws[0]
	for _, w := range ws[1:] {
		for !strings.HasPrefix(w, p) {
			p = p[:len(p)-1]
		}
	}
	return p
}

func (e *Editor) tab(l *line) {
	if e.Complete == nil {
		return
	}
	partial, cands := e.Complete(string(l.buf[:l.cur]))
	ws := words(cands, partial)
	switch {
	case len(ws) == 1:
		l.insert(ws[0][len(partial):] + " ")
	case len(ws) > 1:
		if p := commonPrefix(ws); len(p) > len(partial) {
			l.insert(p[len(partial):])
			return
		}
		fmt.Fprint(e.W, "\r\n")
		e.columns(ws)
	case len(cands) > 0:
		e.help(l) // only hints: explain what goes here
	default:
		fmt.Fprint(e.W, "\a")
	}
}

func (e *Editor) help(l *line) {
	if e.Complete == nil {
		return
	}
	partial, cands := e.Complete(string(l.buf[:l.cur]))
	fmt.Fprint(e.W, "?\r\n")
	shown := 0
	width := 0
	for _, c := range cands {
		if strings.HasPrefix(c.Word, "<") || strings.HasPrefix(c.Word, partial) {
			width = max(width, len(c.Word))
		}
	}
	for _, c := range cands {
		if !strings.HasPrefix(c.Word, "<") && !strings.HasPrefix(c.Word, partial) {
			continue
		}
		fmt.Fprintf(e.W, "  %-*s  %s\r\n", width, c.Word, c.Help)
		shown++
	}
	if shown == 0 {
		fmt.Fprint(e.W, "  <Enter>  nothing more is needed here\r\n")
	}
}

func (e *Editor) columns(ws []string) {
	width := 0
	for _, w := range ws {
		width = max(width, len(w))
	}
	per := max(1, 78/(width+2))
	for i, w := range ws {
		fmt.Fprintf(e.W, "%-*s", width+2, w)
		if (i+1)%per == 0 || i == len(ws)-1 {
			fmt.Fprint(e.W, "\r\n")
		}
	}
}

// Raw puts the terminal on stdin into raw mode (no echo, no line buffering,
// Ctrl-C delivered as a byte) and returns a function that restores it.
func Raw() (restore func(), err error) {
	saved, err := stty("-g")
	if err != nil {
		return nil, err
	}
	if _, err := stty("-icanon", "-echo", "-isig", "-ixon", "-icrnl", "min", "1", "time", "0"); err != nil {
		return nil, err
	}
	return func() { stty(strings.TrimSpace(saved)) }, nil
}

func stty(args ...string) (string, error) {
	c := exec.Command("stty", args...)
	c.Stdin = os.Stdin
	out, err := c.Output()
	return string(out), err
}
