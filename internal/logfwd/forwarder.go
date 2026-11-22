package logfwd

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/stevejboyle/hobby-ngfw/internal/config"
	"github.com/stevejboyle/hobby-ngfw/internal/logs"
)

// Status is the forwarder's state: the journal follower and each server.
type Status struct {
	Following   bool           `json:"following"`
	FollowError string         `json:"follow_error,omitempty"`
	Servers     []ServerStatus `json:"servers"`
}

// Source starts reading journal records (`journalctl -o json` lines) after
// cursor ("" = from now on); tests replace it.
type Source func(ctx context.Context, cursor string) (io.ReadCloser, error)

// Forwarder sends log records to the configured servers.
type Forwarder struct {
	Journal    logs.Journal // ParseRecord: zones and rule names
	Source     Source       // nil: journalctl -f
	CursorFile string       // where the journal position is kept ("" = not kept)
	Hostname   func() string
	Version    string
	Dial       Dialer // nil: Dial
	Log        *slog.Logger
	Now        func() time.Time

	mu        sync.Mutex
	order     []string
	senders   map[string]*sender
	cancel    context.CancelFunc
	followed  chan struct{}
	following bool
	followErr string
}

func (f *Forwarder) log() *slog.Logger {
	if f.Log == nil {
		return slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return f.Log
}

func (f *Forwarder) now() time.Time {
	if f.Now != nil {
		return f.Now()
	}
	return time.Now()
}

func (f *Forwarder) host() string {
	if f.Hostname != nil {
		return f.Hostname()
	}
	h, _ := os.Hostname()
	return h
}

// Configure makes the forwarder send to servers: senders are kept for
// unchanged servers, restarted for changed ones and stopped for removed
// ones; the journal follower runs while there is at least one. It never
// blocks on the network.
func (f *Forwarder) Configure(servers []config.LogServer) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.senders == nil {
		f.senders = map[string]*sender{}
	}
	dial := f.Dial
	if dial == nil {
		dial = Dial
	}
	want := map[string]config.LogServer{}
	var order []string
	for _, s := range servers {
		want[s.Name] = s
		order = append(order, s.Name)
	}
	for name, s := range f.senders {
		if w, ok := want[name]; !ok || !reflect.DeepEqual(w, s.cfg) {
			go s.close()
			delete(f.senders, name)
		}
	}
	var warns []string
	for _, s := range servers {
		if _, ok := f.senders[s.Name]; ok {
			continue
		}
		f.senders[s.Name] = newSender(s, dial, f.now)
		f.log().Info("log forwarding to server", "server", s.Name, "address", s.Address, "port", s.PortOrDefault(),
			"transport", s.TransportOrDefault(), "format", s.FormatOrDefault(), "vrf", s.VRFOrDefault())
	}
	f.order = order
	switch {
	case len(servers) > 0 && f.cancel == nil:
		ctx, cancel := context.WithCancel(context.Background())
		f.cancel, f.followed = cancel, make(chan struct{})
		go f.follow(ctx, f.followed)
	case len(servers) == 0 && f.cancel != nil:
		f.cancel()
		f.cancel = nil
		f.following = false
	}
	return warns
}

// Close stops the follower and every sender.
func (f *Forwarder) Close() {
	f.Configure(nil)
	f.mu.Lock()
	done := f.followed
	f.mu.Unlock()
	if done != nil {
		<-done
	}
}

// Status reports the follower and every server, in config order.
func (f *Forwarder) Status() Status {
	f.mu.Lock()
	defer f.mu.Unlock()
	st := Status{Following: f.following, FollowError: f.followErr, Servers: []ServerStatus{}}
	for _, name := range f.order {
		if s := f.senders[name]; s != nil {
			st.Servers = append(st.Servers, s.status())
		}
	}
	return st
}

// Handle queues a record for every server that takes its kind.
func (f *Forwarder) Handle(r logs.Record) {
	f.mu.Lock()
	defer f.mu.Unlock()
	host := f.host()
	for _, name := range f.order {
		s := f.senders[name]
		if s == nil || !s.cfg.Sends(r.Kind) {
			continue
		}
		s.enqueue(Message(s.cfg, host, f.Version, r))
	}
}

// Test queues a test message (a system log entry) for one server.
func (f *Forwarder) Test(name, by string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := f.senders[name]
	if s == nil {
		return fmt.Errorf("no log server %q in the running config", name)
	}
	r := logs.Record{Kind: logs.KindSystem, Entry: logs.System{Time: f.now().UTC(), Source: "ngfwd", Level: "info",
		Message: "SJB-OS log forwarding test: border check passed", Fields: "server=" + name + " by=" + by}}
	s.enqueue(Message(s.cfg, f.host(), f.Version, r))
	return nil
}

func (f *Forwarder) setFollow(on bool, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.following = on
	if err != nil {
		f.followErr = err.Error()
	} else if on {
		f.followErr = ""
	}
}

// follow reads the journal until ctx ends, restarting the reader when it
// stops, and keeps the cursor so a restart resumes where it left off.
func (f *Forwarder) follow(ctx context.Context, done chan struct{}) {
	defer close(done)
	cursor := f.readCursor()
	backoff := minBackoff
	for ctx.Err() == nil {
		src := f.Source
		if src == nil {
			src = Journalctl("journalctl")
		}
		rc, err := src(ctx, cursor)
		if err != nil {
			f.setFollow(false, err)
			f.log().Warn("log forwarding: can't read the journal", "err", err)
			if !sleep(ctx, backoff) {
				return
			}
			backoff = min(backoff*2, maxBackoff)
			continue
		}
		f.setFollow(true, nil)
		backoff = minBackoff
		started := time.Now()
		next := f.read(ctx, rc, cursor)
		rc.Close()
		if ctx.Err() != nil {
			cursor = next
			break
		}
		if next == cursor && cursor != "" && time.Since(started) < 2*time.Second {
			// journalctl gave up at once: the saved position has most
			// likely been rotated away. Carry on from now.
			f.log().Warn("log forwarding: the saved journal position is gone; forwarding from now on")
			next = ""
		}
		cursor = next
		f.setFollow(false, fmt.Errorf("journal reader stopped"))
		if !sleep(ctx, minBackoff) {
			break
		}
	}
	f.writeCursor(cursor)
}

func (f *Forwarder) read(ctx context.Context, rc io.Reader, cursor string) string {
	sc := bufio.NewScanner(rc)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	last := time.Now()
	for sc.Scan() {
		if ctx.Err() != nil {
			break
		}
		r, ok := f.Journal.ParseRecord(sc.Bytes())
		if r.Cursor != "" {
			cursor = r.Cursor
		}
		if ok {
			f.Handle(r)
		}
		if time.Since(last) > 2*time.Second {
			f.writeCursor(cursor)
			last = time.Now()
		}
	}
	f.writeCursor(cursor)
	return cursor
}

func (f *Forwarder) readCursor() string {
	if f.CursorFile == "" {
		return ""
	}
	b, err := os.ReadFile(f.CursorFile)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func (f *Forwarder) writeCursor(c string) {
	if f.CursorFile == "" || c == "" {
		return
	}
	tmp := f.CursorFile + ".tmp"
	if err := os.WriteFile(tmp, []byte(c+"\n"), 0o600); err != nil {
		return
	}
	os.Rename(tmp, f.CursorFile)
}

// Journalctl is the appliance's Source: `journalctl -f -o json` over the
// log units, after cursor or from now on.
func Journalctl(path string) Source {
	return func(ctx context.Context, cursor string) (io.ReadCloser, error) {
		args := []string{"-f", "-o", "json", "--no-pager"}
		if cursor != "" {
			args = append(args, "--after-cursor", cursor)
		} else {
			args = append(args, "-n", "0")
		}
		args = append(args, logs.FollowMatches()...)
		cmd := exec.CommandContext(ctx, path, args...)
		out, err := cmd.StdoutPipe()
		if err != nil {
			return nil, err
		}
		if err := cmd.Start(); err != nil {
			return nil, fmt.Errorf("journalctl: %w", err)
		}
		return &cmdReader{ReadCloser: out, cmd: cmd}, nil
	}
}

type cmdReader struct {
	io.ReadCloser
	cmd *exec.Cmd
}

func (c *cmdReader) Close() error {
	c.ReadCloser.Close()
	if c.cmd.Process != nil {
		c.cmd.Process.Kill()
	}
	c.cmd.Wait()
	return nil
}

// CursorPath is where ngfwd keeps the forwarder's journal position.
func CursorPath(stateDir string) string { return filepath.Join(stateDir, "logfwd.cursor") }
