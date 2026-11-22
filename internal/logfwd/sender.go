package logfwd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/stevejboyle/hobby-ngfw/internal/config"
)

// QueueSize is how many messages wait per server; when full, the oldest
// is dropped (and counted).
const QueueSize = 10000

// Server states.
const (
	StateConnecting = "connecting"
	StateConnected  = "connected"
	StateError      = "error"
)

// ServerStatus is one server's forwarding state.
type ServerStatus struct {
	Name        string     `json:"name"`
	Address     string     `json:"address"`
	Port        int        `json:"port"`
	Transport   string     `json:"transport"`
	Format      string     `json:"format"`
	VRF         string     `json:"vrf"`
	Types       []string   `json:"types"`
	State       string     `json:"state"`
	Since       *time.Time `json:"since,omitempty"` // connected since
	Sent        uint64     `json:"sent"`
	Dropped     uint64     `json:"dropped"`
	Queued      int        `json:"queued"`
	LastError   string     `json:"last_error,omitempty"`
	LastErrorAt *time.Time `json:"last_error_at,omitempty"`
	LastSent    *time.Time `json:"last_sent,omitempty"`
}

// Dialer opens a connection to a log server; tests replace it.
type Dialer func(ctx context.Context, s config.LogServer) (net.Conn, error)

// sender delivers one server's queue.
type sender struct {
	cfg    config.LogServer
	dial   Dialer
	now    func() time.Time
	cancel context.CancelFunc
	done   chan struct{}

	mu       sync.Mutex
	cond     *sync.Cond
	queue    [][]byte // ring buffer contents, oldest first
	closed   bool
	state    string
	since    time.Time
	sent     uint64
	dropped  uint64
	lastErr  string
	lastErrT time.Time
	lastSent time.Time
}

func newSender(cfg config.LogServer, dial Dialer, now func() time.Time) *sender {
	ctx, cancel := context.WithCancel(context.Background())
	s := &sender{cfg: cfg, dial: dial, now: now, cancel: cancel, done: make(chan struct{}), state: StateConnecting}
	s.cond = sync.NewCond(&s.mu)
	go s.run(ctx)
	return s
}

// enqueue adds a message, dropping the oldest when the queue is full.
func (s *sender) enqueue(msg []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	if len(s.queue) >= QueueSize {
		s.queue[0] = nil
		s.queue = s.queue[1:]
		s.dropped++
	}
	s.queue = append(s.queue, msg)
	s.cond.Signal()
}

// next waits for a message; ok is false once the sender is closed.
func (s *sender) next() ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for len(s.queue) == 0 && !s.closed {
		s.cond.Wait()
	}
	if s.closed {
		return nil, false
	}
	m := s.queue[0]
	s.queue[0] = nil
	s.queue = s.queue[1:]
	return m, true
}

// requeue puts back a message whose write failed.
func (s *sender) requeue(msg []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.queue) >= QueueSize {
		s.dropped++
		return
	}
	s.queue = append([][]byte{msg}, s.queue...)
}

func (s *sender) setState(state string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = state
	switch state {
	case StateConnected:
		s.since = s.now()
	default:
		s.since = time.Time{}
	}
	if err != nil {
		s.lastErr, s.lastErrT = err.Error(), s.now()
	}
}

func (s *sender) close() {
	s.mu.Lock()
	s.closed = true
	s.cond.Broadcast()
	s.mu.Unlock()
	s.cancel()
	<-s.done
}

func (s *sender) status() ServerStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.cfg
	st := ServerStatus{Name: c.Name, Address: c.Address, Port: c.PortOrDefault(), Transport: c.TransportOrDefault(),
		Format: c.FormatOrDefault(), VRF: c.VRFOrDefault(), Types: c.TypesOrDefault(), State: s.state,
		Sent: s.sent, Dropped: s.dropped, Queued: len(s.queue), LastError: s.lastErr}
	if !s.since.IsZero() {
		t := s.since
		st.Since = &t
	}
	if !s.lastErrT.IsZero() {
		t := s.lastErrT
		st.LastErrorAt = &t
	}
	if !s.lastSent.IsZero() {
		t := s.lastSent
		st.LastSent = &t
	}
	return st
}

// Backoff bounds for reconnecting.
var (
	minBackoff = time.Second
	maxBackoff = 30 * time.Second
)

func (s *sender) run(ctx context.Context) {
	defer close(s.done)
	backoff := minBackoff
	stream := s.cfg.TransportOrDefault() != config.LogUDP
	for ctx.Err() == nil {
		dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		conn, err := s.dial(dctx, s.cfg)
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			s.setState(StateError, err)
			if !sleep(ctx, backoff) {
				return
			}
			backoff = min(backoff*2, maxBackoff)
			continue
		}
		s.setState(StateConnected, nil)
		backoff = minBackoff
		stop := context.AfterFunc(ctx, func() { conn.Close() })
		err = s.drain(conn, stream)
		stop()
		conn.Close()
		if ctx.Err() != nil || err == nil {
			return
		}
		s.setState(StateError, err)
		if !sleep(ctx, backoff) {
			return
		}
	}
}

// drain writes queued messages until the sender closes (nil) or a write
// fails (the message is put back).
func (s *sender) drain(conn net.Conn, stream bool) error {
	for {
		msg, ok := s.next()
		if !ok {
			return nil
		}
		out := msg
		if stream {
			out = Frame(msg)
		} else if len(out) > MaxUDPMessage {
			out = out[:MaxUDPMessage]
		}
		conn.SetWriteDeadline(s.now().Add(15 * time.Second))
		if _, err := conn.Write(out); err != nil {
			s.requeue(msg)
			return err
		}
		s.mu.Lock()
		s.sent++
		s.lastSent = s.now()
		s.mu.Unlock()
	}
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// MgmtVRFDevice is the management VRF's device: connections to servers in
// the mgmt VRF are bound to it.
const MgmtVRFDevice = "vrf-mgmt"

// Dial is the appliance's Dialer: UDP, TCP or TLS to the server, bound to
// the management VRF unless the server is in the default VRF. TLS checks
// the server's certificate against the server's CA (or the system roots)
// and its server_name (or address).
func Dial(ctx context.Context, s config.LogServer) (net.Conn, error) {
	d := net.Dialer{}
	if s.VRFOrDefault() == config.VRFMgmt {
		d.Control = bindToDevice(MgmtVRFDevice)
	}
	addr := net.JoinHostPort(s.Address, strconv.Itoa(s.PortOrDefault()))
	switch s.TransportOrDefault() {
	case config.LogUDP:
		return d.DialContext(ctx, "udp4", addr)
	case config.LogTCP:
		return d.DialContext(ctx, "tcp4", addr)
	}
	tc, err := TLSConfig(s)
	if err != nil {
		return nil, err
	}
	td := tls.Dialer{NetDialer: &d, Config: tc}
	return td.DialContext(ctx, "tcp4", addr)
}

// TLSConfig is the client config for a TLS log server.
func TLSConfig(s config.LogServer) (*tls.Config, error) {
	tc := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: s.ServerName}
	if tc.ServerName == "" {
		tc.ServerName = s.Address
	}
	if s.CA != "" {
		certs, err := config.ParseCAPEM(s.CA)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		for _, c := range certs {
			pool.AddCert(c)
		}
		tc.RootCAs = pool
	}
	return tc, nil
}
