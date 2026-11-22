package logfwd

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stevejboyle/hobby-ngfw/internal/config"
	"github.com/stevejboyle/hobby-ngfw/internal/logs"
)

var update = flag.Bool("update", false, "rewrite golden files")

var t0 = time.Date(2026, 11, 21, 10, 0, 0, 123456000, time.UTC)

func records() []logs.Record {
	return []logs.Record{
		{Kind: logs.KindTraffic, Entry: logs.Traffic{Time: t0, Type: "start", Rule: "web-out", Action: "allow", FromZone: "users", ToZone: "internet",
			In: "inside", Out: "outside", Src: "10.0.0.5", Dst: "203.0.113.9", Proto: "tcp", SPort: 40000, DPort: 443, Len: 60, TTL: 64, Flags: "SYN"}},
		{Kind: logs.KindTraffic, Entry: logs.Traffic{Time: t0, Type: "end", Rule: "web-out", Action: "allow", Src: "10.0.0.5", Dst: "203.0.113.9",
			Proto: "tcp", SPort: 40000, DPort: 443, App: "YouTube", Category: "Media", Bytes: 9000, Packets: 12, Duration: 1.5}},
		{Kind: logs.KindTraffic, Entry: logs.Traffic{Time: t0, Type: "start", Rule: "block|p2p", Action: "deny", In: "inside", Out: "outside",
			Src: "10.0.0.6", Dst: "198.51.100.7", Proto: "udp", SPort: 6881, DPort: 6881}},
		{Kind: logs.KindThreat, Entry: logs.Threat{Time: t0, Rule: "web-out", Profile: "strict", Action: "block", Severity: "critical", SID: 9900001,
			Signature: "SJB-OS test signature: a=b \\ c", Category: "Attempted Administrator Privilege Gain", Proto: "tcp",
			Src: "10.0.0.5", SPort: 40000, Dst: "203.0.113.9", DPort: 80, Decrypted: true}},
		{Kind: logs.KindDecryption, Entry: logs.Decryption{Time: t0, Rule: "decrypt-web", Decision: "decrypted", ServerName: "example.com",
			Src: "10.0.0.5", SPort: 40001, Dst: "203.0.113.9", DPort: 443, TLS: "1.3", ALPN: "http/1.1"}},
		{Kind: logs.KindSystem, Entry: logs.System{Time: t0, Source: "ngfwd", Level: "info", Message: "commit", Fields: "revision=4 author=cli:admin"}},
		{Kind: logs.KindSystem, Entry: logs.System{Time: t0, Source: "sshd", Level: "warn", Message: "Failed password for x\nfrom 10.0.0.9"}},
	}
}

func TestMessagesGolden(t *testing.T) {
	for _, format := range []string{"json", "cef"} {
		srv := config.LogServer{Name: "s", Address: "10.0.0.50", Format: format}
		var b strings.Builder
		for _, r := range records() {
			b.Write(Message(srv, "sjb-fw", "0.9.11-r01", r))
			b.WriteByte('\n')
		}
		path := filepath.Join("testdata", format+".golden")
		if *update {
			os.WriteFile(path, []byte(b.String()), 0o644)
		}
		want, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if b.String() != string(want) {
			t.Errorf("%s differs from %s (go test -update):\n%s", format, path, b.String())
		}
	}
}

func TestMessageHeader(t *testing.T) {
	srv := config.LogServer{Name: "s", Address: "10.0.0.50", Facility: "local3"}
	r := records()[3] // critical threat: severity 2
	m := string(Message(srv, "sjb fw\n", "v", r))
	want := "<154>1 2026-11-21T10:00:00.123456Z sjbfw sjb-os - THREAT - {\"log\":\"threat\","
	if !strings.HasPrefix(m, want) {
		t.Fatalf("got %q\nwant prefix %q", m, want)
	}
	if got := string(Frame([]byte("abc"))); got != "3 abc" {
		t.Fatalf("frame %q", got)
	}
}

func TestCEFEscaping(t *testing.T) {
	if got := cefHeader(`a|b\c`); got != `a\|b\\c` {
		t.Errorf("header %q", got)
	}
	if got := cefValue("a=b\\c\nd"); got != `a\=b\\c\nd` {
		t.Errorf("value %q", got)
	}
}

// listener collects messages on one transport.
type listener struct {
	addr string
	port int
	mu   sync.Mutex
	got  []string
	stop func()
}

func (l *listener) add(m string) {
	l.mu.Lock()
	l.got = append(l.got, m)
	l.mu.Unlock()
}

func (l *listener) wait(t *testing.T, n int) []string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		l.mu.Lock()
		if len(l.got) >= n {
			out := append([]string(nil), l.got...)
			l.mu.Unlock()
			return out
		}
		l.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("got %d messages, want %d", len(l.got), n)
	return nil
}

func streamListener(t *testing.T, tc *tls.Config) *listener {
	var ln net.Listener
	var err error
	if tc != nil {
		ln, err = tls.Listen("tcp4", "127.0.0.1:0", tc)
	} else {
		ln, err = net.Listen("tcp4", "127.0.0.1:0")
	}
	if err != nil {
		t.Fatal(err)
	}
	l := &listener{addr: "127.0.0.1", port: ln.Addr().(*net.TCPAddr).Port, stop: func() { ln.Close() }}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				br := bufio.NewReader(c)
				for {
					n, err := br.ReadString(' ')
					if err != nil {
						return
					}
					size, err := strconv.Atoi(strings.TrimSpace(n))
					if err != nil {
						l.add("BAD FRAME " + n)
						return
					}
					buf := make([]byte, size)
					if _, err := io.ReadFull(br, buf); err != nil {
						return
					}
					l.add(string(buf))
				}
			}()
		}
	}()
	t.Cleanup(l.stop)
	return l
}

func udpListener(t *testing.T) *listener {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := &listener{addr: "127.0.0.1", port: pc.LocalAddr().(*net.UDPAddr).Port, stop: func() { pc.Close() }}
	go func() {
		buf := make([]byte, 65536)
		for {
			n, _, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			l.add(string(buf[:n]))
		}
	}()
	t.Cleanup(l.stop)
	return l
}

func testPKI(t *testing.T) (caPEM string, server tls.Certificate) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caT := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "log CA"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caT, caT, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	st := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "siem.lab"}, DNSNames: []string{"siem.lab"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, st, ca, &k.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})), tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}

func TestForwardEveryTransport(t *testing.T) {
	caPEM, cert := testPKI(t)
	tlsL := streamListener(t, &tls.Config{Certificates: []tls.Certificate{cert}})
	tcpL := streamListener(t, nil)
	udpL := udpListener(t)
	f := &Forwarder{Hostname: func() string { return "sjb-fw" }, Version: "test",
		Source: func(ctx context.Context, cursor string) (io.ReadCloser, error) { <-ctx.Done(); return nil, ctx.Err() }}
	defer f.Close()
	servers := []config.LogServer{
		{Name: "tls", Address: "127.0.0.1", Port: tlsL.port, VRF: "default", ServerName: "siem.lab", CA: caPEM},
		{Name: "tcp", Address: "127.0.0.1", Port: tcpL.port, VRF: "default", Transport: "tcp", Format: "cef"},
		{Name: "udp", Address: "127.0.0.1", Port: udpL.port, VRF: "default", Transport: "udp", Types: []string{"threat"}},
	}
	f.Configure(servers)
	for _, r := range records() {
		f.Handle(r)
	}
	if got := tlsL.wait(t, len(records())); !strings.Contains(got[0], `{"log":"traffic"`) {
		t.Errorf("tls: %q", got[0])
	}
	if got := tcpL.wait(t, len(records())); !strings.Contains(got[3], "CEF:0|SJB Consulting|SJB-OS|test|9900001|") {
		t.Errorf("tcp: %q", got[3])
	}
	if got := udpL.wait(t, 1); len(got) != 1 || !strings.Contains(got[0], " THREAT ") {
		t.Errorf("udp should get only the threat: %q", got)
	}
	st := f.Status()
	if len(st.Servers) != 3 || st.Servers[0].Name != "tls" || st.Servers[0].State != StateConnected || st.Servers[0].Sent != uint64(len(records())) {
		t.Errorf("status %+v", st.Servers)
	}
	if err := f.Test("udp", "cli:admin"); err != nil {
		t.Fatal(err)
	}
	if got := udpL.wait(t, 2); !strings.Contains(got[1], "border check") {
		t.Errorf("test message %q", got[1])
	}
	if f.Test("nope", "x") == nil {
		t.Error("test of an unknown server")
	}
}

func TestTLSRejectsWrongCA(t *testing.T) {
	_, cert := testPKI(t)
	otherCA, _ := testPKI(t)
	l := streamListener(t, &tls.Config{Certificates: []tls.Certificate{cert}})
	f := &Forwarder{Source: func(ctx context.Context, _ string) (io.ReadCloser, error) { <-ctx.Done(); return nil, ctx.Err() }}
	defer f.Close()
	f.Configure([]config.LogServer{{Name: "tls", Address: "127.0.0.1", Port: l.port, VRF: "default", ServerName: "siem.lab", CA: otherCA}})
	f.Handle(records()[0])
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if s := f.Status().Servers[0]; s.State == StateError && strings.Contains(s.LastError, "certificate") {
			if s.Queued != 1 || s.Sent != 0 {
				t.Fatalf("queued %d sent %d", s.Queued, s.Sent)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no certificate error: %+v", f.Status().Servers[0])
}

func TestQueueDropsOldest(t *testing.T) {
	s := &sender{cfg: config.LogServer{Name: "x"}, now: time.Now, done: make(chan struct{})}
	s.cond = sync.NewCond(&s.mu)
	for i := 0; i < QueueSize+5; i++ {
		s.enqueue([]byte(strconv.Itoa(i)))
	}
	st := s.status()
	if st.Queued != QueueSize || st.Dropped != 5 || string(s.queue[0]) != "5" {
		t.Fatalf("queued %d dropped %d first %s", st.Queued, st.Dropped, s.queue[0])
	}
}

func TestReconnectsAndReconfigures(t *testing.T) {
	minBackoff, maxBackoff = 10*time.Millisecond, 20*time.Millisecond
	defer func() { minBackoff, maxBackoff = time.Second, 30*time.Second }()
	l := streamListener(t, nil)
	var fails int
	var mu sync.Mutex
	dial := func(ctx context.Context, s config.LogServer) (net.Conn, error) {
		mu.Lock()
		defer mu.Unlock()
		if fails < 2 {
			fails++
			return nil, io.ErrUnexpectedEOF
		}
		return Dial(ctx, s)
	}
	f := &Forwarder{Dial: dial, Source: func(ctx context.Context, _ string) (io.ReadCloser, error) { <-ctx.Done(); return nil, ctx.Err() }}
	defer f.Close()
	srv := config.LogServer{Name: "tcp", Address: "127.0.0.1", Port: l.port, VRF: "default", Transport: "tcp"}
	f.Configure([]config.LogServer{srv})
	f.Handle(records()[5])
	l.wait(t, 1)
	if st := f.Status().Servers[0]; st.LastError == "" || st.State != StateConnected {
		t.Fatalf("status %+v", st)
	}
	// Changing the format restarts the sender; removing all stops the follower.
	srv.Format = "cef"
	f.Configure([]config.LogServer{srv})
	f.Handle(records()[5])
	if got := l.wait(t, 2); !strings.Contains(got[1], "CEF:0") {
		t.Fatalf("after reconfigure: %q", got[1])
	}
	f.Configure(nil)
	if st := f.Status(); len(st.Servers) != 0 || st.Following {
		t.Fatalf("after removing: %+v", st)
	}
}

func TestFollowerResumesFromCursor(t *testing.T) {
	l := udpListener(t)
	dir := t.TempDir()
	cursorFile := filepath.Join(dir, "logfwd.cursor")
	var seen []string
	var mu sync.Mutex
	lines := `{"__CURSOR":"c1","__REALTIME_TIMESTAMP":"1763700000000000","_SYSTEMD_UNIT":"ngfwd.service","MESSAGE":"time=x level=INFO msg=one"}
{"__CURSOR":"c2","_TRANSPORT":"kernel","MESSAGE":"unrelated kernel line"}
`
	src := func(ctx context.Context, cursor string) (io.ReadCloser, error) {
		mu.Lock()
		seen = append(seen, cursor)
		first := len(seen) == 1
		mu.Unlock()
		if !first {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return io.NopCloser(strings.NewReader(lines)), nil
	}
	f := &Forwarder{Source: src, CursorFile: cursorFile}
	f.Configure([]config.LogServer{{Name: "u", Address: "127.0.0.1", Port: l.port, VRF: "default", Transport: "udp"}})
	if got := l.wait(t, 1); !strings.Contains(got[0], `"message":"one"`) {
		t.Fatalf("got %q", got[0])
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(seen)
		mu.Unlock()
		if n >= 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	f.Close()
	mu.Lock()
	defer mu.Unlock()
	if len(seen) < 2 || seen[0] != "" || seen[1] != "c2" {
		t.Fatalf("cursors asked for: %q", seen)
	}
	if b, _ := os.ReadFile(cursorFile); strings.TrimSpace(string(b)) != "c2" {
		t.Fatalf("cursor file %q", b)
	}
}
