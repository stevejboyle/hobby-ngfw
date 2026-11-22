package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stevejboyle/hobby-ngfw/internal/compiler"
	"github.com/stevejboyle/hobby-ngfw/internal/decrypt"
	"github.com/stevejboyle/hobby-ngfw/internal/logs"
)

// testPKI is a "public" CA the proxy trusts for upstream servers.
type testPKI struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newPKI(t *testing.T) *testPKI {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Public Root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(c)
	return &testPKI{c, key, pool}
}

func (p *testPKI) leaf(t *testing.T, name string, notAfter time.Time) tls.Certificate {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: time.Now().Add(-2 * time.Hour), NotAfter: notAfter, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.cert, &key.PublicKey, p.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// upstream is an HTTPS server answering with the request line it saw.
func upstream(t *testing.T, cert tls.Certificate) net.Listener {
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "upstream saw "+r.Method+" "+r.URL.Path)
	}))
	t.Cleanup(func() { ln.Close() })
	return ln
}

// tap records what crosses the loop (what the forward chain would see).
type tap struct {
	net.Conn
	mu  sync.Mutex
	buf bytes.Buffer
}

func (t *tap) Read(b []byte) (int, error) {
	n, err := t.Conn.Read(b)
	t.mu.Lock()
	t.buf.Write(b[:n])
	t.mu.Unlock()
	return n, err
}

func (t *tap) seen() string { t.mu.Lock(); defer t.mu.Unlock(); return t.buf.String() }

type harness struct {
	p      *proxy
	cas    decrypt.CAs
	events chan logs.Decryption
	up     net.Listener
	taps   chan *tap
	deny   bool
}

func newHarness(t *testing.T, mode string, upCert tls.Certificate, pki *testPKI, rule decrypt.PolicyRule, excl ...string) *harness {
	dir := t.TempDir()
	if _, err := decrypt.GenerateCA(dir, "fw", time.Now(), decrypt.NoOwner); err != nil {
		t.Fatal(err)
	}
	cas, _ := decrypt.LoadCAs(dir)
	h := &harness{cas: cas, events: make(chan logs.Decryption, 10), up: upstream(t, upCert), taps: make(chan *tap, 10)}
	leaf, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	h.p = &proxy{now: time.Now, emit: func(d logs.Decryption) { h.events <- d }, leaf: leaf, roots: pki.pool,
		learned: decrypt.OpenLearned("", time.Hour), helloTimeout: 2 * time.Second, handshakeTimeout: 5 * time.Second,
		markOf: func(net.Conn) (uint32, error) { return compiler.DecryptMark | 3<<compiler.DecryptZoneShift | 1, nil },
		dialUp: func(ctx context.Context, _ netip.AddrPort) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", h.up.Addr().String())
		},
	}
	h.p.dialLoop = func(ctx context.Context, client, server netip.AddrPort, dscp int) (net.Conn, error) {
		if dscp != 3 {
			t.Errorf("loop dscp %d, want the zone's 3", dscp)
		}
		if h.deny {
			return nil, errors.New("connection timed out")
		}
		a, b := net.Pipe()
		tp := &tap{Conn: b}
		h.taps <- tp
		ch, _ := h.p.pending.Load(client.String() + ">" + server.String())
		ch.(chan net.Conn) <- tp
		return a, nil
	}
	h.p.st.Store(&state{policy: decrypt.Policy{Mode: mode, Rules: []decrypt.PolicyRule{rule}},
		match: decrypt.NewMatcher(map[string][]string{"banks": excl}), cas: &cas})
	return h
}

// get connects as a client trusting roots and fetches /path from name.
func (h *harness) get(t *testing.T, name string, roots *x509.CertPool, path string) (string, *x509.Certificate, error) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			h.p.handle(c)
		}
	}()
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		return "", nil, err
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(5 * time.Second))
	c := tls.Client(raw, &tls.Config{ServerName: name, RootCAs: roots, NextProtos: []string{"h2", "http/1.1"}})
	if err := c.Handshake(); err != nil {
		return "", nil, err
	}
	io.WriteString(c, "GET "+path+" HTTP/1.1\r\nHost: "+name+"\r\nConnection: close\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		return "", nil, err
	}
	body, _ := io.ReadAll(resp.Body)
	return string(body), c.ConnectionState().PeerCertificates[0], nil
}

func (h *harness) event(t *testing.T) logs.Decryption {
	t.Helper()
	select {
	case e := <-h.events:
		return e
	case <-time.After(5 * time.Second):
		t.Fatal("no decryption log entry")
	}
	return logs.Decryption{}
}

var defaultRule = decrypt.PolicyRule{Name: "users-out", Profile: "default", BadCertificate: "warn", Unsupported: "pass", Pinned: "exclude"}

func roots(cs ...*x509.Certificate) *x509.CertPool {
	p := x509.NewCertPool()
	for _, c := range cs {
		p.AddCert(c)
	}
	return p
}

func TestDecrypts(t *testing.T) {
	pki := newPKI(t)
	h := newHarness(t, decrypt.ModeDecrypt, pki.leaf(t, "shop.example", time.Now().Add(48*time.Hour)), pki, defaultRule)
	body, cert, err := h.get(t, "shop.example", roots(h.cas.Trusted.Cert), "/SJB-IPS-TEST-CRITICAL")
	if err != nil {
		t.Fatal(err)
	}
	if body != "upstream saw GET /SJB-IPS-TEST-CRITICAL" {
		t.Fatalf("body %q", body)
	}
	if cert.Issuer.CommonName != h.cas.Trusted.Cert.Subject.CommonName {
		t.Fatalf("client saw a certificate from %q, want the decryption CA", cert.Issuer.CommonName)
	}
	ev := h.event(t)
	if ev.Decision != logs.DecDecrypted || ev.Rule != "users-out" || ev.ServerName != "shop.example" || ev.TLS != "1.3" || ev.ALPN != "http/1.1" {
		t.Fatalf("event %+v", ev)
	}
	// The loop carried plaintext: the IPS sees the request.
	if seen := (<-h.taps).seen(); !strings.Contains(seen, "GET /SJB-IPS-TEST-CRITICAL HTTP/1.1") {
		t.Fatalf("loop saw %q, want the plaintext request", seen)
	}
}

func TestObservePassesThrough(t *testing.T) {
	pki := newPKI(t)
	h := newHarness(t, decrypt.ModeObserve, pki.leaf(t, "shop.example", time.Now().Add(48*time.Hour)), pki, defaultRule)
	_, cert, err := h.get(t, "shop.example", pki.pool, "/x")
	if err != nil {
		t.Fatal(err)
	}
	if cert.Issuer.CommonName != "Test Public Root" {
		t.Fatalf("observe mode must show the real certificate, got one from %q", cert.Issuer.CommonName)
	}
	if ev := h.event(t); ev.Decision != logs.DecWouldDecrypt || ev.ServerName != "shop.example" {
		t.Fatalf("event %+v", ev)
	}
	if seen := (<-h.taps).seen(); strings.Contains(seen, "GET /x") {
		t.Fatal("observe mode must not decrypt")
	}
}

func TestExcluded(t *testing.T) {
	pki := newPKI(t)
	h := newHarness(t, decrypt.ModeDecrypt, pki.leaf(t, "www.bank.example", time.Now().Add(48*time.Hour)), pki, defaultRule, "bank.example")
	_, cert, err := h.get(t, "www.bank.example", pki.pool, "/")
	if err != nil {
		t.Fatal(err)
	}
	if cert.Issuer.CommonName != "Test Public Root" {
		t.Fatal("an excluded name must keep the server's own certificate")
	}
	if ev := h.event(t); ev.Decision != logs.DecExcluded || !strings.Contains(ev.Reason, "banks") {
		t.Fatalf("event %+v", ev)
	}
}

// A client that doesn't trust the CA (a pinned app) is learned, and its
// server passes through from then on.
func TestPinnedLearned(t *testing.T) {
	pki := newPKI(t)
	h := newHarness(t, decrypt.ModeDecrypt, pki.leaf(t, "app.example", time.Now().Add(48*time.Hour)), pki, defaultRule)
	if _, _, err := h.get(t, "app.example", pki.pool, "/"); err == nil {
		t.Fatal("a client that doesn't trust the CA must fail the first time")
	}
	if ev := h.event(t); ev.Decision != logs.DecLearned {
		t.Fatalf("event %+v", ev)
	}
	_, cert, err := h.get(t, "app.example", pki.pool, "/")
	if err != nil || cert.Issuer.CommonName != "Test Public Root" {
		t.Fatalf("second try should pass through: %v", err)
	}
	if ev := h.event(t); ev.Decision != logs.DecLearned || !strings.Contains(ev.Reason, "rejected") {
		t.Fatalf("event %+v", ev)
	}
	rule := defaultRule
	rule.Pinned = "block"
	h2 := newHarness(t, decrypt.ModeDecrypt, pki.leaf(t, "app.example", time.Now().Add(48*time.Hour)), pki, rule)
	h2.get(t, "app.example", pki.pool, "/")
	if ev := h2.event(t); ev.Decision != logs.DecBlocked {
		t.Fatalf("pinned block: %+v", ev)
	}
}

// A server with a bad certificate is re-signed with the untrusted CA
// (warn), or refused (block).
func TestBadCertificate(t *testing.T) {
	pki, other := newPKI(t), newPKI(t)
	bad := other.leaf(t, "bad.example", time.Now().Add(48*time.Hour)) // from an authority the firewall doesn't trust
	h := newHarness(t, decrypt.ModeDecrypt, bad, pki, defaultRule)
	_, cert, err := h.get(t, "bad.example", roots(h.cas.Untrusted.Cert), "/")
	if err != nil {
		t.Fatal(err)
	}
	if cert.Issuer.CommonName != h.cas.Untrusted.Cert.Subject.CommonName {
		t.Fatalf("issuer %q, want the untrusted CA", cert.Issuer.CommonName)
	}
	if ev := h.event(t); ev.Decision != logs.DecDecrypted || !strings.Contains(ev.Reason, "untrusted CA") || !strings.Contains(ev.Reason, "authority") {
		t.Fatalf("event %+v", ev)
	}
	// A browser trusting only the decryption CA refuses it, so the user
	// sees a warning.
	if _, _, err := h.get(t, "bad.example", roots(h.cas.Trusted.Cert), "/"); err == nil {
		t.Fatal("the untrusted CA's certificate must not be accepted by a client trusting the decryption CA")
	}
	h.event(t)

	rule := defaultRule
	rule.BadCertificate = "block"
	h = newHarness(t, decrypt.ModeDecrypt, pki.leaf(t, "old.example", time.Now().Add(-time.Hour)), pki, rule) // expired
	if _, _, err := h.get(t, "old.example", roots(h.cas.Trusted.Cert, h.cas.Untrusted.Cert), "/"); err == nil {
		t.Fatal("block must refuse")
	}
	if ev := h.event(t); ev.Decision != logs.DecBlocked || !strings.Contains(ev.Reason, "expired") {
		t.Fatalf("event %+v", ev)
	}
}

func TestDeniedByRules(t *testing.T) {
	pki := newPKI(t)
	h := newHarness(t, decrypt.ModeDecrypt, pki.leaf(t, "shop.example", time.Now().Add(48*time.Hour)), pki, defaultRule)
	h.deny = true
	if _, _, err := h.get(t, "shop.example", roots(h.cas.Trusted.Cert), "/"); err == nil {
		t.Fatal("a connection the rules deny must not complete")
	}
	if ev := h.event(t); ev.Decision != logs.DecBlocked || !strings.Contains(ev.Reason, "security rules") {
		t.Fatalf("event %+v", ev)
	}
}

func TestNotTLS(t *testing.T) {
	pki := newPKI(t)
	for _, unsupported := range []string{"pass", "block"} {
		rule := defaultRule
		rule.Unsupported = unsupported
		h := newHarness(t, decrypt.ModeDecrypt, pki.leaf(t, "x.example", time.Now().Add(time.Hour)), pki, rule)
		// The server end reads whatever arrives: the harness's TLS upstream
		// would close on the first bytes, and the rest of the client's
		// bytes could then never cross the loop.
		sink, _ := net.Listen("tcp", "127.0.0.1:0")
		go func() {
			for {
				s, err := sink.Accept()
				if err != nil {
					return
				}
				go io.Copy(io.Discard, s)
			}
		}()
		h.p.dialUp = func(ctx context.Context, _ netip.AddrPort) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", sink.Addr().String())
		}
		ln, _ := net.Listen("tcp", "127.0.0.1:0")
		go func() {
			c, _ := ln.Accept()
			h.p.handle(c)
		}()
		c, _ := net.Dial("tcp", ln.Addr().String())
		c.Write([]byte("SSH-2.0-test\r\n"))
		ev := h.event(t)
		want := map[string]string{"pass": logs.DecPassed, "block": logs.DecBlocked}[unsupported]
		if ev.Decision != want || ev.Reason != "not TLS" {
			t.Fatalf("%s: event %+v", unsupported, ev)
		}
		if unsupported == "pass" {
			tp := <-h.taps
			deadline := time.Now().Add(2 * time.Second)
			for !strings.Contains(tp.seen(), "SSH-2.0-test") && time.Now().Before(deadline) {
				time.Sleep(10 * time.Millisecond)
			}
			if !strings.Contains(tp.seen(), "SSH-2.0-test") {
				t.Fatalf("passed-through bytes should cross the loop: %q", tp.seen())
			}
		}
		c.Close()
		ln.Close()
		sink.Close()
	}
}

func TestCertCache(t *testing.T) {
	pki := newPKI(t)
	h := newHarness(t, decrypt.ModeDecrypt, pki.leaf(t, "c.example", time.Now().Add(48*time.Hour)), pki, defaultRule)
	n := 0
	mk := func() (*tls.Certificate, error) {
		n++
		return decrypt.Forge(h.cas.Trusted, h.p.leaf, []string{"c.example"}, time.Now().Add(48*time.Hour), time.Now())
	}
	a, _ := h.p.certs.get("c.example", true, time.Now(), mk)
	b, _ := h.p.certs.get("c.example", true, time.Now(), mk)
	h.p.certs.get("c.example", false, time.Now(), mk)
	if a != b || n != 2 {
		t.Fatalf("cache: %d issued", n)
	}
	h.p.certs.get("c.example", true, time.Now().Add(72*time.Hour), mk)
	if n != 3 {
		t.Fatal("an expiring certificate is reissued")
	}
}

func TestInspectableALPN(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"h2,http/1.1", "http/1.1"}, {"http/1.1", "http/1.1"}, {"h2", "h2"}, {"", ""}, {"acme-tls/1", "acme-tls/1"},
	} {
		var in []string
		if c.in != "" {
			in = strings.Split(c.in, ",")
		}
		if got := strings.Join(inspectableALPN(in), ","); got != c.want {
			t.Errorf("%q: got %q, want %q", c.in, got, c.want)
		}
	}
}
