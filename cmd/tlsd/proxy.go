package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/stevejboyle/hobby-ngfw/internal/compiler"
	"github.com/stevejboyle/hobby-ngfw/internal/decrypt"
	"github.com/stevejboyle/hobby-ngfw/internal/logs"
)

// state is what tlsd works from: the policy, its exclusions and the CAs.
// Reloaded whole, swapped atomically.
type state struct {
	policy decrypt.Policy
	match  *decrypt.Matcher
	cas    *decrypt.CAs // nil: no CA yet (everything passes through)
	err    string       // why the last load failed, if it did
}

// proxy handles handed-over connections.
type proxy struct {
	st      atomic.Pointer[state]
	now     func() time.Time
	emit    func(logs.Decryption)
	leaf    crypto.Signer // key of every forged certificate (memory only)
	roots   *x509.CertPool
	learned *decrypt.Learned
	certs   certCache
	// sessions resumes TLS sessions with servers (fewer full handshakes).
	sessions tls.ClientSessionCache

	// dialLoop opens the loop leg (client half); dialUp reaches the server.
	dialLoop func(ctx context.Context, client, server netip.AddrPort, dscp int) (net.Conn, error)
	dialUp   func(ctx context.Context, server netip.AddrPort) (net.Conn, error)
	// markOf reads the mark of a handed-over connection (rule, zone).
	markOf func(net.Conn) (uint32, error)

	pending sync.Map // "client>server" -> chan net.Conn (the loop's server end)
	counts  sync.Map // decision -> *atomic.Int64
	active  atomic.Int64

	helloTimeout     time.Duration
	handshakeTimeout time.Duration
}

func (p *proxy) count(decision string) {
	v, _ := p.counts.LoadOrStore(decision, new(atomic.Int64))
	v.(*atomic.Int64).Add(1)
}

// Counts reports connections by decision.
func (p *proxy) Counts() map[string]int64 {
	out := map[string]int64{}
	p.counts.Range(func(k, v any) bool {
		out[k.(string)] = v.(*atomic.Int64).Load()
		return true
	})
	return out
}

func addrPort(a net.Addr) netip.AddrPort {
	if t, ok := a.(*net.TCPAddr); ok {
		ap := t.AddrPort()
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	}
	ap, _ := netip.ParseAddrPort(a.String())
	return ap
}

// serveLoop takes the loop's server ends (in the server-half namespace)
// and hands each to the connection waiting for it.
func (p *proxy) serveLoop(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		key := addrPort(c.RemoteAddr()).String() + ">" + addrPort(c.LocalAddr()).String()
		if ch, ok := p.pending.Load(key); ok {
			select {
			case ch.(chan net.Conn) <- c:
				continue
			default:
			}
		}
		c.Close() // nobody waiting (timed out, or not ours)
	}
}

// openLoop sends a connection round the loop: through the forward chain,
// where the security rules, App Identification and the IPS apply. An error
// means the rules didn't let it through (or the loop is broken).
func (p *proxy) openLoop(ctx context.Context, client, server netip.AddrPort, dscp int) (net.Conn, net.Conn, error) {
	key := client.String() + ">" + server.String()
	ch := make(chan net.Conn, 1)
	if _, dup := p.pending.LoadOrStore(key, ch); dup {
		return nil, nil, fmt.Errorf("a connection from %s to %s is already being set up", client, server)
	}
	defer p.pending.Delete(key)
	lc, err := p.dialLoop(ctx, client, server, dscp)
	if err != nil {
		return nil, nil, err
	}
	select {
	case ls := <-ch:
		return lc, ls, nil
	case <-time.After(loopTimeout):
		lc.Close()
		return nil, nil, errors.New("the loop's far end never saw the connection")
	}
}

// handle is one handed-over client connection.
func (p *proxy) handle(c net.Conn) {
	p.active.Add(1)
	defer p.active.Add(-1)
	st := p.st.Load()
	client, server := addrPort(c.RemoteAddr()), addrPort(c.LocalAddr())
	mark, _ := p.markOf(c)
	rule := decrypt.PolicyRule{Name: "?", BadCertificate: "warn", Unsupported: "pass", Pinned: "exclude"}
	if i := int(mark&compiler.DecryptRuleMask) - 1; i >= 0 && i < len(st.policy.Rules) {
		rule = st.policy.Rules[i]
	}
	dscp := int(mark&compiler.DecryptZoneMask) >> compiler.DecryptZoneShift
	ev := logs.Decryption{Time: p.now().UTC(), Rule: rule.Name, Src: client.Addr().String(), SPort: int(client.Port()),
		Dst: server.Addr().String(), DPort: int(server.Port())}
	ctx, cancel := context.WithTimeout(context.Background(), p.handshakeTimeout)
	defer cancel()

	c.SetReadDeadline(p.now().Add(p.helloTimeout))
	raw, hello, err := decrypt.ReadHello(c)
	c.SetReadDeadline(time.Time{})
	ev.ServerName = hello.ServerName

	unsupported := func(reason string) {
		ev.Reason = reason
		if rule.Unsupported == "block" {
			ev.Decision = logs.DecBlocked
			p.log(ev)
			reset(c)
			return
		}
		ev.Decision = logs.DecPassed
		p.passThrough(ctx, c, raw, ev, client, server, dscp)
	}
	switch {
	case err != nil && !errors.Is(err, decrypt.ErrNotTLS):
		if len(raw) == 0 {
			c.Close() // connected and said nothing; nothing to pass on
			return
		}
		unsupported("incomplete TLS hello")
		return
	case err != nil:
		unsupported("not TLS")
		return
	case hello.ServerName == "":
		unsupported("no server name in the TLS hello")
		return
	case hello.ECH:
		unsupported("encrypted client hello: the real server name is hidden")
		return
	case hello.MaxVersion < tls.VersionTLS12:
		unsupported("TLS older than 1.2")
		return
	}
	if list := st.match.Match(hello.ServerName); list != "" {
		ev.Decision, ev.Reason = logs.DecExcluded, "on exclusion list "+list
		p.passThrough(ctx, c, raw, ev, client, server, dscp)
		return
	}
	if p.learned.Has(hello.ServerName, server.Addr().String(), p.now()) {
		ev.Decision, ev.Reason = logs.DecLearned, "its client rejected the firewall's certificate before (pinned app?)"
		p.passThrough(ctx, c, raw, ev, client, server, dscp)
		return
	}
	if st.cas == nil {
		ev.Decision, ev.Reason = logs.DecPassed, "no decryption CA yet (request decryption ca generate)"
		p.passThrough(ctx, c, raw, ev, client, server, dscp)
		return
	}
	if st.policy.Mode != decrypt.ModeDecrypt {
		ev.Decision = logs.DecWouldDecrypt
		p.passThrough(ctx, c, raw, ev, client, server, dscp)
		return
	}
	p.decrypt(ctx, st, c, raw, hello, ev, rule, client, server, dscp)
}

func (p *proxy) log(ev logs.Decryption) {
	p.count(ev.Decision)
	p.emit(ev)
}

// passThrough sends the connection's bytes round the loop unchanged.
func (p *proxy) passThrough(ctx context.Context, c net.Conn, raw []byte, ev logs.Decryption, client, server netip.AddrPort, dscp int) {
	lc, ls, err := p.openLoop(ctx, client, server, dscp)
	if err != nil {
		ev.Decision, ev.Reason = logs.DecBlocked, "the security rules don't allow it ("+short(err)+")"
		p.log(ev)
		reset(c)
		return
	}
	p.passOn(ctx, c, raw, lc, ls, ev, server)
}

func (p *proxy) passOn(ctx context.Context, c net.Conn, raw []byte, lc, ls net.Conn, ev logs.Decryption, server netip.AddrPort) {
	up, err := p.dialUp(ctx, server)
	if err != nil {
		ev.Decision, ev.Reason = logs.DecFailed, "server unreachable: "+short(err)
		p.log(ev)
		reset(c)
		lc.Close()
		ls.Close()
		return
	}
	p.log(ev)
	// The hello goes first, then the rest of what the client sends.
	join(&replayConn{Conn: c, r: io.MultiReader(bytes.NewReader(raw), c)}, lc, ls, up)
}

// decrypt stands in the middle: TLS to the real server (whose certificate
// is checked), TLS to the client with a certificate the firewall issues,
// and the plaintext round the loop in between.
func (p *proxy) decrypt(ctx context.Context, st *state, c net.Conn, raw []byte, hello decrypt.Hello, ev logs.Decryption,
	rule decrypt.PolicyRule, client, server netip.AddrPort, dscp int) {
	fail := func(decision, reason string, conns ...net.Conn) {
		ev.Decision, ev.Reason = decision, reason
		p.log(ev)
		reset(c)
		for _, x := range conns {
			x.Close()
		}
	}
	lc, ls, err := p.openLoop(ctx, client, server, dscp)
	if err != nil {
		fail(logs.DecBlocked, "the security rules don't allow it ("+short(err)+")")
		return
	}
	rawUp, err := p.dialUp(ctx, server)
	if err != nil {
		fail(logs.DecFailed, "server unreachable: "+short(err), lc, ls)
		return
	}
	up := tls.Client(rawUp, &tls.Config{
		ServerName: hello.ServerName, NextProtos: inspectableALPN(hello.ALPN), MinVersion: tls.VersionTLS12,
		ClientSessionCache: p.sessions,
		// Checked below, so a bad certificate can be warned about
		// (re-signed with the untrusted CA) rather than only refused.
		InsecureSkipVerify: true,
	})
	if err := up.HandshakeContext(ctx); err != nil {
		rawUp.Close()
		// The server won't do TLS 1.2+ with us: treat it like any
		// connection that can't be decrypted.
		if rule.Unsupported == "block" {
			fail(logs.DecBlocked, "the server's TLS can't be decrypted: "+short(err), lc, ls)
			return
		}
		ev.Decision, ev.Reason = logs.DecPassed, "the server's TLS can't be decrypted: "+short(err)
		p.passOn(ctx, c, raw, lc, ls, ev, server)
		return
	}
	cs := up.ConnectionState()
	trusted, why := p.verify(cs, hello.ServerName)
	if !trusted && rule.BadCertificate == "block" {
		fail(logs.DecBlocked, "the server's certificate "+why, lc, ls, up)
		return
	}
	ca, notAfter := st.cas.Trusted, cs.PeerCertificates[0].NotAfter
	if !trusted {
		ca, notAfter = st.cas.Untrusted, time.Time{}
	}
	cert, err := p.certs.get(hello.ServerName, trusted, p.now(), func() (*tls.Certificate, error) {
		return decrypt.Forge(ca, p.leaf, []string{hello.ServerName}, notAfter, p.now())
	})
	if err != nil {
		fail(logs.DecFailed, "issuing a certificate: "+short(err), lc, ls, up)
		return
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{*cert}, MinVersion: tls.VersionTLS12}
	if cs.NegotiatedProtocol != "" {
		cfg.NextProtos = []string{cs.NegotiatedProtocol}
	}
	ct := tls.Server(&replayConn{Conn: c, r: io.MultiReader(bytes.NewReader(raw), c)}, cfg)
	if err := ct.HandshakeContext(ctx); err != nil {
		switch {
		case !trusted:
			fail(logs.DecBlocked, "the server's certificate "+why+": the client was shown the untrusted certificate and didn't accept it", lc, ls, up)
		case clientRejected(err) && rule.Pinned == "exclude":
			p.learned.Add(hello.ServerName, server.Addr().String(), p.now())
			fail(logs.DecLearned, "the client rejected the firewall's certificate (pinned app, or the CA isn't installed on it): passed through from now on", lc, ls, up)
		case clientRejected(err):
			fail(logs.DecBlocked, "the client rejected the firewall's certificate (pinned app, or the CA isn't installed on it)", lc, ls, up)
		default:
			fail(logs.DecFailed, "TLS with the client failed: "+short(err), lc, ls, up)
		}
		return
	}
	ev.Decision = logs.DecDecrypted
	if !trusted {
		ev.Reason = "the server's certificate " + why + ": re-signed with the untrusted CA, so the browser warns"
	}
	ev.TLS = map[uint16]string{tls.VersionTLS12: "1.2", tls.VersionTLS13: "1.3"}[ct.ConnectionState().Version]
	ev.ALPN = cs.NegotiatedProtocol
	p.log(ev)
	join(ct, lc, ls, up)
}

// inspectableALPN picks the application protocols to offer the server:
// HTTP/1.1 alone when the client offers it (App Identification and the IPS
// read HTTP/1.1 best; HTTP/2's compressed headers hide the host name from
// App Identification), otherwise what the client offered (e.g. h2-only
// gRPC).
func inspectableALPN(offered []string) []string {
	for _, p := range offered {
		if p == "http/1.1" {
			return []string{"http/1.1"}
		}
	}
	return offered
}

// verify checks the server's certificate chain against the roots, for the
// server name. why says what's wrong, in words.
func (p *proxy) verify(cs tls.ConnectionState, name string) (bool, string) {
	if len(cs.PeerCertificates) == 0 {
		return false, "is missing"
	}
	inter := x509.NewCertPool()
	for _, c := range cs.PeerCertificates[1:] {
		inter.AddCert(c)
	}
	_, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{Roots: p.roots, Intermediates: inter, DNSName: name, CurrentTime: p.now()})
	if err == nil {
		return true, ""
	}
	var ua x509.UnknownAuthorityError
	var hn x509.HostnameError
	var inv x509.CertificateInvalidError
	switch {
	case errors.As(err, &ua):
		return false, "is from an authority the firewall doesn't trust (self-signed?)"
	case errors.As(err, &hn):
		return false, "isn't for " + name
	case errors.As(err, &inv) && inv.Reason == x509.Expired:
		return false, "has expired or isn't valid yet"
	}
	return false, "failed the checks: " + short(err)
}

// clientRejected: the client turned the firewall's certificate down: an
// alert about it, or it hung up mid-handshake. A TLS 1.3 client that sends
// its alert before switching to the handshake keys (OpenSSL does) shows up
// here as a record that won't decrypt ("bad record MAC").
func clientRejected(err error) bool {
	s := err.Error()
	for _, w := range []string{"unknown certificate authority", "bad certificate", "certificate unknown", "unsupported certificate", "access denied", "bad record MAC"} {
		if strings.Contains(s, w) {
			return true
		}
	}
	return errors.Is(err, io.EOF) || strings.Contains(s, "connection reset")
}

func short(err error) string {
	s := err.Error()
	if len(s) > 160 {
		s = s[:160] + "…"
	}
	return s
}

// replayConn reads what was already read (the hello) before the rest.
type replayConn struct {
	net.Conn
	r io.Reader
}

func (c *replayConn) Read(b []byte) (int, error) { return c.r.Read(b) }

// CloseWrite passes a half-close on to the connection underneath.
func (c *replayConn) CloseWrite() error {
	if cw, ok := c.Conn.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}

type closeWriter interface{ CloseWrite() error }

// join pipes client <-> loop entry and loop exit <-> server until both
// directions end, passing half-closes on.
func join(client, loopIn, loopOut, server net.Conn) {
	var wg sync.WaitGroup
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		io.Copy(dst, src)
		if cw, ok := dst.(closeWriter); ok {
			cw.CloseWrite()
		} else {
			dst.Close()
		}
	}
	wg.Add(4)
	go cp(loopIn, client)
	go cp(client, loopIn)
	go cp(server, loopOut)
	go cp(loopOut, server)
	wg.Wait()
	for _, c := range []net.Conn{client, loopIn, loopOut, server} {
		c.Close()
	}
}

// certCache keeps forged certificates per server name.
type certCache struct {
	mu sync.Mutex
	m  map[string]cachedCert
}

type cachedCert struct {
	cert  *tls.Certificate
	until time.Time
}

const maxCachedCerts = 10000

func (cc *certCache) get(name string, trusted bool, now time.Time, make func() (*tls.Certificate, error)) (*tls.Certificate, error) {
	key := fmt.Sprintf("%s|%v", name, trusted)
	cc.mu.Lock()
	if e, ok := cc.m[key]; ok && now.Before(e.until) {
		cc.mu.Unlock()
		return e.cert, nil
	}
	cc.mu.Unlock()
	cert, err := make()
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, err
	}
	cc.mu.Lock()
	defer cc.mu.Unlock()
	if cc.m == nil || len(cc.m) >= maxCachedCerts {
		cc.m = map[string]cachedCert{}
	}
	// Reissue an hour before it runs out.
	cc.m[key] = cachedCert{cert: cert, until: leaf.NotAfter.Add(-time.Hour)}
	return cert, nil
}

// reset drops all cached certificates (the CA changed).
func (cc *certCache) reset() {
	cc.mu.Lock()
	cc.m = nil
	cc.mu.Unlock()
}
