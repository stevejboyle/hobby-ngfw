// Package mgmtcert manages the management certificate: the one the web UI
// (mgmt :443) and the tag API (:8443) present. First boot makes a
// self-signed one; operators may import their own (e.g. from a lab CA) and
// go back to a fresh self-signed one. The files live in /etc/ngfw, never in
// the config, a backup or a bundle.
//
// The listeners take their certificate from a Manager (GetCertificate), so
// an import changes what new connections get without a restart: existing
// connections, the one doing the import included, keep theirs.
package mgmtcert

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/stevejboyle/sjb-os/internal/decrypt"
)

// Sources.
const (
	SelfSigned = "self-signed"
	Imported   = "imported"
)

// sourceFile, beside the certificate, records how it got there. A missing
// file means first boot's self-signed certificate.
const sourceFile = "tls.source"

// ExpirySoon is how close to its end a certificate gets a warning.
const ExpirySoon = 30 * 24 * time.Hour

// Names are what the certificate should cover: the hostname and the
// management address(es) operators reach the firewall by.
type Names struct {
	Hostname string
	IPs      []netip.Addr
}

// Info describes the current certificate. It never includes the key.
type Info struct {
	Source      string    `json:"source"` // self-signed or imported
	Subject     string    `json:"subject"`
	Issuer      string    `json:"issuer"`
	DNSNames    []string  `json:"dns_names"`
	IPAddresses []string  `json:"ip_addresses"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	Fingerprint string    `json:"fingerprint"` // SHA-256, hex pairs
	Chain       int       `json:"chain"`       // intermediates sent after it
	Warnings    []string  `json:"warnings"`
	PEM         string    `json:"pem"` // the certificate and its chain
}

// Manager owns the certificate files and the certificate the listeners
// present.
type Manager struct {
	CertFile, KeyFile string
	Now               func() time.Time

	mu  sync.Mutex // serialises changes to the files
	cur atomic.Pointer[tls.Certificate]
}

func (m *Manager) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

func (m *Manager) sourcePath() string {
	return filepath.Join(filepath.Dir(m.CertFile), sourceFile)
}

// Load reads the files into the certificate the listeners present.
func (m *Manager) Load() error {
	c, err := tls.LoadX509KeyPair(m.CertFile, m.KeyFile)
	if err != nil {
		return err
	}
	m.cur.Store(&c)
	return nil
}

// LoadOrGenerate loads the files, or, when they are missing or don't make
// a pair (say a write was cut short), replaces them with a fresh
// self-signed certificate so the web UI always comes up. The error says
// what was wrong with the old files (nil if nothing was).
func (m *Manager) LoadOrGenerate(n Names) error {
	err := m.Load()
	if err == nil {
		return nil
	}
	if _, gerr := m.SelfSigned(n); gerr != nil {
		return fmt.Errorf("%v; a new self-signed certificate failed too: %w", err, gerr)
	}
	return err
}

// GetCertificate is for tls.Config: the current certificate.
func (m *Manager) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	if c := m.cur.Load(); c != nil {
		return c, nil
	}
	return nil, errors.New("no management certificate loaded")
}

// TLSConfig is the listeners' configuration.
func (m *Manager) TLSConfig() *tls.Config {
	return &tls.Config{GetCertificate: m.GetCertificate, MinVersion: tls.VersionTLS12}
}

// Info describes the certificate in use.
func (m *Manager) Info(n Names) (Info, error) {
	c := m.cur.Load()
	if c == nil || len(c.Certificate) == 0 {
		return Info{}, errors.New("no management certificate loaded")
	}
	var certs []*x509.Certificate
	for _, der := range c.Certificate {
		x, err := x509.ParseCertificate(der)
		if err != nil {
			return Info{}, err
		}
		certs = append(certs, x)
	}
	src := Imported
	if b, err := os.ReadFile(m.sourcePath()); err != nil || strings.TrimSpace(string(b)) != Imported {
		src = SelfSigned
	}
	return describe(certs[0], certs[1:], src, n, m.now()), nil
}

// Import checks an operator's certificate (PEM, first), its chain and its
// unencrypted key, writes them and presents them from the next connection.
// The checks are the decryption CA import's (decrypt.ParseKeyPair) plus a
// server certificate's: not a CA, usable for server authentication.
func (m *Manager) Import(certPEM, keyPEM []byte, n Names) (Info, error) {
	now := m.now()
	cert, chain, key, err := decrypt.ParseKeyPair(certPEM, keyPEM, now, serverCert)
	if err != nil {
		return Info{}, err
	}
	keyOut, err := decrypt.KeyPEM(key)
	if err != nil {
		return Info{}, err
	}
	if err := m.install(decrypt.CertPEM(append([]*x509.Certificate{cert}, chain...)...), keyOut, Imported); err != nil {
		return Info{}, err
	}
	return describe(cert, chain, Imported, n, now), nil
}

// serverCert checks a certificate is a server's.
func serverCert(c *x509.Certificate) error {
	if c.BasicConstraintsValid && c.IsCA {
		return errors.New("the certificate is a CA certificate (basic constraints CA:TRUE): give the firewall's own server certificate")
	}
	if len(c.ExtKeyUsage) > 0 && !slices.Contains(c.ExtKeyUsage, x509.ExtKeyUsageServerAuth) && !slices.Contains(c.ExtKeyUsage, x509.ExtKeyUsageAny) {
		return errors.New("the certificate is not for server authentication (extended key usage lacks TLS Web Server Authentication)")
	}
	if c.KeyUsage != 0 {
		ok := c.KeyUsage&x509.KeyUsageDigitalSignature != 0
		if c.PublicKeyAlgorithm == x509.RSA {
			ok = ok || c.KeyUsage&x509.KeyUsageKeyEncipherment != 0
		}
		if !ok {
			return errors.New("the certificate's key usage allows neither digital signature nor key encipherment, which TLS servers need")
		}
	}
	return nil
}

// SelfSigned replaces the certificate with a fresh self-signed one (ECDSA
// P-256, 10 years) naming the hostname and the management addresses.
func (m *Manager) SelfSigned(n Names) (Info, error) {
	now := m.now()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Info{}, err
	}
	sn, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return Info{}, err
	}
	host := n.Hostname
	if host == "" {
		host = "sjb-fw"
	}
	tmpl := &x509.Certificate{
		SerialNumber:          sn,
		Subject:               pkix.Name{CommonName: host, Organization: []string{"SJB-OS"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{host},
	}
	for _, ip := range n.IPs {
		tmpl.IPAddresses = append(tmpl.IPAddresses, net.IP(ip.AsSlice()))
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return Info{}, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return Info{}, err
	}
	keyOut, err := decrypt.KeyPEM(key)
	if err != nil {
		return Info{}, err
	}
	if err := m.install(decrypt.CertPEM(cert), keyOut, SelfSigned); err != nil {
		return Info{}, err
	}
	return describe(cert, nil, SelfSigned, n, now), nil
}

// install writes the files (key 0600) and presents the new pair. The pair
// is checked as tls would load it before anything is replaced.
func (m *Manager) install(certPEM, keyPEM []byte, source string) error {
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := writeAtomic(m.KeyFile, keyPEM, 0o600); err != nil {
		return err
	}
	if err := writeAtomic(m.CertFile, certPEM, 0o644); err != nil {
		return err
	}
	if err := writeAtomic(m.sourcePath(), []byte(source+"\n"), 0o644); err != nil {
		return err
	}
	m.cur.Store(&pair)
	return nil
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func describe(c *x509.Certificate, chain []*x509.Certificate, source string, n Names, now time.Time) Info {
	in := Info{
		Source:      source,
		Subject:     c.Subject.String(),
		Issuer:      c.Issuer.String(),
		DNSNames:    append([]string{}, c.DNSNames...),
		IPAddresses: []string{},
		NotBefore:   c.NotBefore,
		NotAfter:    c.NotAfter,
		Fingerprint: decrypt.Fingerprint(c.Raw),
		Chain:       len(chain),
		Warnings:    []string{},
		PEM:         string(decrypt.CertPEM(append([]*x509.Certificate{c}, chain...)...)),
	}
	for _, ip := range c.IPAddresses {
		in.IPAddresses = append(in.IPAddresses, ip.String())
	}
	in.Warnings = warnings(c, chain, n, now)
	return in
}

// warnings are what an operator should know but that doesn't stop an
// import: names the certificate doesn't cover, a missing chain, an end
// coming soon.
func warnings(c *x509.Certificate, chain []*x509.Certificate, n Names, now time.Time) []string {
	var w []string
	if len(c.DNSNames) == 0 && len(c.IPAddresses) == 0 {
		w = append(w, "the certificate has no subject alternative names; browsers ignore the common name and will warn")
	} else {
		var want []string
		covered := false
		if n.Hostname != "" {
			want = append(want, n.Hostname)
			covered = covered || c.VerifyHostname(n.Hostname) == nil
		}
		for _, ip := range n.IPs {
			want = append(want, ip.String())
			covered = covered || c.VerifyHostname(ip.String()) == nil
		}
		if len(want) > 0 && !covered {
			what := "doesn't name " + want[0]
			if len(want) == 2 {
				what = "names neither " + want[0] + " nor " + want[1]
			} else if len(want) > 2 {
				what = "names none of " + strings.Join(want, ", ")
			}
			w = append(w, fmt.Sprintf("the certificate %s; browsers warn unless you reach the firewall by a name it lists (%s)",
				what, strings.Join(sans(c), ", ")))
		}
	}
	if len(chain) == 0 && !bytes.Equal(c.RawIssuer, c.RawSubject) {
		w = append(w, fmt.Sprintf("no chain given: clients must trust the issuer (%s) directly", c.Issuer.String()))
	}
	if left := c.NotAfter.Sub(now); left < ExpirySoon {
		w = append(w, fmt.Sprintf("the certificate expires on %s", c.NotAfter.Format("2006-01-02")))
	}
	return w
}

func sans(c *x509.Certificate) []string {
	out := append([]string{}, c.DNSNames...)
	for _, ip := range c.IPAddresses {
		out = append(out, ip.String())
	}
	return out
}
