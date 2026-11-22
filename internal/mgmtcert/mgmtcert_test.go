package mgmtcert

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)

type cert struct {
	c   *x509.Certificate
	key crypto.Signer
}

func (c cert) pem() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.c.Raw})
}

func (c cert) keyPEM(t *testing.T) []byte {
	der, err := x509.MarshalPKCS8PrivateKey(c.key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func mk(t *testing.T, tmpl *x509.Certificate, parent *cert, key crypto.Signer) cert {
	t.Helper()
	if key == nil {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		key = k
	}
	tmpl.SerialNumber = big.NewInt(time.Now().UnixNano())
	if tmpl.NotBefore.IsZero() {
		tmpl.NotBefore = now.AddDate(0, -1, 0)
	}
	if tmpl.NotAfter.IsZero() {
		tmpl.NotAfter = now.AddDate(1, 0, 0)
	}
	signer, p := key, tmpl
	if parent != nil {
		signer, p = parent.key, parent.c
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p, key.Public(), signer)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert{c, key}
}

// lab is a root, an issuing CA under it and a server certificate from that.
func lab(t *testing.T, leaf *x509.Certificate) (root, issuing, server cert) {
	ca := func(cn string) *x509.Certificate {
		return &x509.Certificate{Subject: pkix.Name{CommonName: cn}, IsCA: true, BasicConstraintsValid: true,
			KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	}
	root = mk(t, ca("Lab Root"), nil, nil)
	issuing = mk(t, ca("Lab Issuing CA"), &root, nil)
	if leaf == nil {
		leaf = &x509.Certificate{Subject: pkix.Name{CommonName: "sjb-fw.lab"}, DNSNames: []string{"sjb-fw.lab", "sjb-fw"},
			IPAddresses: []net.IP{net.ParseIP("192.168.1.75")},
			KeyUsage:    x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	}
	server = mk(t, leaf, &issuing, nil)
	return
}

func manager(t *testing.T) *Manager {
	d := t.TempDir()
	return &Manager{CertFile: filepath.Join(d, "tls.crt"), KeyFile: filepath.Join(d, "tls.key"), Now: func() time.Time { return now }}
}

var names = Names{Hostname: "sjb-fw", IPs: []netip.Addr{netip.MustParseAddr("192.168.1.75")}}

func TestImportLabChain(t *testing.T) {
	m := manager(t)
	if _, err := m.SelfSigned(names); err != nil {
		t.Fatal(err)
	}
	before, _ := m.Info(names)
	_, issuing, server := lab(t, nil)
	in, err := m.Import(append(server.pem(), issuing.pem()...), server.keyPEM(t), names)
	if err != nil {
		t.Fatal(err)
	}
	if in.Source != Imported || in.Chain != 1 || len(in.Warnings) != 0 || in.Fingerprint == before.Fingerprint {
		t.Fatalf("info %+v", in)
	}
	// The listeners present it now, chain included.
	c, err := m.GetCertificate(nil)
	if err != nil || len(c.Certificate) != 2 {
		t.Fatalf("presented %v %v", c, err)
	}
	if got, _ := m.Info(names); got.Fingerprint != in.Fingerprint || got.Source != Imported {
		t.Fatalf("Info after import %+v", got)
	}
	st, err := os.Stat(m.KeyFile)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("key file %v %v", st, err)
	}
	// A fresh Manager (ngfwd restarting) loads the same pair.
	m2 := &Manager{CertFile: m.CertFile, KeyFile: m.KeyFile}
	if err := m2.Load(); err != nil {
		t.Fatal(err)
	}
	if got, _ := m2.Info(names); got.Fingerprint != in.Fingerprint {
		t.Fatal("reloaded a different certificate")
	}
	// Back to self-signed: a new certificate naming the firewall.
	ss, err := m.SelfSigned(names)
	if err != nil {
		t.Fatal(err)
	}
	if ss.Source != SelfSigned || ss.Fingerprint == in.Fingerprint || ss.Fingerprint == before.Fingerprint ||
		strings.Join(ss.DNSNames, ",") != "sjb-fw" || strings.Join(ss.IPAddresses, ",") != "192.168.1.75" || len(ss.Warnings) != 0 {
		t.Fatalf("self-signed %+v", ss)
	}
}

func TestImportRefusals(t *testing.T) {
	root, issuing, server := lab(t, nil)
	_, _, other := lab(t, nil)
	rsaSmall, _ := rsa.GenerateKey(rand.Reader, 1024)
	small := mk(t, &x509.Certificate{Subject: pkix.Name{CommonName: "small"}, DNSNames: []string{"sjb-fw"}}, &issuing, rsaSmall)
	clientOnly := mk(t, &x509.Certificate{Subject: pkix.Name{CommonName: "c"}, DNSNames: []string{"sjb-fw"},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}, &issuing, nil)
	certSignOnly := mk(t, &x509.Certificate{Subject: pkix.Name{CommonName: "k"}, DNSNames: []string{"sjb-fw"},
		KeyUsage: x509.KeyUsageCertSign}, &issuing, nil)
	expired := mk(t, &x509.Certificate{Subject: pkix.Name{CommonName: "old"}, DNSNames: []string{"sjb-fw"},
		NotBefore: now.AddDate(-2, 0, 0), NotAfter: now.AddDate(0, 0, -1)}, &issuing, nil)
	encrypted := pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte{1}})
	for _, tc := range []struct {
		name      string
		cert, key []byte
		want      string
	}{
		{"CA", issuing.pem(), issuing.keyPEM(t), "CA certificate"},
		{"chain order", append(append(server.pem(), root.pem()...), issuing.pem()...), server.keyPEM(t), "didn't sign"},
		{"wrong key", server.pem(), other.keyPEM(t), "does not belong"},
		{"encrypted key", server.pem(), encrypted, "encrypted"},
		{"small RSA", small.pem(), small.keyPEM(t), "2048"},
		{"client auth only", clientOnly.pem(), clientOnly.keyPEM(t), "server authentication"},
		{"key usage", certSignOnly.pem(), certSignOnly.keyPEM(t), "key usage"},
		{"expired", expired.pem(), expired.keyPEM(t), "expired"},
		{"no PEM", []byte("hello"), server.keyPEM(t), "no PEM certificate"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := manager(t)
			m.SelfSigned(names)
			before, _ := m.Info(names)
			_, err := m.Import(tc.cert, tc.key, names)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err %v, want %q", err, tc.want)
			}
			if after, _ := m.Info(names); after.Fingerprint != before.Fingerprint {
				t.Fatal("a refused import changed the certificate")
			}
		})
	}
}

func TestImportWarnings(t *testing.T) {
	_, issuing, server := lab(t, &x509.Certificate{Subject: pkix.Name{CommonName: "www"}, DNSNames: []string{"www.example.test"},
		NotAfter: now.AddDate(0, 0, 10)})
	in, err := manager(t).Import(server.pem(), server.keyPEM(t), names)
	if err != nil {
		t.Fatal(err)
	}
	w := strings.Join(in.Warnings, "|")
	for _, want := range []string{"names neither sjb-fw nor 192.168.1.75", "no chain given", "expires on"} {
		if !strings.Contains(w, want) {
			t.Errorf("warnings %q lack %q", w, want)
		}
	}
	_ = issuing
}

func TestLoadOrGenerate(t *testing.T) {
	m := manager(t)
	os.WriteFile(m.CertFile, []byte("garbage"), 0o644)
	if err := m.LoadOrGenerate(names); err == nil {
		t.Fatal("expected the old files' error")
	}
	if _, err := m.GetCertificate(nil); err != nil {
		t.Fatal(err)
	}
	if _, err := tls.LoadX509KeyPair(m.CertFile, m.KeyFile); err != nil {
		t.Fatal(err)
	}
}
