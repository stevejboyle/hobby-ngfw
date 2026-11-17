package decrypt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)

func TestGenerateAndLoad(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "decryption")
	info, err := GenerateCA(dir, "sjb-lab", now, NoOwner)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Present || info.Source != "generated" || !strings.Contains(info.Subject, "SJB-OS Decryption CA (sjb-lab)") ||
		len(info.Fingerprint) != 95 || !info.NotAfter.Equal(now.AddDate(5, 0, 0)) || !strings.HasPrefix(info.PEM, "-----BEGIN CERTIFICATE-----") {
		t.Fatalf("info: %+v", info)
	}
	for name, mode := range map[string]os.FileMode{"ca.key": 0o600, "untrusted.key": 0o600, "ca.crt": 0o644} {
		st, err := os.Stat(filepath.Join(dir, name))
		if err != nil || st.Mode().Perm() != mode {
			t.Errorf("%s: mode %v, want %v (%v)", name, st.Mode().Perm(), mode, err)
		}
	}
	cas, err := LoadCAs(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !cas.Trusted.Cert.IsCA || cas.Untrusted.Cert.Equal(cas.Trusted.Cert) {
		t.Fatal("two distinct CAs expected")
	}
	if got := ReadCAInfo(dir); got.Fingerprint != info.Fingerprint || got.Source != "generated" {
		t.Fatalf("ReadCAInfo: %+v", got)
	}
	if got := ReadCAInfo(t.TempDir()); got.Present {
		t.Fatal("no CA should read as absent")
	}
	if _, err := LoadCAs(t.TempDir()); !os.IsNotExist(err) {
		t.Fatalf("missing CA: %v", err)
	}
}

// Forged certificates chain to the CA, name the server, and live at most a
// week; the untrusted CA's don't verify against the trusted CA.
func TestForge(t *testing.T) {
	dir := t.TempDir()
	if _, err := GenerateCA(dir, "fw", now, NoOwner); err != nil {
		t.Fatal(err)
	}
	cas, _ := LoadCAs(dir)
	leaf, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tc, err := Forge(cas.Trusted, leaf, []string{"www.example.com"}, now.AddDate(1, 0, 0), now)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(tc.Certificate[0])
	roots := x509.NewCertPool()
	roots.AddCert(cas.Trusted.Cert)
	if _, err := c.Verify(x509.VerifyOptions{Roots: roots, DNSName: "www.example.com", CurrentTime: now}); err != nil {
		t.Fatalf("forged cert should verify: %v", err)
	}
	if !c.NotAfter.Equal(now.Add(7 * 24 * time.Hour)) {
		t.Fatalf("validity capped at 7 days, got %v", c.NotAfter)
	}
	soon := now.Add(48 * time.Hour)
	tc, _ = Forge(cas.Trusted, leaf, []string{"a.example"}, soon, now)
	c, _ = x509.ParseCertificate(tc.Certificate[0])
	if !c.NotAfter.Equal(soon) {
		t.Fatalf("validity should follow the real certificate's, got %v", c.NotAfter)
	}
	tc, _ = Forge(cas.Untrusted, leaf, []string{"bad.example"}, soon, now)
	c, _ = x509.ParseCertificate(tc.Certificate[0])
	if _, err := c.Verify(x509.VerifyOptions{Roots: roots, DNSName: "bad.example", CurrentTime: now}); err == nil {
		t.Fatal("untrusted CA's certificate must not verify against the trusted CA")
	}
	if _, err := Forge(cas.Trusted, leaf, nil, soon, now); err == nil {
		t.Fatal("no names should fail")
	}
}

func pemOf(typ string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}

func selfSigned(t *testing.T, isCA bool, notAfter time.Time) ([]byte, []byte, *ecdsa.PrivateKey) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "Lab Sub CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: notAfter, IsCA: isCA, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	k, _ := x509.MarshalPKCS8PrivateKey(key)
	return pemOf("CERTIFICATE", der), pemOf("PRIVATE KEY", k), key
}

func TestImport(t *testing.T) {
	certP, keyP, _ := selfSigned(t, true, now.AddDate(2, 0, 0))
	dir := t.TempDir()
	info, err := ImportCA(dir, certP, keyP, now, NoOwner)
	if err != nil {
		t.Fatal(err)
	}
	if info.Source != "imported" || !strings.Contains(info.Subject, "Lab Sub CA") {
		t.Fatalf("info: %+v", info)
	}
	if _, err := LoadCAs(dir); err != nil {
		t.Fatal(err)
	}
	_, otherKey, _ := selfSigned(t, true, now.AddDate(2, 0, 0))
	leafCert, leafKey, _ := selfSigned(t, false, now.AddDate(2, 0, 0))
	oldCert, oldKey, _ := selfSigned(t, true, now.Add(-time.Minute))
	for name, tc := range map[string]struct {
		cert, key []byte
		want      string
	}{
		"wrong key": {certP, otherKey, "does not belong"},
		"not a CA":  {leafCert, leafKey, "not a CA certificate"},
		"expired":   {oldCert, oldKey, "expired"},
		"no cert":   {[]byte("hello"), keyP, "no PEM certificate"},
		"no key":    {certP, []byte("nope"), "no PEM private key"},
		"encrypted": {certP, pemOf("ENCRYPTED PRIVATE KEY", []byte{1}), "encrypted"},
	} {
		if _, err := ImportCA(t.TempDir(), tc.cert, tc.key, now, NoOwner); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: want %q, got %v", name, tc.want, err)
		}
	}
}

// A subordinate CA imported with its intermediate: issued certificates
// carry the chain, so a client trusting only the root verifies them.
func TestImportSubordinateChain(t *testing.T) {
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mk := func(cn string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, pub *ecdsa.PublicKey) *x509.Certificate {
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
			NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(1, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
		if parent == nil {
			parent = tmpl
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, parentKey)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := x509.ParseCertificate(der)
		return c
	}
	root := mk("Lab Root", nil, rootKey, &rootKey.PublicKey)
	interKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	inter := mk("Lab Intermediate", root, rootKey, &interKey.PublicKey)
	subKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sub := mk("Lab Firewall Sub CA", inter, interKey, &subKey.PublicKey)
	k, _ := x509.MarshalPKCS8PrivateKey(subKey)
	dir := t.TempDir()
	bundle := append(pemOf("CERTIFICATE", sub.Raw), pemOf("CERTIFICATE", inter.Raw)...)
	if _, err := ImportCA(dir, bundle, pemOf("PRIVATE KEY", k), now, NoOwner); err != nil {
		t.Fatal(err)
	}
	cas, err := LoadCAs(dir)
	if err != nil || len(cas.Trusted.Chain) != 1 {
		t.Fatalf("chain not kept: %v %d", err, len(cas.Trusted.Chain))
	}
	leaf, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tc, err := Forge(cas.Trusted, leaf, []string{"x.example"}, now.AddDate(0, 0, 3), now)
	if err != nil || len(tc.Certificate) != 3 {
		t.Fatalf("forged chain: %v %d", err, len(tc.Certificate))
	}
	c, _ := x509.ParseCertificate(tc.Certificate[0])
	inters := x509.NewCertPool()
	for _, der := range tc.Certificate[1:] {
		ic, _ := x509.ParseCertificate(der)
		inters.AddCert(ic)
	}
	if _, err := c.Verify(x509.VerifyOptions{Roots: roots(root), Intermediates: inters, DNSName: "x.example", CurrentTime: now}); err != nil {
		t.Fatalf("a client trusting only the root should verify: %v", err)
	}
	// Out of order: refused with a plain explanation.
	wrong := append(pemOf("CERTIFICATE", inter.Raw), pemOf("CERTIFICATE", sub.Raw)...)
	if _, err := ImportCA(t.TempDir(), wrong, pemOf("PRIVATE KEY", k), now, NoOwner); err == nil || !strings.Contains(err.Error(), "in order") && !strings.Contains(err.Error(), "does not belong") {
		t.Fatalf("out-of-order chain: %v", err)
	}
}

func roots(cs ...*x509.Certificate) *x509.CertPool {
	p := x509.NewCertPool()
	for _, c := range cs {
		p.AddCert(c)
	}
	return p
}

// CA names stay within X.509's 64-character limit on a common name, even
// for the longest hostname, and keep the prefixes clients and tools match.
func TestCANamesFit(t *testing.T) {
	long := strings.Repeat("h", 63) // the longest DNS label
	for _, host := range []string{"sjb-fw", long} {
		dir := filepath.Join(t.TempDir(), "decryption")
		if _, err := GenerateCA(dir, host, now, NoOwner); err != nil {
			t.Fatal(err)
		}
		cas, err := LoadCAs(dir)
		if err != nil {
			t.Fatal(err)
		}
		tr, un := cas.Trusted.Cert.Subject.CommonName, cas.Untrusted.Cert.Subject.CommonName
		if len(tr) > maxCN || len(un) > maxCN {
			t.Errorf("host %d chars: names %d and %d chars, want at most %d: %q, %q", len(host), len(tr), len(un), maxCN, tr, un)
		}
		if !strings.HasPrefix(tr, "SJB-OS Decryption CA (") || !strings.HasSuffix(tr, ")") || !strings.HasPrefix(un, "SJB-OS Untrusted") {
			t.Errorf("names lost their prefixes: %q, %q", tr, un)
		}
	}
	if got := trustedCN("sjb-fw"); got != "SJB-OS Decryption CA (sjb-fw)" {
		t.Errorf("short hostname changed: %q", got)
	}
}
