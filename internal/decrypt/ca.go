package decrypt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// CADir is where the decryption CA lives on the appliance. Upgrades never
// touch /etc/ngfw; the key is readable only by tlsd's user.
const CADir = "/etc/ngfw/decryption"

// Files in CADir.
const (
	caCert        = "ca.crt"
	caKey         = "ca.key"
	untrustedCert = "untrusted.crt"
	untrustedKey  = "untrusted.key"
	caSource      = "source" // "generated" or "imported"
)

// CA is a certificate authority tlsd signs with.
type CA struct {
	Cert *x509.Certificate
	Key  crypto.Signer
}

// CAs are the decryption CA (clients trust it) and the untrusted CA (no
// client trusts it: sites whose own certificate is bad are re-signed with
// it, so the browser shows its usual warning).
type CAs struct {
	Trusted   CA
	Untrusted CA
	Source    string
}

// CAInfo describes the decryption CA for show decryption and the web UI.
// It never includes the key.
type CAInfo struct {
	Present     bool      `json:"present"`
	Source      string    `json:"source,omitempty"` // generated or imported
	Subject     string    `json:"subject,omitempty"`
	Fingerprint string    `json:"fingerprint,omitempty"` // SHA-256 of the certificate, hex pairs
	NotBefore   time.Time `json:"not_before,omitzero"`
	NotAfter    time.Time `json:"not_after,omitzero"`
	PEM         string    `json:"pem,omitempty"`
}

// Owner is who the files belong to (tlsd's user); -1 leaves them as created.
type Owner struct{ UID, GID int }

// NoOwner keeps files owned by the writer (tests, development).
var NoOwner = Owner{-1, -1}

// Fingerprint is a certificate's SHA-256 in colon-separated hex pairs.
func Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	h := strings.ToUpper(hex.EncodeToString(sum[:]))
	var parts []string
	for i := 0; i < len(h); i += 2 {
		parts = append(parts, h[i:i+2])
	}
	return strings.Join(parts, ":")
}

func serial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
}

func newCA(cn string, now time.Time, years int) (CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return CA{}, err
	}
	sn, err := serial()
	if err != nil {
		return CA{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          sn,
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"SJB-OS"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(years, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return CA{}, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return CA{}, err
	}
	return CA{Cert: cert, Key: key}, nil
}

// GenerateCA makes a new decryption CA (valid 5 years) and untrusted CA in
// dir, replacing any there.
func GenerateCA(dir, hostname string, now time.Time, o Owner) (CAInfo, error) {
	if hostname == "" {
		hostname = "sjb-fw"
	}
	tr, err := newCA(fmt.Sprintf("SJB-OS Decryption CA (%s)", hostname), now, 5)
	if err != nil {
		return CAInfo{}, err
	}
	un, err := newCA("SJB-OS Untrusted: this site's own certificate failed the firewall's checks", now, 5)
	if err != nil {
		return CAInfo{}, err
	}
	if err := writeCAs(dir, tr, un, "generated", o); err != nil {
		return CAInfo{}, err
	}
	return InfoOf(CAs{Trusted: tr, Untrusted: un, Source: "generated"}), nil
}

// ImportCA installs an operator's CA (PEM certificate and key, e.g. a
// subordinate CA from their own PKI) in dir, with a fresh untrusted CA.
func ImportCA(dir string, certPEM, keyPEM []byte, now time.Time, o Owner) (CAInfo, error) {
	cert, err := parseCert(certPEM)
	if err != nil {
		return CAInfo{}, err
	}
	switch {
	case !cert.IsCA || !cert.BasicConstraintsValid:
		return CAInfo{}, errors.New("the certificate is not a CA certificate (basic constraints CA:TRUE)")
	case cert.KeyUsage != 0 && cert.KeyUsage&x509.KeyUsageCertSign == 0:
		return CAInfo{}, errors.New("the certificate may not sign certificates (key usage lacks certificate signing)")
	case now.After(cert.NotAfter):
		return CAInfo{}, fmt.Errorf("the certificate expired on %s", cert.NotAfter.Format("2006-01-02"))
	case now.Before(cert.NotBefore):
		return CAInfo{}, fmt.Errorf("the certificate is not valid until %s", cert.NotBefore.Format("2006-01-02"))
	}
	key, err := parseKey(keyPEM)
	if err != nil {
		return CAInfo{}, err
	}
	if !samePublic(cert.PublicKey, key.Public()) {
		return CAInfo{}, errors.New("the key does not belong to the certificate")
	}
	un, err := newCA("SJB-OS Untrusted: this site's own certificate failed the firewall's checks", now, 5)
	if err != nil {
		return CAInfo{}, err
	}
	tr := CA{Cert: cert, Key: key}
	if err := writeCAs(dir, tr, un, "imported", o); err != nil {
		return CAInfo{}, err
	}
	return InfoOf(CAs{Trusted: tr, Untrusted: un, Source: "imported"}), nil
}

func samePublic(a, b crypto.PublicKey) bool {
	type eq interface{ Equal(crypto.PublicKey) bool }
	x, ok := a.(eq)
	return ok && x.Equal(b)
}

func parseCert(p []byte) (*x509.Certificate, error) {
	for {
		var blk *pem.Block
		blk, p = pem.Decode(p)
		if blk == nil {
			return nil, errors.New("no PEM certificate found (-----BEGIN CERTIFICATE-----)")
		}
		if blk.Type == "CERTIFICATE" {
			c, err := x509.ParseCertificate(blk.Bytes)
			if err != nil {
				return nil, fmt.Errorf("certificate: %v", err)
			}
			return c, nil
		}
	}
}

func parseKey(p []byte) (crypto.Signer, error) {
	for {
		var blk *pem.Block
		blk, p = pem.Decode(p)
		if blk == nil {
			return nil, errors.New("no PEM private key found (an unencrypted key: -----BEGIN PRIVATE KEY-----)")
		}
		if strings.Contains(blk.Type, "ENCRYPTED") || blk.Headers["Proc-Type"] != "" {
			return nil, errors.New("the key is encrypted; give it without a passphrase")
		}
		var k any
		var err error
		switch blk.Type {
		case "PRIVATE KEY":
			k, err = x509.ParsePKCS8PrivateKey(blk.Bytes)
		case "EC PRIVATE KEY":
			k, err = x509.ParseECPrivateKey(blk.Bytes)
		case "RSA PRIVATE KEY":
			k, err = x509.ParsePKCS1PrivateKey(blk.Bytes)
		default:
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("private key: %v", err)
		}
		switch s := k.(type) {
		case *ecdsa.PrivateKey:
			return s, nil
		case *rsa.PrivateKey:
			if s.N.BitLen() < 2048 {
				return nil, errors.New("RSA keys must be at least 2048 bits")
			}
			return s, nil
		}
		return nil, fmt.Errorf("unsupported key type %T (use ECDSA or RSA)", k)
	}
}

func certPEM(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

func keyPEM(k crypto.Signer) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// writeCAs writes both CAs; keys 0600, certificates 0644, all owned by o.
func writeCAs(dir string, tr, un CA, source string, o Owner) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	if o.UID >= 0 {
		if err := os.Chown(dir, 0, o.GID); err != nil {
			return err
		}
	}
	trKey, err := keyPEM(tr.Key)
	if err != nil {
		return err
	}
	unKey, err := keyPEM(un.Key)
	if err != nil {
		return err
	}
	// Keys first: a reader never sees a certificate without its key.
	for _, f := range []struct {
		name string
		data []byte
		mode os.FileMode
	}{
		{caKey, trKey, 0o600}, {untrustedKey, unKey, 0o600},
		{caCert, certPEM(tr.Cert), 0o644}, {untrustedCert, certPEM(un.Cert), 0o644},
		{caSource, []byte(source + "\n"), 0o644},
	} {
		if err := writeFile(filepath.Join(dir, f.name), f.data, f.mode, o); err != nil {
			return err
		}
	}
	return nil
}

func writeFile(path string, data []byte, mode os.FileMode, o Owner) error {
	tmp := path + ".new"
	os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if o.UID >= 0 {
		if err := os.Chown(tmp, o.UID, o.GID); err != nil {
			os.Remove(tmp)
			return err
		}
	}
	return os.Rename(tmp, path)
}

// LoadCAs reads both CAs from dir. os.ErrNotExist means none yet.
func LoadCAs(dir string) (CAs, error) {
	load := func(certName, keyName string) (CA, error) {
		cp, err := os.ReadFile(filepath.Join(dir, certName))
		if err != nil {
			return CA{}, err
		}
		kp, err := os.ReadFile(filepath.Join(dir, keyName))
		if err != nil {
			return CA{}, err
		}
		c, err := parseCert(cp)
		if err != nil {
			return CA{}, err
		}
		k, err := parseKey(kp)
		if err != nil {
			return CA{}, err
		}
		if !samePublic(c.PublicKey, k.Public()) {
			return CA{}, fmt.Errorf("%s: the key does not belong to the certificate", keyName)
		}
		return CA{Cert: c, Key: k}, nil
	}
	tr, err := load(caCert, caKey)
	if err != nil {
		return CAs{}, err
	}
	un, err := load(untrustedCert, untrustedKey)
	if err != nil {
		return CAs{}, err
	}
	src, _ := os.ReadFile(filepath.Join(dir, caSource))
	return CAs{Trusted: tr, Untrusted: un, Source: strings.TrimSpace(string(src))}, nil
}

// ReadCAInfo describes the CA in dir from its certificate alone (ngfwd
// reads this; only tlsd needs the key).
func ReadCAInfo(dir string) CAInfo {
	cp, err := os.ReadFile(filepath.Join(dir, caCert))
	if err != nil {
		return CAInfo{}
	}
	c, err := parseCert(cp)
	if err != nil {
		return CAInfo{}
	}
	src, _ := os.ReadFile(filepath.Join(dir, caSource))
	return info(c, strings.TrimSpace(string(src)))
}

// InfoOf describes cas.
func InfoOf(cas CAs) CAInfo { return info(cas.Trusted.Cert, cas.Source) }

func info(c *x509.Certificate, source string) CAInfo {
	return CAInfo{Present: true, Source: source, Subject: c.Subject.String(), Fingerprint: Fingerprint(c.Raw),
		NotBefore: c.NotBefore, NotAfter: c.NotAfter, PEM: string(certPEM(c))}
}

// Forge issues a leaf certificate for names, signed by ca, valid until
// notAfter (at most 7 days). leaf is the key every forged certificate
// shares (generated when tlsd starts, never written to disk).
func Forge(ca CA, leaf crypto.Signer, names []string, notAfter, now time.Time) (*tls.Certificate, error) {
	if len(names) == 0 {
		return nil, errors.New("no server name to issue a certificate for")
	}
	if max := now.Add(7 * 24 * time.Hour); notAfter.After(max) || notAfter.IsZero() {
		notAfter = max
	}
	if notAfter.After(ca.Cert.NotAfter) {
		notAfter = ca.Cert.NotAfter
	}
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          sn,
		Subject:               pkix.Name{CommonName: names[0]},
		DNSNames:              names,
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, leaf.Public(), ca.Key)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{der, ca.Cert.Raw}, PrivateKey: leaf}, nil
}
