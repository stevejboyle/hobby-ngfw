package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stevejboyle/sjb-os/internal/cliconf"
)

// A CA pasted on one line in configure mode (as the boot test does it)
// arrives as one word and validates.
func TestLogServerCAOnOneLine(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "log CA"}, NotBefore: time.Now(),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	ca := strings.ReplaceAll(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), "\n", " ")
	w, err := splitWords(`set log-server siem address 10.0.0.50 server-name siem.lab ca "` + ca + `"`)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile("../../examples/basic.yaml")
	m, err := cliconf.LoadYAML(data)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Set(w[1:]); err != nil {
		t.Fatal(err)
	}
	c, err := m.Config()
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(c.LogServers[0].CA, "-----BEGIN CERTIFICATE----- ") {
		t.Fatalf("ca %q", c.LogServers[0].CA[:40])
	}
}
