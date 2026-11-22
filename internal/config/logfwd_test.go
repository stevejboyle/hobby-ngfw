package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func testCAPEM(t *testing.T) string {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestValidLogServers(t *testing.T) {
	ca := testCAPEM(t)
	c := base()
	c.LogServers = []LogServer{
		{Name: "siem", Address: "10.0.0.50"},
		{Name: "siem-tls", Address: "10.0.0.51", ServerName: "siem.lab", CA: ca, Types: []string{"threat", "system"}},
		{Name: "udp-cef", Address: "192.0.2.10", Transport: "udp", Format: "cef", VRF: "default", Facility: "local5", Port: 5140},
		{Name: "one-line-ca", Address: "10.0.0.52", CA: strings.ReplaceAll(ca, "\n", " ")},
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	l := c.LogServers[0]
	if l.TransportOrDefault() != "tls" || l.FormatOrDefault() != "json" || l.PortOrDefault() != 6514 ||
		l.VRFOrDefault() != "mgmt" || l.FacilityOrDefault() != "local0" || len(l.TypesOrDefault()) != 4 {
		t.Errorf("defaults: %+v", l)
	}
	if c.LogServers[2].PortOrDefault() != 5140 || (LogServer{Transport: "tcp"}).PortOrDefault() != 514 {
		t.Error("ports")
	}
	if !c.LogServers[1].Sends("threat") || c.LogServers[1].Sends("traffic") {
		t.Error("Sends")
	}
}

func TestInvalidLogServers(t *testing.T) {
	ca := testCAPEM(t)
	cases := []struct {
		name string
		l    []LogServer
		want string
	}{
		{"no address", []LogServer{{Name: "a"}}, "address required"},
		{"ipv6", []LogServer{{Name: "a", Address: "2001:db8::1"}}, "must be an IPv4 address"},
		{"hostname", []LogServer{{Name: "a", Address: "siem.lab"}}, "must be an IPv4 address"},
		{"multicast", []LogServer{{Name: "a", Address: "224.0.0.1"}}, "can't be a log server"},
		{"port", []LogServer{{Name: "a", Address: "10.0.0.5", Port: 70000}}, "port must be"},
		{"transport", []LogServer{{Name: "a", Address: "10.0.0.5", Transport: "relp"}}, "transport must be"},
		{"format", []LogServer{{Name: "a", Address: "10.0.0.5", Format: "leef"}}, "format must be"},
		{"type", []LogServer{{Name: "a", Address: "10.0.0.5", Types: []string{"audit"}}}, "unknown log type"},
		{"type twice", []LogServer{{Name: "a", Address: "10.0.0.5", Types: []string{"threat", "threat"}}}, "listed twice"},
		{"vrf", []LogServer{{Name: "a", Address: "10.0.0.5", VRF: "blue"}}, "vrf must be"},
		{"facility", []LogServer{{Name: "a", Address: "10.0.0.5", Facility: "kern"}}, "unknown facility"},
		{"ca on udp", []LogServer{{Name: "a", Address: "10.0.0.5", Transport: "udp", CA: ca}}, "ca applies to transport tls only"},
		{"name on tcp", []LogServer{{Name: "a", Address: "10.0.0.5", Transport: "tcp", ServerName: "x"}}, "server_name applies"},
		{"bad ca", []LogServer{{Name: "a", Address: "10.0.0.5", CA: "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"}}, "ca:"},
		{"not pem", []LogServer{{Name: "a", Address: "10.0.0.5", CA: "hello"}}, "no PEM certificate"},
		{"dup name", []LogServer{{Name: "a", Address: "10.0.0.5"}, {Name: "a", Address: "10.0.0.6"}}, "duplicate name"},
		{"dup target", []LogServer{{Name: "a", Address: "10.0.0.5"}, {Name: "b", Address: "10.0.0.5", Port: 6514}}, `same server, port, transport and VRF as "a"`},
		{"bad name", []LogServer{{Name: "a b", Address: "10.0.0.5"}}, "invalid name"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := base()
			c.LogServers = tc.l
			err := c.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
			if !strings.Contains(err.Error(), "log_servers[") {
				t.Errorf("error lacks its path: %v", err)
			}
		})
	}
	c := base()
	for i := 0; i <= MaxLogServers; i++ {
		c.LogServers = append(c.LogServers, LogServer{Name: string(rune('a' + i)), Address: "10.0.0." + string(rune('1'+i))})
	}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "at most 8") {
		t.Fatalf("cap: %v", err)
	}
}

func TestNormalizePEM(t *testing.T) {
	ca := testCAPEM(t)
	one := strings.ReplaceAll(ca, "\n", " ")
	if got := NormalizePEM(one); got != strings.TrimSpace(ca) {
		t.Errorf("one line:\n%s\nwant\n%s", got, ca)
	}
	if NormalizePEM(ca) != strings.TrimSpace(ca) {
		t.Error("multi-line changed")
	}
}
