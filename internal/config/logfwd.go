package config

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// LogServer is a syslog server the appliance forwards logs to (RFC 5424
// over UDP, TCP or TLS; JSON or CEF message bodies).
type LogServer struct {
	Name    string `yaml:"name" json:"name"`
	Address string `yaml:"address" json:"address"` // IPv4 address
	// Port defaults by transport: 6514 for tls, 514 for tcp and udp.
	Port      int    `yaml:"port,omitempty" json:"port"`
	Transport string `yaml:"transport,omitempty" json:"transport"` // tls (default), tcp or udp
	Format    string `yaml:"format,omitempty" json:"format"`       // json (default) or cef
	// Types are the logs sent: traffic, threat, decryption, system (empty: all).
	Types []string `yaml:"types,omitempty" json:"types"`
	// VRF the connection leaves from: mgmt (default) or default.
	VRF      string `yaml:"vrf,omitempty" json:"vrf"`
	Facility string `yaml:"facility,omitempty" json:"facility"` // syslog facility, default local0
	// ServerName (tls) is the name checked on the server's certificate
	// (default: the address).
	ServerName string `yaml:"server_name,omitempty" json:"server_name"`
	// CA (tls) is a PEM certificate the server's chain must lead to; empty
	// means the system's trusted roots.
	CA string `yaml:"ca,omitempty" json:"ca"`
}

// Log forwarding transports, formats and types.
const (
	LogTLS = "tls"
	LogTCP = "tcp"
	LogUDP = "udp"

	LogJSON = "json"
	LogCEF  = "cef"

	LogTraffic    = "traffic"
	LogThreat     = "threat"
	LogDecryption = "decryption"
	LogSystem     = "system"

	// MaxLogServers caps log_servers.
	MaxLogServers = 8
)

// LogTypes are every forwardable log type, in display order.
var LogTypes = []string{LogTraffic, LogThreat, LogDecryption, LogSystem}

// LogFacilities are the syslog facility names allowed, with their codes.
var LogFacilities = map[string]int{
	"user": 1, "daemon": 3, "auth": 4, "syslog": 5, "authpriv": 10,
	"local0": 16, "local1": 17, "local2": 18, "local3": 19,
	"local4": 20, "local5": 21, "local6": 22, "local7": 23,
}

// TransportOrDefault is the server's transport (tls when unset).
func (l LogServer) TransportOrDefault() string {
	if l.Transport == "" {
		return LogTLS
	}
	return l.Transport
}

// FormatOrDefault is the server's message format (json when unset).
func (l LogServer) FormatOrDefault() string {
	if l.Format == "" {
		return LogJSON
	}
	return l.Format
}

// PortOrDefault is the server's port (by transport when unset).
func (l LogServer) PortOrDefault() int {
	if l.Port != 0 {
		return l.Port
	}
	if l.TransportOrDefault() == LogTLS {
		return 6514
	}
	return 514
}

// VRFOrDefault is the VRF the server is reached in (mgmt when unset).
func (l LogServer) VRFOrDefault() string {
	if l.VRF == "" {
		return VRFMgmt
	}
	return l.VRF
}

// FacilityOrDefault is the syslog facility (local0 when unset).
func (l LogServer) FacilityOrDefault() string {
	if l.Facility == "" {
		return "local0"
	}
	return l.Facility
}

// TypesOrDefault are the log types sent (all when unset).
func (l LogServer) TypesOrDefault() []string {
	if len(l.Types) == 0 {
		return slices.Clone(LogTypes)
	}
	return l.Types
}

// Sends reports whether the server gets logs of type t.
func (l LogServer) Sends(t string) bool { return slices.Contains(l.TypesOrDefault(), t) }

// NormalizePEM returns PEM text with its line breaks restored, so a
// certificate pasted on one line (CLI set, spaces for newlines) still
// parses. Text that already has line breaks is returned unchanged.
func NormalizePEM(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || strings.Contains(s, "\n") {
		return s
	}
	var out strings.Builder
	for s != "" {
		i := strings.Index(s, "-----BEGIN ")
		if i < 0 {
			break
		}
		s = s[i:]
		hdrEnd := strings.Index(s[len("-----BEGIN "):], "-----")
		if hdrEnd < 0 {
			break
		}
		hdrEnd += len("-----BEGIN ") + len("-----")
		header := s[:hdrEnd]
		label := strings.TrimSuffix(strings.TrimPrefix(header, "-----BEGIN "), "-----")
		footer := "-----END " + label + "-----"
		j := strings.Index(s, footer)
		if j < 0 {
			break
		}
		body := strings.Join(strings.Fields(s[hdrEnd:j]), "")
		out.WriteString(header + "\n")
		for len(body) > 64 {
			out.WriteString(body[:64] + "\n")
			body = body[64:]
		}
		if body != "" {
			out.WriteString(body + "\n")
		}
		out.WriteString(footer + "\n")
		s = strings.TrimSpace(s[j+len(footer):])
	}
	return strings.TrimSpace(out.String())
}

// ParseCAPEM parses one or more PEM certificates.
func ParseCAPEM(s string) ([]*x509.Certificate, error) {
	rest := []byte(NormalizePEM(s))
	var certs []*x509.Certificate
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("PEM block %q is not a certificate", b.Type)
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no PEM certificate found")
	}
	if strings.TrimSpace(string(rest)) != "" {
		return nil, fmt.Errorf("unexpected text after the certificates")
	}
	return certs, nil
}

func (v *validator) logServers(c *Config) {
	if len(c.LogServers) > MaxLogServers {
		v.add("log_servers", "at most %d servers", MaxLogServers)
	}
	names := map[string]bool{}
	targets := map[string]string{}
	for i, l := range c.LogServers {
		p := fmt.Sprintf("log_servers[%d] %q", i, l.Name)
		v.checkName(p, l.Name)
		if names[l.Name] {
			v.add(p, "duplicate name")
		}
		names[l.Name] = true
		ip, err := netip.ParseAddr(l.Address)
		switch {
		case l.Address == "":
			v.add(p, "address required")
		case err != nil || !ip.Is4():
			v.add(p, "address must be an IPv4 address, got %q", l.Address)
		case ip.IsUnspecified() || ip.IsMulticast() || ip == netip.AddrFrom4([4]byte{255, 255, 255, 255}):
			v.add(p, "address %s can't be a log server", ip)
		}
		if l.Port < 0 || l.Port > 65535 {
			v.add(p, "port must be 1-65535 (or unset for the transport's default)")
		}
		tr := l.TransportOrDefault()
		switch tr {
		case LogTLS, LogTCP, LogUDP:
		default:
			v.add(p, "transport must be tls, tcp or udp, got %q", l.Transport)
		}
		switch l.FormatOrDefault() {
		case LogJSON, LogCEF:
		default:
			v.add(p, "format must be json or cef, got %q", l.Format)
		}
		seen := map[string]bool{}
		for _, t := range l.Types {
			if !slices.Contains(LogTypes, t) {
				v.add(p, "unknown log type %q (types: %s)", t, strings.Join(LogTypes, ", "))
			}
			if seen[t] {
				v.add(p, "log type %q listed twice", t)
			}
			seen[t] = true
		}
		switch l.VRFOrDefault() {
		case VRFMgmt, VRFDefault:
		default:
			v.add(p, "vrf must be mgmt or default, got %q", l.VRF)
		}
		if _, ok := LogFacilities[l.FacilityOrDefault()]; !ok {
			v.add(p, "unknown facility %q (e.g. local0-local7, daemon, syslog)", l.Facility)
		}
		if tr != LogTLS {
			if l.CA != "" {
				v.add(p, "ca applies to transport tls only")
			}
			if l.ServerName != "" {
				v.add(p, "server_name applies to transport tls only")
			}
		}
		if l.CA != "" {
			if _, err := ParseCAPEM(l.CA); err != nil {
				v.add(p, "ca: %v", err)
			}
		}
		if l.ServerName != "" && (len(l.ServerName) > 253 || strings.ContainsAny(l.ServerName, " /\t")) {
			v.add(p, "invalid server_name %q", l.ServerName)
		}
		key := fmt.Sprintf("%s %s:%d %s", tr, l.Address, l.PortOrDefault(), l.VRFOrDefault())
		if other, ok := targets[key]; ok {
			v.add(p, "same server, port, transport and VRF as %q", other)
		} else {
			targets[key] = l.Name
		}
	}
}
