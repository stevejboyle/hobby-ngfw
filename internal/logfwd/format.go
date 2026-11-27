// Package logfwd forwards the appliance's logs (traffic, threat,
// decryption, system) to syslog servers: RFC 5424 messages over UDP, TCP or
// TLS (octet-counted framing on streams), with a JSON or CEF body. ngfwd
// runs it: one journal follower feeds a bounded queue per server.
package logfwd

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/stevejboyle/sjb-os/internal/config"
	"github.com/stevejboyle/sjb-os/internal/logs"
)

// AppName is the RFC 5424 APP-NAME of every message.
const AppName = "sjb-os"

// MaxUDPMessage caps a UDP message (bytes); longer bodies are cut.
const MaxUDPMessage = 8192

// msgID is the RFC 5424 MSGID for each log kind.
var msgID = map[string]string{
	logs.KindTraffic:    "TRAFFIC",
	logs.KindThreat:     "THREAT",
	logs.KindDecryption: "DECRYPT",
	logs.KindSystem:     "SYSTEM",
}

// Severity is the syslog severity (0 emergency .. 7 debug) of a record.
func Severity(r logs.Record) int {
	switch e := r.Entry.(type) {
	case logs.Traffic:
		if e.Action == "allow" {
			return 6
		}
		return 5
	case logs.Threat:
		switch e.Severity {
		case "critical":
			return 2
		case "major":
			return 3
		case "minor":
			return 4
		}
		return 6
	case logs.Decryption:
		if e.Decision == logs.DecBlocked || e.Decision == logs.DecFailed {
			return 4
		}
		return 6
	case logs.System:
		switch e.Level {
		case "error":
			return 3
		case "warn":
			return 4
		}
		return 6
	}
	return 6
}

func entryTime(r logs.Record) time.Time {
	switch e := r.Entry.(type) {
	case logs.Traffic:
		return e.Time
	case logs.Threat:
		return e.Time
	case logs.Decryption:
		return e.Time
	case logs.System:
		return e.Time
	}
	return time.Time{}
}

// Message formats r for server s as one RFC 5424 message (no framing).
func Message(s config.LogServer, host, version string, r logs.Record) []byte {
	t := entryTime(r)
	if t.IsZero() {
		t = time.Now()
	}
	pri := config.LogFacilities[s.FacilityOrDefault()]*8 + Severity(r)
	if host == "" {
		host = "-"
	}
	var body string
	if s.FormatOrDefault() == config.LogCEF {
		body = CEF(version, r)
	} else {
		body = JSON(r)
	}
	head := fmt.Sprintf("<%d>1 %s %s %s - %s - ", pri, t.UTC().Format("2006-01-02T15:04:05.000000Z"), printable(host, 255), AppName, msgID[r.Kind])
	return []byte(head + body)
}

// printable keeps RFC 5424 header fields to printable US-ASCII.
func printable(s string, max int) string {
	var b strings.Builder
	for _, c := range s {
		if c > 32 && c < 127 {
			b.WriteRune(c)
		}
	}
	out := b.String()
	if out == "" {
		return "-"
	}
	if len(out) > max {
		out = out[:max]
	}
	return out
}

// JSON is the record's entry as a JSON object with "log" naming its kind.
func JSON(r logs.Record) string {
	b, err := json.Marshal(r.Entry)
	if err != nil {
		return `{"log":"` + r.Kind + `"}`
	}
	return `{"log":"` + r.Kind + `",` + string(b[1:])
}

// CEF renders the record as a CEF:0 event.
func CEF(version string, r logs.Record) string {
	var sig, name string
	sev := 3
	var ext []kv
	addAddr := func(src string, sport int, dst string, dport int, proto string) {
		ext = append(ext, kv{"src", src}, kv{"spt", num(sport)}, kv{"dst", dst}, kv{"dpt", num(dport)}, kv{"proto", proto})
	}
	switch e := r.Entry.(type) {
	case logs.Traffic:
		sig, name = "traffic-"+e.Type, "Connection "+e.Type
		if e.Action != "allow" {
			sev = 5
		}
		ext = append(ext, kv{"rt", ms(e.Time)}, kv{"act", e.Action}, kv{"cs1Label", "rule"}, kv{"cs1", e.Rule},
			kv{"cs2Label", "fromZone"}, kv{"cs2", e.FromZone}, kv{"cs3Label", "toZone"}, kv{"cs3", e.ToZone},
			kv{"deviceInboundInterface", e.In}, kv{"deviceOutboundInterface", e.Out})
		addAddr(e.Src, e.SPort, e.Dst, e.DPort, e.Proto)
		ext = append(ext, geoExt(e.Geo)...)
		ext = append(ext, kv{"app", e.App}, kv{"cat", e.Category})
		if e.Type == "end" {
			ext = append(ext, kv{"cn1Label", "bytes"}, kv{"cn1", strconv.FormatInt(e.Bytes, 10)},
				kv{"cn2Label", "packets"}, kv{"cn2", strconv.FormatInt(e.Packets, 10)},
				kv{"cn3Label", "durationMs"}, kv{"cn3", strconv.FormatInt(int64(e.Duration*1000), 10)})
		}
	case logs.Threat:
		sig, name = strconv.Itoa(e.SID), e.Signature
		sev = map[string]int{"critical": 10, "major": 8, "minor": 5, "informational": 2}[e.Severity]
		ext = append(ext, kv{"rt", ms(e.Time)}, kv{"act", e.Action}, kv{"cs1Label", "rule"}, kv{"cs1", e.Rule},
			kv{"cs2Label", "profile"}, kv{"cs2", e.Profile}, kv{"cs3Label", "severity"}, kv{"cs3", e.Severity}, kv{"cat", e.Category})
		addAddr(e.Src, e.SPort, e.Dst, e.DPort, e.Proto)
		ext = append(ext, geoExt(e.Geo)...)
		ext = append(ext, kv{"app", e.App})
		if e.Decrypted {
			ext = append(ext, kv{"cs4Label", "decrypted"}, kv{"cs4", "yes"})
		}
		if e.Exception != "" {
			ext = append(ext, kv{"cs5Label", "ipsException"}, kv{"cs5", e.Exception})
		}
	case logs.Decryption:
		sig, name = "decryption-"+e.Decision, "TLS "+e.Decision
		if e.Decision == logs.DecBlocked || e.Decision == logs.DecFailed {
			sev = 5
		}
		ext = append(ext, kv{"rt", ms(e.Time)}, kv{"act", e.Decision}, kv{"cs1Label", "rule"}, kv{"cs1", e.Rule},
			kv{"dhost", e.ServerName}, kv{"reason", e.Reason})
		addAddr(e.Src, e.SPort, e.Dst, e.DPort, "tcp")
		ext = append(ext, geoExt(e.Geo)...)
		ext = append(ext, kv{"cs2Label", "tls"}, kv{"cs2", e.TLS}, kv{"cs3Label", "alpn"}, kv{"cs3", e.ALPN})
	case logs.System:
		sig, name = "system-"+e.Source, e.Message
		sev = map[string]int{"error": 7, "warn": 5}[e.Level]
		if sev == 0 {
			sev = 2
		}
		ext = append(ext, kv{"rt", ms(e.Time)}, kv{"cs1Label", "source"}, kv{"cs1", e.Source}, kv{"msg", e.Fields})
	}
	if len(name) > 512 {
		name = name[:512]
	}
	var b strings.Builder
	b.WriteString("CEF:0|SJB Consulting|SJB-OS|" + cefHeader(version) + "|" + cefHeader(sig) + "|" + cefHeader(name) + "|" + strconv.Itoa(sev) + "|")
	set := map[string]bool{}
	for _, p := range ext {
		if p.v != "" {
			set[p.k] = true
		}
	}
	first := true
	for _, p := range ext {
		if p.v == "" {
			continue
		}
		// A label without its value (cs2Label with no cs2) is left out.
		if k, ok := strings.CutSuffix(p.k, "Label"); ok && !set[k] {
			continue
		}
		if !first {
			b.WriteByte(' ')
		}
		first = false
		b.WriteString(p.k + "=" + cefValue(p.v))
	}
	return b.String()
}

type kv struct{ k, v string }

// geoExt is the country and AS of both addresses. CEF's dictionary has no
// keys for them and cs1-cs5 are taken, so they use vendor-prefixed keys, as
// the CEF spec allows for extensions outside the dictionary.
func geoExt(g logs.Geo) []kv {
	asn := func(n uint32) string {
		if n == 0 {
			return ""
		}
		return strconv.FormatUint(uint64(n), 10)
	}
	return []kv{
		{"sjbSrcCountry", g.SrcCountry}, {"sjbSrcAsn", asn(g.SrcASN)}, {"sjbSrcAsOrg", g.SrcASOrg},
		{"sjbDstCountry", g.DstCountry}, {"sjbDstAsn", asn(g.DstASN)}, {"sjbDstAsOrg", g.DstASOrg},
	}
}

func num(n int) string {
	if n == 0 {
		return ""
	}
	return strconv.Itoa(n)
}

func ms(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return strconv.FormatInt(t.UnixMilli(), 10)
}

// cefHeader escapes a CEF header field: backslash and pipe.
func cefHeader(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "|", `\|`)
	return strings.NewReplacer("\r", " ", "\n", " ").Replace(s)
}

// cefValue escapes a CEF extension value: backslash, equals, newlines.
func cefValue(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "=", `\=`)
	return strings.NewReplacer("\r\n", `\n`, "\n", `\n`, "\r", `\r`).Replace(s)
}

// Frame frames a message for a stream transport (RFC 6587/5425 octet
// counting: "<length> <message>").
func Frame(msg []byte) []byte {
	return append([]byte(strconv.Itoa(len(msg))+" "), msg...)
}
