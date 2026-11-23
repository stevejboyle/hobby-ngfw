package ips

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// EVESocket is where Suricata sends its alerts (eve-log unix_dgram).
const EVESocket = "/run/ngfw/ips-eve.sock"

// Alert is the part of a Suricata EVE alert SJB-OS uses.
type Alert struct {
	Time     time.Time
	SID      int
	Message  string
	Category string
	Severity string // critical, major, minor, informational
	Proto    string
	Src      string
	SPort    int
	Dst      string
	DPort    int
	// Client and Server are the connection's ends, whichever way the
	// packet went: Suricata's flow addresses (it sits after destination
	// NAT, so Server is the server's inside address), else the packet's
	// by its direction.
	Client, Server string
}

type eveRecord struct {
	Timestamp string `json:"timestamp"`
	EventType string `json:"event_type"`
	SrcIP     string `json:"src_ip"`
	SrcPort   int    `json:"src_port"`
	DestIP    string `json:"dest_ip"`
	DestPort  int    `json:"dest_port"`
	Proto     string `json:"proto"`
	Direction string `json:"direction"` // to_server or to_client (Suricata 7)
	Flow      struct {
		SrcIP  string `json:"src_ip"`
		DestIP string `json:"dest_ip"`
	} `json:"flow"`
	Alert struct {
		SignatureID int                 `json:"signature_id"`
		Signature   string              `json:"signature"`
		Category    string              `json:"category"`
		Metadata    map[string][]string `json:"metadata"`
	} `json:"alert"`
}

// ParseEVE reads one EVE record; ok is false for anything but an alert.
func ParseEVE(b []byte) (Alert, bool) {
	var r eveRecord
	if json.Unmarshal(b, &r) != nil || r.EventType != "alert" || r.Alert.SignatureID == 0 {
		return Alert{}, false
	}
	a := Alert{
		SID: r.Alert.SignatureID, Message: r.Alert.Signature, Category: r.Alert.Category,
		Proto: strings.ToLower(r.Proto), Src: r.SrcIP, SPort: r.SrcPort, Dst: r.DestIP, DPort: r.DestPort,
		Severity: "informational",
	}
	switch {
	case r.Flow.SrcIP != "" && r.Flow.DestIP != "":
		a.Client, a.Server = r.Flow.SrcIP, r.Flow.DestIP
	case r.Direction == "to_client":
		a.Client, a.Server = r.DestIP, r.SrcIP
	default:
		a.Client, a.Server = r.SrcIP, r.DestIP
	}
	if s := r.Alert.Metadata["signature_severity"]; len(s) > 0 {
		a.Severity = Severity(s[0])
	}
	if t, err := time.Parse("2006-01-02T15:04:05.999999-0700", r.Timestamp); err == nil {
		a.Time = t.UTC()
	}
	return a, true
}

// Listen receives EVE records on a unix datagram socket at path and calls
// handle for each alert until the socket is closed. The returned close
// function stops it.
func Listen(path string, handle func(Alert)) (func() error, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		return nil, err
	}
	conn.SetReadBuffer(4 << 20)
	go func() {
		buf := make([]byte, 256*1024)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			if a, ok := ParseEVE(buf[:n]); ok {
				handle(a)
			}
		}
	}()
	return conn.Close, nil
}
