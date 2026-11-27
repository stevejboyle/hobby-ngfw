package logs

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

// DecryptionPrefix starts each decryption line tlsd writes to its journal,
// followed by the Decryption as JSON.
const DecryptionPrefix = "ngfw-decrypt "

// Decryption decisions.
const (
	DecDecrypted    = "decrypted"     // decrypted and inspected
	DecWouldDecrypt = "would-decrypt" // observe mode: would have been decrypted; passed through
	DecPassed       = "passed"        // passed through undecrypted (can't be decrypted, or no CA)
	DecExcluded     = "excluded"      // server name on an exclusion list
	DecLearned      = "learned"       // pinned: passed through (or just learned)
	DecBlocked      = "blocked"       // refused (profile, or the security rules)
	DecFailed       = "failed"        // something went wrong (server unreachable, handshake failed)
)

// Decryption is one connection tlsd handled. It never holds what was
// inside the connection: no URLs, headers or content.
type Decryption struct {
	Time       time.Time `json:"time"`
	Rule       string    `json:"rule"`
	Decision   string    `json:"decision"`
	Reason     string    `json:"reason,omitempty"`
	ServerName string    `json:"server_name,omitempty"`
	Src        string    `json:"src"`
	SPort      int       `json:"sport,omitempty"`
	Dst        string    `json:"dst"`
	DPort      int       `json:"dport,omitempty"`
	TLS        string    `json:"tls,omitempty"`  // 1.2 or 1.3
	ALPN       string    `json:"alpn,omitempty"` // h2, http/1.1, ...
	Geo
}

// Line is the journal line for d.
func (d Decryption) Line() string {
	b, _ := json.Marshal(d)
	return DecryptionPrefix + string(b)
}

// ParseDecryption reads a line written by Line.
func ParseDecryption(msg string) (Decryption, bool) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(msg), DecryptionPrefix)
	if !ok {
		return Decryption{}, false
	}
	var d Decryption
	if json.Unmarshal([]byte(rest), &d) != nil || d.Decision == "" {
		return Decryption{}, false
	}
	return d, true
}

// DecryptionColumns are the decryption log's columns, in display order.
var DecryptionColumns = []Column{
	{"time", "Time", "when the connection started"},
	{"rule", "Rule", "the decryption rule that matched"},
	{"decision", "Decision", "decrypted, would-decrypt, passed, excluded, learned, blocked or failed"},
	{"reason", "Reason", "why, when it wasn't simply decrypted"},
	{"server_name", "Server name", "the name the client asked for (TLS server name)"},
	{"src", "Source", "source address"},
	{"sport", "Src port", "source port"},
	{"src_country", "Src country", "the source's country (ISO code), from the DB-IP country database"},
	{"src_asn", "Src AS", "the source's autonomous system: number and organisation"},
	{"dst", "Destination", "destination address"},
	{"dport", "Dst port", "destination port"},
	{"dst_country", "Dst country", "the destination's country (ISO code)"},
	{"dst_asn", "Dst AS", "the destination's autonomous system: number and organisation"},
	{"tls", "TLS", "TLS version, when decrypted"},
	{"alpn", "Protocol", "application protocol, when decrypted (h2, http/1.1)"},
}

// DefaultDecryptionColumns are shown when no columns are chosen.
var DefaultDecryptionColumns = []string{"time", "rule", "decision", "server_name", "src", "src_country", "dst", "dport", "dst_country", "reason"}

// DecryptionSchema is the decryption log's query fields.
var DecryptionSchema = withGeo(Schema{
	"rule":        {kText, []string{"rule"}, "decryption rule name"},
	"decision":    {kText, []string{"decision"}, "decrypted, would-decrypt, passed, excluded, learned, blocked, failed"},
	"reason":      {kText, []string{"reason"}, "reason text, e.g. reason ~ pinned"},
	"server_name": {kText, []string{"server_name"}, "server name, e.g. server_name ~ example.com"},
	"src":         {kAddr, []string{"src"}, "source address or prefix"},
	"dst":         {kAddr, []string{"dst"}, "destination address or prefix"},
	"sport":       {kNum, []string{"sport"}, "source port"},
	"dport":       {kNum, []string{"dport"}, "destination port"},
	"tls":         {kText, []string{"tls"}, "TLS version"},
})

// Value is the text of one column of d.
func (d Decryption) Value(col string) string {
	if v, ok := d.Geo.value(col); ok {
		return v
	}
	num := func(n int) string {
		if n == 0 {
			return ""
		}
		return strconv.Itoa(n)
	}
	switch col {
	case "time":
		return d.Time.Format(time.RFC3339)
	case "rule":
		return d.Rule
	case "decision":
		return d.Decision
	case "reason":
		return d.Reason
	case "server_name":
		return d.ServerName
	case "src":
		return d.Src
	case "sport":
		return num(d.SPort)
	case "dst":
		return d.Dst
	case "dport":
		return num(d.DPort)
	case "tls":
		return d.TLS
	case "alpn":
		return d.ALPN
	}
	return ""
}

func (d Decryption) values() []string {
	out := make([]string, 0, len(DecryptionColumns))
	for _, c := range DecryptionColumns {
		if c.Name != "time" {
			out = append(out, d.Value(c.Name))
		}
	}
	return out
}

// ParseDecryptionColumns reads a comma-separated decryption column list.
func ParseDecryptionColumns(s string) ([]string, error) { return parseColumns(DecryptionColumns, s) }

// TLSDUnit is tlsd's systemd unit, whose journal holds the decryption log.
const TLSDUnit = "sjb-tlsd.service"

// Decryption reads decryption entries, newest first.
func (j Journal) Decryption(n int, q string) ([]Decryption, error) {
	query, err := ParseQuery(q, DecryptionSchema)
	if err != nil {
		return nil, err
	}
	n = clamp(n)
	want := n
	if q != "" {
		want = MaxEntries * 5
	}
	out, err := j.run("-u", TLSDUnit, "-o", "json", "--no-pager", "-r", "-n", strconv.Itoa(want), "--grep", "^"+strings.TrimSpace(DecryptionPrefix)+" ")
	if err != nil {
		out, err = j.run("-u", TLSDUnit, "-o", "json", "--no-pager", "-r", "-n", strconv.Itoa(want*5))
		if err != nil {
			return nil, err
		}
	}
	var res []Decryption
	for _, e := range entries(out) {
		if d, ok := ParseDecryption(e.message()); ok {
			if d.Time.IsZero() {
				d.Time = e.time()
			}
			d.Geo.fill(j.Geo, d.Src, d.Dst)
			if query.Match(d.Value, d.values()) {
				res = append(res, d)
			}
		}
	}
	res = newestFirst(res, func(i int) time.Time { return res[i].Time })
	if len(res) > n {
		res = res[:n]
	}
	return res, nil
}
