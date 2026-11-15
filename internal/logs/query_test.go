package logs

import (
	"errors"
	"strings"
	"testing"
)

func TestQueryMatch(t *testing.T) {
	web := Traffic{Type: "end", Rule: "allow-web", Action: "allow", FromZone: "inside", ToZone: "outside", In: "inside", Out: "outside",
		Src: "10.10.1.50", Dst: "4.2.2.2", Proto: "tcp", SPort: 40000, DPort: 443, App: "YouTube", Category: "Media", Bytes: 52341, Duration: 12.5, Flags: "SYN"}
	dns := Traffic{Type: "start", Rule: "block-dns", Action: "deny", FromZone: "lab", ToZone: "outside", Src: "172.16.20.5", Dst: "8.8.8.8", Proto: "udp", SPort: 5353, DPort: 53}
	for _, tc := range []struct {
		q        string
		web, dns bool
	}{
		{"zone = inside and dst = 4.2.2.2", true, false},
		{"from=inside dst=4.2.2.2", true, false},           // no spaces; implicit and
		{"FROM eq Inside and DST eq 4.2.2.2", true, false}, // case, word operators
		{"zone = outside", true, true},                     // either side
		{"zone != inside", false, true},                    // neither side
		{"dst = 8.0.0.0/8", false, true},
		{"addr = 10.10.0.0/16", true, false},
		{"dst != 4.2.2.2", false, true},
		{"dport = 443", true, false},
		{"port = 5000-6000", false, true},
		{"dport >= 53 and dport < 100", false, true},
		{"bytes > 1000000", false, false},
		{"bytes > 50000", true, false},
		{"duration >= 10", true, false},
		{"app ~ tube", true, false},
		{"app = youtube", true, false},
		{"app = tube", false, false},
		{"app !~ tube", false, true},
		{"flags ~ syn", true, false},
		{"action = allow or action = deny", true, true},
		{"not action = allow", false, true},
		{"(proto = udp or dport = 443) and zone = lab", false, true},
		{"allow-web", true, false},          // bare word: anywhere
		{"8.8.8.8", false, true},            // bare word: an address
		{"youtube media", true, false},      // two bare words: both
		{`rule = "allow-web"`, true, false}, // quoted value
		{"", true, true},
	} {
		q, err := ParseQuery(tc.q, TrafficSchema)
		if err != nil {
			t.Errorf("%q: %v", tc.q, err)
			continue
		}
		if got := q.Match(web.Value, web.values()); got != tc.web {
			t.Errorf("%q on web entry: %v, want %v", tc.q, got, tc.web)
		}
		if got := q.Match(dns.Value, dns.values()); got != tc.dns {
			t.Errorf("%q on dns entry: %v, want %v", tc.q, got, tc.dns)
		}
	}
}

func TestQueryErrors(t *testing.T) {
	for q, want := range map[string]string{
		"zon = inside":         `unknown field "zon"`,
		"dst = example.com":    "is not an address or CIDR",
		"dst > 1.2.3.4":        "dst takes =, != or ~",
		"dport = https":        "is not a number",
		"port = 2000-1000":     "is not a range",
		"app > 3":              "app is text",
		"(zone = inside":       "missing )",
		"zone = inside)":       `unexpected ")"`,
		"= inside":             "needs a field before it",
		"zone =":               "needs a value",
		`rule = "open`:         "unterminated quote",
		"zone = inside and":    "ends too early",
		"zone = inside or not": "ends too early",
	} {
		_, err := ParseQuery(q, TrafficSchema)
		if err == nil || !errors.Is(err, ErrQuery) || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: got %v, want %q", q, err, want)
		}
	}
}
