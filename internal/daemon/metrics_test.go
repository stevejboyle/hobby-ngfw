package daemon

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stevejboyle/sjb-os/internal/accounts"
	"github.com/stevejboyle/sjb-os/internal/ips"
	"github.com/stevejboyle/sjb-os/internal/nft"
)

// counterNFT is the fake runner plus rule counters.
type counterNFT struct {
	*nft.Fake
	counters map[string]map[string]nft.Counter
}

func (c *counterNFT) Counters(table string, chains ...string) (map[string]map[string]nft.Counter, error) {
	out := map[string]map[string]nft.Counter{}
	for _, ch := range chains {
		if m, ok := c.counters[ch]; ok {
			out[ch] = m
		}
	}
	return out, nil
}

func TestMetricsSnapshot(t *testing.T) {
	d, f := setup(t)
	d.metrics.serviceActive = func(string) bool { return false }
	d.SetCandidate(lab(t))
	if _, err := d.Commit("steve", "lab", 0); err != nil {
		t.Fatal(err)
	}
	d.nft = &counterNFT{Fake: f, counters: map[string]map[string]nft.Counter{
		"forward": {
			"rule:allow-web":                       {Packets: 10, Bytes: 1000},
			"rule:allow-web (application pending)": {Packets: 2, Bytes: 100},
			"default-deny":                         {Packets: 5, Bytes: 300},
			"zone-to-firewall":                     {Packets: 99},
		},
		"allowed": {"rule:allow-web": {Packets: 1, Bytes: 10}},
	}}
	// Two blocked critical matches and an alert, as IPSAlert counts them.
	d.countIPSMatch("critical", "block")
	d.countIPSMatch("critical", "block")
	d.countIPSMatch("minor", "alert")
	d.RegisterTags(netip.MustParseAddr("10.10.1.10"), []string{"quarantine"}, time.Minute)

	s := d.Metrics()
	if s.Config.RunningRevision != 1 || !s.Config.LastCommitOK || s.Config.LastCommitTime == nil {
		t.Errorf("config: %+v", s.Config)
	}
	var web *struct{ p, b uint64 }
	for _, r := range s.Rules {
		if r.Name == "allow-web" {
			web = &struct{ p, b uint64 }{r.Packets, r.Bytes}
		}
	}
	if web == nil || web.p != 13 || web.b != 1110 {
		t.Errorf("allow-web counters: %+v (rules %+v)", web, s.Rules)
	}
	last := s.Rules[len(s.Rules)-1]
	if last.Name != "default-deny" || last.Packets != 5 {
		t.Errorf("default deny: %+v", last)
	}
	if s.IPS.Matches["critical"]["block"] != 2 || s.Threats[0].Blocked != 2 || s.Threats[2].Alerted != 1 {
		t.Errorf("ips: %+v %+v", s.IPS.Matches, s.Threats)
	}
	if len(s.Tags) != 1 || s.Tags[0] != struct {
		Tag       string `json:"tag"`
		Addresses int    `json:"addresses"`
	}{"quarantine", 1} {
		t.Errorf("tags: %+v", s.Tags)
	}
	names := map[string]bool{}
	for _, sv := range s.Services {
		names[sv.Name] = true
		if sv.Name == "ngfwd" && !sv.Up {
			t.Error("ngfwd down in its own snapshot")
		}
	}
	for _, n := range []string{"ngfwd", "suricata", "tlsd", "appidd", "frr", "kea"} {
		if !names[n] {
			t.Errorf("service %s missing", n)
		}
	}
	if s.IPS.State == "" || s.Decryption.State == "" {
		t.Errorf("states unset: %q %q", s.IPS.State, s.Decryption.State)
	}
}

func TestMetricsCommitOutcome(t *testing.T) {
	d, f := setup(t)
	d.SetCandidate(lab(t))
	d.Commit("steve", "lab", 0)
	// The ruleset fails to load: a failed commit.
	d.SetCandidate(withoutWeb(t))
	f.ApplyErr = func(string) error { return errors.New("fake: ruleset won't load") }
	if _, err := d.Commit("steve", "fails", 0); err == nil {
		t.Fatal("commit succeeded with nft failing")
	}
	f.ApplyErr = nil
	if s := d.Metrics().Config; s.LastCommitOK || s.LastCommitNote == "" {
		t.Errorf("failed commit not recorded: %+v", s)
	}
	if _, err := d.Commit("steve", "ok", 0); err != nil {
		t.Fatal(err)
	}
	if !d.Metrics().Config.LastCommitOK {
		t.Error("a good commit didn't clear the failure")
	}
}

// A commit holding d.mu must not stall the snapshot: it answers within
// slowWait with the last values read.
func TestMetricsDontWaitForCommit(t *testing.T) {
	d, _ := setup(t)
	d.SetCandidate(lab(t))
	d.Commit("steve", "lab", 0)
	first := d.Metrics()
	d.mu.Lock()
	start := time.Now()
	s := d.Metrics()
	took := time.Since(start)
	d.mu.Unlock()
	if took > slowWait+time.Second {
		t.Errorf("snapshot waited %v for d.mu", took)
	}
	if s.Config.RunningRevision != first.Config.RunningRevision {
		t.Errorf("busy snapshot lost the last values: %+v", s.Config)
	}
	// Once d.mu is free the background read finishes.
	deadline := time.Now().Add(2 * time.Second)
	for d.metrics.slowBusy.Load() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if d.metrics.slowBusy.Load() {
		t.Error("slow read still busy after d.mu was released")
	}
}

func TestPrometheusEndpointAndKeys(t *testing.T) {
	d, _ := setup(t)
	withAccounts(t, d)
	d.SetCandidate(lab(t))
	d.Commit("steve", "lab", 0)
	keyFile := filepath.Join(t.TempDir(), "api-keys")
	os.WriteFile(keyFile, []byte("# <name> <scopes> <key>\nnac tags:read,tags:write tag-key-0000000000000000000\n"), 0o600)
	d.SetAPIKeysFile(keyFile)
	keys, err := LoadKeys(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	d.nft = &counterNFT{Fake: d.nft.(*nft.Fake), counters: map[string]map[string]nft.Counter{"forward": {"rule:allow-web": {Packets: 4}}}}
	srv := httptest.NewServer(d.APIHandler(keys))
	defer srv.Close()
	get := func(key string) (int, string) {
		req, _ := http.NewRequest("GET", srv.URL+"/metrics", nil)
		if key != "" {
			req.Header.Set("Authorization", "Bearer "+key)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	if c, _ := get(""); c != 401 {
		t.Errorf("no key: %d", c)
	}
	if c, _ := get("tag-key-0000000000000000000"); c != 403 {
		t.Errorf("tags key on /metrics: %d", c)
	}

	// A superuser adds a metrics key over the management socket; it works
	// at once and the file keeps the old key.
	h := d.MgmtHandler()
	ops := &accounts.Caller{Name: "ops", Via: "cli"}
	if c, _ := sock(t, h, ops, "POST", "/v1/api-keys", `{"name":"prom","scopes":["metrics:read"]}`); c != 403 {
		t.Errorf("admin added a key: %d", c)
	}
	c, body := sock(t, h, &accounts.Root, "POST", "/v1/api-keys", `{"name":"prom","scopes":["metrics:read"]}`)
	var added struct{ Key string }
	if c != 200 || json.Unmarshal([]byte(body), &added) != nil || len(added.Key) < 24 {
		t.Fatalf("add key: %d %s", c, body)
	}
	code, text := get(added.Key)
	if code != 200 || !strings.Contains(text, "sjbos_config_running_revision 1\n") || !strings.Contains(text, `sjbos_rule_packets_total{rule="allow-web",action="allow"}`) {
		t.Errorf("scrape: %d\n%s", code, text)
	}
	b, _ := os.ReadFile(keyFile)
	if !strings.Contains(string(b), "nac tags:read,tags:write tag-key-0000000000000000000") || !strings.Contains(string(b), "prom metrics:read "+added.Key) {
		t.Errorf("key file:\n%s", b)
	}
	if c, body := sock(t, h, &accounts.Root, "POST", "/v1/api-keys", `{"name":"prom","scopes":["metrics:read"]}`); c != 400 {
		t.Errorf("duplicate name: %d %s", c, body)
	}
	if c, body := sock(t, h, &accounts.Root, "POST", "/v1/api-keys", `{"name":"x","scopes":["root"]}`); c != 400 {
		t.Errorf("unknown scope: %d %s", c, body)
	}
	// Deleting it stops it at once, on /metrics and the XML endpoint alike.
	if c, body := sock(t, h, &accounts.Root, "DELETE", "/v1/api-keys/prom", ""); c != 200 {
		t.Fatalf("delete: %d %s", c, body)
	}
	if c, _ := get(added.Key); c != 401 {
		t.Errorf("deleted key still works: %d", c)
	}
	if c, _ := sock(t, h, &accounts.Root, "DELETE", "/v1/api-keys/nac", ""); c != 200 {
		t.Fatal("delete nac")
	}
	req, _ := http.NewRequest("POST", srv.URL+"/api/", strings.NewReader("<uid-message/>"))
	req.Header.Set("X-API-Key", "tag-key-0000000000000000000")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 && resp.StatusCode != 403 {
		t.Errorf("deleted key accepted by the XML endpoint: %d", resp.StatusCode)
	}
	// The socket's own metrics view needs monitoring view.
	if c, text := sock(t, h, ops, "GET", "/v1/metrics", ""); c != 200 || !strings.HasPrefix(text, "# HELP sjbos_info") {
		t.Errorf("socket metrics: %d %.80s", c, text)
	}
}

// IPSAlert counts what it logs, and nothing it ignores.
func TestIPSAlertCounts(t *testing.T) {
	d, _ := setup(t)
	d.SetCandidate(lab(t))
	d.Commit("steve", "lab", 0)
	d.ips.emit = func(string) {}
	d.IPSAlert(ips.Alert{Severity: "major", SID: 1, Proto: "TCP", Src: "10.10.1.5", Dst: "1.1.1.1"})
	var n uint64
	for _, c := range d.ipsMatches()["major"] {
		n += c
	}
	if n != 1 {
		t.Errorf("major matches: %v", d.ipsMatches())
	}
}
