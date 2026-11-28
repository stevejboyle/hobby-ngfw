package webui

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stevejboyle/sjb-os/internal/accounts"
	"github.com/stevejboyle/sjb-os/internal/config"
	"github.com/stevejboyle/sjb-os/internal/conntrack"
	"github.com/stevejboyle/sjb-os/internal/daemon"
	"github.com/stevejboyle/sjb-os/internal/geoip"
	"github.com/stevejboyle/sjb-os/internal/logs"
	"github.com/stevejboyle/sjb-os/internal/nft"
	"github.com/stevejboyle/sjb-os/internal/ospkg"
	"github.com/stevejboyle/sjb-os/internal/store"
	"github.com/stevejboyle/sjb-os/internal/tags"
	"github.com/stevejboyle/sjb-os/internal/upgrade"
)

const pw = "correct horse battery"

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

type fakeUpgrader struct{ staged string }

func (f *fakeUpgrader) Status() (upgrade.Status, error) {
	return upgrade.Status{Version: "0.3.0", History: []upgrade.Event{}}, nil
}
func (f *fakeUpgrader) Stage(r io.Reader) (*upgrade.Manifest, error) {
	b, _ := io.ReadAll(r)
	f.staged = string(b)
	return &upgrade.Manifest{Version: "0.3.1", Files: []upgrade.File{{Path: "usr/local/sbin/ngfwd"}}}, nil
}
func (f *fakeUpgrader) Start() error    { return nil }
func (f *fakeUpgrader) Rollback() error { return nil }
func (f *fakeUpgrader) Packages() *ospkg.Status {
	return &ospkg.Status{State: ospkg.StateOK, RebootRequired: true, RebootReasons: []string{"kernel 6.12.118"}}
}

func setup(t *testing.T, up Upgrader) (http.Handler, *clock, *daemon.Daemon) {
	t.Helper()
	accounts.Iterations = 1000
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	reg, err := tags.Open(filepath.Join(dir, "tags.json"))
	if err != nil {
		t.Fatal(err)
	}
	clk := &clock{t: time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)}
	d := daemon.New(st, reg, &nft.Fake{}, &conntrack.Fake{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	d.Now = clk.now
	if err := d.Start(); err != nil {
		t.Fatal(err)
	}
	withAdmin(t, dir, d)
	h := New(d, Options{Upgrader: up, Now: clk.now, Interfaces: func(string) []string { return []string{"10.0.0.1/24"} }})
	return h, clk, d
}

// withAdmin gives d a user database whose admin has password pw.
func withAdmin(t *testing.T, dir string, d *daemon.Daemon) *accounts.Store {
	t.Helper()
	a := &accounts.Store{Path: filepath.Join(dir, "users.json"), RolesPath: filepath.Join(dir, "roles.json")}
	if err := a.Open(); err != nil {
		t.Fatal(err)
	}
	if err := a.SetPassword(accounts.Root, accounts.Admin, pw); err != nil {
		t.Fatal(err)
	}
	d.SetAccounts(a)
	return a
}

type client struct {
	t      *testing.T
	h      http.Handler
	cookie string
	csrf   string
	addr   string
}

func (c *client) do(method, path string, body any) (int, map[string]any, http.Header) {
	c.t.Helper()
	var r io.Reader
	switch b := body.(type) {
	case nil:
	case []byte:
		r = bytes.NewReader(b)
	default:
		j, _ := json.Marshal(b)
		r = bytes.NewReader(j)
	}
	req := httptest.NewRequest(method, path, r)
	req.RemoteAddr = c.addr + ":40000"
	if c.cookie != "" {
		req.AddCookie(&http.Cookie{Name: cookieName, Value: c.cookie})
	}
	if c.csrf != "" {
		req.Header.Set(csrfHeader, c.csrf)
	}
	w := httptest.NewRecorder()
	c.h.ServeHTTP(w, req)
	for _, ck := range w.Result().Cookies() {
		if ck.Name == cookieName {
			c.cookie = ck.Value
		}
	}
	var out map[string]any
	json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out, w.Header()
}

func login(t *testing.T, h http.Handler) *client {
	t.Helper()
	c := &client{t: t, h: h, addr: "192.0.2.10"}
	code, out, _ := c.do("POST", "/ui/api/login", map[string]string{"user": "admin", "password": pw})
	if code != 200 {
		t.Fatalf("login: %d %v", code, out)
	}
	c.csrf = out["csrf"].(string)
	return c
}

func labJSON(t *testing.T) map[string]any {
	t.Helper()
	cfg, err := config.Load("../../examples/lab.yaml")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(cfg)
	var m map[string]any
	json.Unmarshal(b, &m)
	return m
}

func TestStaticAndHeaders(t *testing.T) {
	h, _, _ := setup(t, nil)
	for _, p := range []string{"/", "/app.js", "/app.css"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", p, nil))
		if w.Code != 200 {
			t.Fatalf("%s: %d", p, w.Code)
		}
		if !strings.Contains(w.Header().Get("Content-Security-Policy"), "default-src 'self'") || w.Header().Get("X-SJB-OS") != "Stops Junk at the Border" {
			t.Fatalf("%s: headers %v", p, w.Header())
		}
	}
}

func TestAuth(t *testing.T) {
	h, clk, _ := setup(t, nil)
	anon := &client{t: t, h: h, addr: "192.0.2.20"}
	if code, _, _ := anon.do("GET", "/ui/api/status", nil); code != 401 {
		t.Fatalf("anonymous status: %d", code)
	}
	if code, _, _ := anon.do("POST", "/ui/api/login", map[string]string{"user": "admin", "password": "nope"}); code != 401 {
		t.Fatalf("bad password: %d", code)
	}
	if code, _, _ := anon.do("POST", "/ui/api/login", map[string]string{"user": "nobody", "password": pw}); code != 401 {
		t.Fatalf("unknown user: %d", code)
	}

	c := login(t, h)
	if code, _, _ := c.do("GET", "/ui/api/status", nil); code != 200 {
		t.Fatalf("status: %d", code)
	}
	noCSRF := &client{t: t, h: h, cookie: c.cookie, addr: c.addr}
	if code, _, _ := noCSRF.do("POST", "/ui/api/config/revert", map[string]any{}); code != 403 {
		t.Fatalf("POST without CSRF header: %d", code)
	}
	clk.add(SessionIdle + time.Minute)
	if code, _, _ := c.do("GET", "/ui/api/status", nil); code != 401 {
		t.Fatalf("expired session: %d", code)
	}
}

func TestLoginBackoff(t *testing.T) {
	h, clk, _ := setup(t, nil)
	c := &client{t: t, h: h, addr: "192.0.2.30"}
	// Guessing at names slows the address down (the account lockout is
	// separate: TestAccountLockout).
	for i := 0; i < freeFailures; i++ {
		c.do("POST", "/ui/api/login", map[string]string{"user": "guess", "password": "guess"})
	}
	code, _, hdr := c.do("POST", "/ui/api/login", map[string]string{"user": "admin", "password": pw})
	if code != 429 || hdr.Get("Retry-After") == "" {
		t.Fatalf("after %d failures: %d", freeFailures, code)
	}
	other := &client{t: t, h: h, addr: "192.0.2.31"}
	if code, _, _ := other.do("POST", "/ui/api/login", map[string]string{"user": "admin", "password": pw}); code != 200 {
		t.Fatalf("other address should not be locked out: %d", code)
	}
	clk.add(time.Minute)
	if code, _, _ := c.do("POST", "/ui/api/login", map[string]string{"user": "admin", "password": pw}); code != 200 {
		t.Fatalf("after lockout: %d", code)
	}
}

func TestAccountLockout(t *testing.T) {
	h, _, d := setup(t, nil)
	for i := 0; i < accounts.LockoutFailures; i++ {
		c := &client{t: t, h: h, addr: fmt.Sprintf("192.0.2.%d", 100+i)}
		c.do("POST", "/ui/api/login", map[string]string{"user": "admin", "password": "guess"})
	}
	c := &client{t: t, h: h, addr: "192.0.2.99"}
	code, out, _ := c.do("POST", "/ui/api/login", map[string]string{"user": "admin", "password": pw})
	if code != 403 || !strings.Contains(out["error"].(string), "locked") {
		t.Fatalf("locked account, right password: %d %v", code, out)
	}
	d.Accounts().Unlock(accounts.Root, accounts.Admin)
	if code, _, _ := c.do("POST", "/ui/api/login", map[string]string{"user": "admin", "password": pw}); code != 200 {
		t.Fatalf("after unlock: %d", code)
	}
}

func TestEditCommitConfirm(t *testing.T) {
	h, _, d := setup(t, nil)
	c := login(t, h)

	bad := labJSON(t)
	bad["rules"].([]any)[0].(map[string]any)["from"] = []string{"nowhere"}
	code, out, _ := c.do("PUT", "/ui/api/config/candidate", bad)
	if code != 400 || !strings.Contains(out["errors"].([]any)[0].(string), `unknown zone "nowhere"`) {
		t.Fatalf("invalid candidate: %d %v", code, out)
	}
	if code, _, _ := c.do("PUT", "/ui/api/config/candidate", map[string]any{"bogus": 1}); code != 400 {
		t.Fatalf("unknown field: %d", code)
	}

	if code, out, _ := c.do("PUT", "/ui/api/config/candidate", labJSON(t)); code != 200 {
		t.Fatalf("put: %d %v", code, out)
	}
	_, out, _ = c.do("GET", "/ui/api/diff", nil)
	if !strings.Contains(out["diff"].(string), "+") {
		t.Fatalf("diff: %v", out)
	}
	_, out, _ = c.do("GET", "/ui/api/status", nil)
	if out["uncommitted_changes"] != true {
		t.Fatalf("status: %v", out)
	}
	code, out, _ = c.do("POST", "/ui/api/commit", map[string]any{"message": "from the UI", "confirm_minutes": 5})
	if code != 200 || out["confirm_by"] == nil {
		t.Fatalf("commit: %d %v", code, out)
	}
	_, out, _ = c.do("GET", "/ui/api/status", nil)
	if out["confirm_by"] == nil || out["running_revision"].(float64) != 1 {
		t.Fatalf("status after commit: %v", out)
	}
	if code, _, _ := c.do("POST", "/ui/api/confirm", map[string]any{}); code != 200 {
		t.Fatalf("confirm: %d", code)
	}
	revs, _ := d.Revisions()
	if len(revs) != 1 || revs[0].Author != "web:admin" {
		t.Fatalf("revisions: %+v", revs)
	}
	_, out, _ = c.do("GET", "/ui/api/revisions/1", nil)
	if !strings.Contains(out["yaml"].(string), "block-quarantined") {
		t.Fatalf("revision yaml: %v", out)
	}
	_, out, _ = c.do("GET", "/ui/api/config/running", nil)
	if len(out["rules"].([]any)) != 3 {
		t.Fatalf("running as JSON: %v", out)
	}
	_, out, _ = c.do("GET", "/ui/api/status", nil)
	if out["counts"].(map[string]any)["rules"].(float64) != 3 || len(out["interfaces"].([]any)) != 2 {
		t.Fatalf("dashboard counts: %v", out)
	}

	// Discarding an edit returns the candidate to running.
	edited := labJSON(t)
	edited["rules"] = edited["rules"].([]any)[:1]
	c.do("PUT", "/ui/api/config/candidate", edited)
	c.do("POST", "/ui/api/config/revert", map[string]any{})
	if _, out, _ := c.do("GET", "/ui/api/diff", nil); out["diff"] != "" {
		t.Fatalf("diff after revert: %q", out["diff"])
	}
}

func TestTags(t *testing.T) {
	h, _, _ := setup(t, nil)
	c := login(t, h)
	c.do("PUT", "/ui/api/config/candidate", labJSON(t))
	c.do("POST", "/ui/api/commit", map[string]any{"message": "base"})
	if code, out, _ := c.do("POST", "/ui/api/tags/register", map[string]any{"ip": "10.10.1.50", "tags": []string{"quarantine"}, "ttl": 600}); code != 200 {
		t.Fatalf("register: %d %v", code, out)
	}
	req := httptest.NewRequest("GET", "/ui/api/tags", nil)
	req.AddCookie(&http.Cookie{Name: cookieName, Value: c.cookie})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	var rows []map[string]any
	json.Unmarshal(w.Body.Bytes(), &rows)
	if len(rows) != 1 || rows[0]["ip"] != "10.10.1.50" || rows[0]["remaining_seconds"].(float64) != 600 {
		t.Fatalf("tags: %s", w.Body)
	}
	if code, _, _ := c.do("POST", "/ui/api/tags/register", map[string]any{"ip": "not-an-ip", "tags": []string{"x"}}); code != 400 {
		t.Fatalf("bad ip: %d", code)
	}
	if code, _, _ := c.do("POST", "/ui/api/tags/unregister", map[string]any{"ip": "10.10.1.50", "tags": []string{"quarantine"}}); code != 200 {
		t.Fatalf("unregister: %d", code)
	}
}

func TestPasswordChange(t *testing.T) {
	h, _, _ := setup(t, nil)
	a := login(t, h)
	b := login(t, h)
	if code, _, _ := a.do("POST", "/ui/api/password", map[string]string{"current": "wrong", "new": "a new long password"}); code != 400 {
		t.Fatalf("wrong current: %d", code)
	}
	if code, _, _ := a.do("POST", "/ui/api/password", map[string]string{"current": pw, "new": "short"}); code != 400 {
		t.Fatalf("short password: %d", code)
	}
	if code, _, _ := a.do("POST", "/ui/api/password", map[string]string{"current": pw, "new": "a new long password"}); code != 200 {
		t.Fatalf("change: %d", code)
	}
	if code, _, _ := a.do("GET", "/ui/api/status", nil); code != 200 {
		t.Fatalf("own session should survive: %d", code)
	}
	if code, _, _ := b.do("GET", "/ui/api/status", nil); code != 401 {
		t.Fatalf("other session should end: %d", code)
	}
	c := &client{t: t, h: h, addr: "192.0.2.40"}
	if code, _, _ := c.do("POST", "/ui/api/login", map[string]string{"user": "admin", "password": "a new long password"}); code != 200 {
		t.Fatalf("login with new password: %d", code)
	}
}

func TestUpgradeRoutes(t *testing.T) {
	h, _, _ := setup(t, nil)
	c := login(t, h)
	if code, _, _ := c.do("GET", "/ui/api/upgrade", nil); code != 501 {
		t.Fatalf("no upgrader: %d", code)
	}
	up := &fakeUpgrader{}
	h, _, _ = setup(t, up)
	c = login(t, h)
	code, out, _ := c.do("POST", "/ui/api/upgrade", []byte("bundle bytes"))
	if code != 200 || out["version"] != "0.3.1" || up.staged != "bundle bytes" {
		t.Fatalf("upload: %d %v", code, out)
	}
	if code, _, _ := c.do("POST", "/ui/api/upgrade/start", map[string]any{}); code != 200 {
		t.Fatalf("start: %d", code)
	}
	c.do("PUT", "/ui/api/config/candidate", labJSON(t))
	c.do("POST", "/ui/api/commit", map[string]any{"message": "pending", "confirm_minutes": 5})
	if code, out, _ := c.do("POST", "/ui/api/upgrade/start", map[string]any{}); code != 409 || !strings.Contains(out["error"].(string), "waiting for confirmation") {
		t.Fatalf("upgrade during a pending commit: %d %v", code, out)
	}
	c.do("POST", "/ui/api/confirm", map[string]any{})
	if code, _, _ := c.do("POST", "/ui/api/upgrade/start", map[string]any{}); code != 200 {
		t.Fatalf("start after confirm: %d", code)
	}
	if _, out, _ := c.do("GET", "/ui/api/status", nil); out["version"] != "0.3.0" {
		t.Fatalf("status version: %v", out)
	}
}

type fakeLogs struct{ q string }

func (f *fakeLogs) Traffic(n int, q string) ([]logs.Traffic, error) {
	f.q = q
	return []logs.Traffic{{Rule: "allow-web", Action: "allow", Src: "10.10.1.50", DPort: 443}}, nil
}
func (f *fakeLogs) Decryption(n int, q string) ([]logs.Decryption, error) {
	f.q = q
	return []logs.Decryption{{Rule: "users-out", Decision: "excluded", ServerName: "www.bank.example", Src: "10.10.1.50", DPort: 443}}, nil
}
func (f *fakeLogs) Threat(n int, q string) ([]logs.Threat, error) {
	f.q = q
	return []logs.Threat{{Rule: "inside-out", Action: "block", Severity: "critical", SID: 9900001}}, nil
}

func (f *fakeLogs) System(n int, q string) ([]logs.System, error) {
	return nil, nil
}

func TestLogRoutes(t *testing.T) {
	h, _, _ := setup(t, nil)
	c := login(t, h)
	if code, out, _ := c.do("GET", "/ui/api/logs/traffic", nil); code != 503 || !strings.Contains(out["error"].(string), "not available") {
		t.Fatalf("no reader: %d %v", code, out)
	}

	dir := t.TempDir()
	st, _ := store.Open(dir)
	reg, _ := tags.Open(filepath.Join(dir, "tags.json"))
	d := daemon.New(st, reg, &nft.Fake{}, &conntrack.Fake{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	d.Start()
	withAdmin(t, dir, d)
	fl := &fakeLogs{}
	h = New(d, Options{Logs: fl})
	c = login(t, h)
	req := httptest.NewRequest("GET", "/ui/api/logs/traffic?n=10&q=web", nil)
	req.AddCookie(&http.Cookie{Name: cookieName, Value: c.cookie})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"rule":"allow-web"`) || fl.q != "web" {
		t.Fatalf("traffic: %d %s (q=%q)", w.Code, w.Body, fl.q)
	}
	req = httptest.NewRequest("GET", "/ui/api/logs/system", nil)
	req.AddCookie(&http.Cookie{Name: cookieName, Value: c.cookie})
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 200 || strings.TrimSpace(w.Body.String()) != "[]" {
		t.Fatalf("empty system log should be []: %d %s", w.Code, w.Body)
	}
	if code, _, _ := c.do("GET", "/ui/api/logs/bogus", nil); code != 404 {
		t.Fatalf("bogus kind: %d", code)
	}
}

func TestCountriesAndGeoIP(t *testing.T) {
	h, _, d := setup(t, nil)
	c := login(t, h)
	code, out, _ := c.do("GET", "/ui/api/countries", nil)
	if code != 200 || out["US"] != "United States" || out["CN"] != "China" {
		t.Fatalf("countries: %d %v", code, out["US"])
	}
	root := t.TempDir()
	d.SetGeoIP(geoip.Store{Shipped: root + "/share", Local: root + "/var"}, nil)
	code, out, _ = c.do("GET", "/ui/api/geoip", nil)
	if code != 200 || out["available"] != false || !strings.Contains(out["attribution"].(string), "DB-IP") {
		t.Fatalf("geoip: %d %v", code, out)
	}
	// A rule with a country and a negated destination saves from the UI.
	cfg := labJSON(t)
	r := cfg["rules"].([]any)[0].(map[string]any)
	r["source"] = []string{"country:CN"}
	r["destination_negate"] = true
	r["destination"] = []string{"country:US"}
	if code, out, _ := c.do("PUT", "/ui/api/config/candidate", cfg); code != 200 {
		t.Fatalf("put: %d %v", code, out)
	}
	_, out, _ = c.do("GET", "/ui/api/config/candidate", nil)
	r = out["rules"].([]any)[0].(map[string]any)
	if r["destination_negate"] != true || r["source"].([]any)[0] != "country:CN" {
		t.Errorf("rule after save: %v", r)
	}
}

func TestUpdatesHandlers(t *testing.T) {
	h, _, d := setup(t, nil)
	c := login(t, h)
	code, out, _ := c.do("GET", "/ui/api/updates", nil)
	if code != 200 || out["available"] != false || out["server"] != "https://updates.os.sjbconsulting.ai" {
		t.Fatalf("updates: %d %v", code, out)
	}
	if code, _, _ := c.do("POST", "/ui/api/updates/check", map[string]any{}); code != 400 {
		t.Errorf("check without online updates: %d", code)
	}
	if code, _, _ := c.do("POST", "/ui/api/updates/install", map[string]any{}); code != 400 {
		t.Errorf("install without online updates: %d", code)
	}
	_ = d
	code, out, _ = c.do("GET", "/ui/api/status", nil)
	if code != 200 || out["update_ready"] != false {
		t.Errorf("status: %d %v", code, out["update_ready"])
	}
}
