package daemon

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stevejboyle/sjb-os/internal/accounts"
)

func withAccounts(t *testing.T, d *Daemon) *accounts.Store {
	t.Helper()
	accounts.Iterations = 1000
	dir := t.TempDir()
	a := &accounts.Store{Path: filepath.Join(dir, "users.json"), RolesPath: filepath.Join(dir, "roles.json")}
	if err := a.Open(); err != nil {
		t.Fatal(err)
	}
	for _, u := range [][2]string{{"ops", accounts.RoleAdmin}, {"reader", accounts.RoleReadOnly}} {
		if err := a.AddUser(accounts.Root, u[0], u[1], "a-long-password"); err != nil {
			t.Fatal(err)
		}
	}
	d.SetAccounts(a)
	return a
}

// sock calls the management handler as a socket caller would arrive.
func sock(t *testing.T, h http.Handler, c *accounts.Caller, method, path, body string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	if c != nil {
		req = req.WithContext(WithCaller(req.Context(), *c))
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w.Code, w.Body.String()
}

func TestMgmtAccess(t *testing.T) {
	d, _ := setup(t)
	withAccounts(t, d)
	h := d.MgmtHandler()
	ops := &accounts.Caller{Name: "ops", Via: "cli"}
	reader := &accounts.Caller{Name: "reader", Via: "cli"}
	stranger := &accounts.Caller{Name: "postgres", Via: "cli"}
	root := &accounts.Root

	cases := []struct {
		name         string
		c            *accounts.Caller
		method, path string
		body         string
		want         int
	}{
		{"no caller", nil, "GET", "/v1/status", "", 403},
		{"not an SJB-OS user", stranger, "GET", "/v1/status", "", 403},
		{"reader status", reader, "GET", "/v1/status", "", 200},
		{"reader config", reader, "GET", "/v1/config/candidate", "", 200},
		{"reader edits", reader, "PUT", "/v1/config/candidate", string(lab(t)), 403},
		{"reader api keys", reader, "GET", "/v1/api-keys", "", 403},
		{"reader users", reader, "GET", "/v1/users", "", 403},
		{"reader own record", reader, "GET", "/v1/users/reader", "", 200},
		{"reader someone else", reader, "GET", "/v1/users/ops", "", 403},
		{"ops edits", ops, "PUT", "/v1/config/candidate", string(lab(t)), 200},
		{"ops makes a CA", ops, "POST", "/v1/decryption/ca/generate", "{}", 403},
		{"ops adds a user", ops, "POST", "/v1/users", `{"name":"eve","role":"superuser","password":"long-password"}`, 403},
		{"root users", root, "GET", "/v1/users", "", 200},
		{"root adds a user", root, "POST", "/v1/users", `{"name":"eve","role":"read-only","password":"long-password"}`, 200},
	}
	for _, c := range cases {
		if code, body := sock(t, h, c.c, c.method, c.path, c.body); code != c.want {
			t.Errorf("%s: %d, want %d: %s", c.name, code, c.want, body)
		}
	}

	// The author is who called, whatever the client claims.
	code, body := sock(t, h, ops, "POST", "/v1/commit", `{"author":"someone-else","message":"m"}`)
	if code != 200 {
		t.Fatalf("commit: %d %s", code, body)
	}
	revs, _ := d.Revisions()
	if a := revs[len(revs)-1].Author; a != "cli:ops" {
		t.Errorf("author %q, want cli:ops", a)
	}

	_, body = sock(t, h, reader, "GET", "/v1/me", "")
	var me Me
	json.Unmarshal([]byte(body), &me)
	if me.Role != "read-only" || me.ConfigEdit || !me.ConfigView || me.Permissions[accounts.Tags] != accounts.View {
		t.Errorf("me: %+v", me)
	}
	if code, body := sock(t, h, reader, "POST", "/v1/password", `{"current":"a-long-password","new":"another-long-one"}`); code != 200 {
		t.Errorf("own password: %d %s", code, body)
	}
	if code, body := sock(t, h, ops, "POST", "/v1/rollback", `{"revision":1}`); code != 200 && !strings.Contains(body, "revision") {
		t.Errorf("ops rollback: %d %s", code, body)
	}
}

// Every management route must need something (a zero Need panics).
func TestMgmtRoutesAllHaveAPermission(t *testing.T) {
	d, _ := setup(t)
	seen := map[string]bool{}
	for _, r := range d.mgmtRoutes() {
		if !r.need.Valid() {
			t.Errorf("%s has no permission", r.pattern)
		}
		if seen[r.pattern] {
			t.Errorf("%s twice", r.pattern)
		}
		seen[r.pattern] = true
	}
}
