package webui

import (
	"strings"
	"testing"
)

// loginAs logs a user in from its own address.
func loginAs(t *testing.T, c0 *client, user, password string) *client {
	t.Helper()
	c := &client{t: t, h: c0.h, addr: "198.51.100." + map[string]string{"reader": "1", "ops": "2", "pat": "3"}[user]}
	code, out, _ := c.do("POST", "/ui/api/login", map[string]string{"user": user, "password": password})
	if code != 200 {
		t.Fatalf("login %s: %d %v", user, code, out)
	}
	c.csrf = out["csrf"].(string)
	return c
}

func TestRoles(t *testing.T) {
	h, _, d := setup(t, &fakeUpgrader{})
	su := login(t, h)
	// Superusers manage users and roles.
	for _, u := range []map[string]string{
		{"name": "reader", "role": "read-only", "password": "reader-password"},
		{"name": "ops", "role": "admin", "password": "ops-password-1"},
	} {
		if code, out, _ := su.do("POST", "/ui/api/users", u); code != 200 {
			t.Fatalf("add %s: %d %v", u["name"], code, out)
		}
	}
	role := map[string]any{"description": "rules only", "permissions": map[string]string{"policy": "change", "revisions": "view"}}
	if code, out, _ := su.do("PUT", "/ui/api/roles/policy-editor", role); code != 200 {
		t.Fatalf("add role: %d %v", code, out)
	}
	su.do("POST", "/ui/api/users", map[string]string{"name": "pat", "role": "policy-editor", "password": "pat-password-1"})
	if code, _, _ := su.do("PUT", "/ui/api/config/candidate", labJSON(t)); code != 200 {
		t.Fatal("candidate")
	}
	if code, out, _ := su.do("POST", "/ui/api/commit", map[string]any{"message": "base"}); code != 200 {
		t.Fatalf("commit: %d %v", code, out)
	}

	reader := loginAs(t, su, "reader", "reader-password")
	ops := loginAs(t, su, "ops", "ops-password-1")
	pat := loginAs(t, su, "pat", "pat-password-1")

	if _, out, _ := reader.do("GET", "/ui/api/session", nil); out["role"] != "read-only" || out["superuser"] != false || out["config_edit"] != false {
		t.Fatalf("reader session: %v", out)
	}
	cases := []struct {
		who          *client
		name         string
		method, path string
		body         any
		want         int
	}{
		{reader, "reader views config", "GET", "/ui/api/config/running", nil, 200},
		{reader, "reader views revisions", "GET", "/ui/api/revisions", nil, 200},
		{reader, "reader edits", "PUT", "/ui/api/config/candidate", labJSON(t), 403},
		{reader, "reader commits", "POST", "/ui/api/commit", map[string]any{}, 403},
		{reader, "reader tags", "POST", "/ui/api/tags/register", map[string]any{"ip": "10.10.1.5", "tags": []string{"x"}}, 403},
		{reader, "reader lists users", "GET", "/ui/api/users", nil, 403},
		{reader, "reader adds a key to admin", "POST", "/ui/api/users/admin/ssh-keys", map[string]string{"key": "ssh-ed25519 AAAA"}, 403},
		{ops, "ops tags", "POST", "/ui/api/tags/register", map[string]any{"ip": "10.10.1.5", "tags": []string{"x"}}, 200},
		{ops, "ops upgrades", "POST", "/ui/api/upgrade/start", map[string]any{}, 403},
		{ops, "ops views upgrades", "GET", "/ui/api/upgrade", nil, 200},
		{ops, "ops makes a CA", "POST", "/ui/api/decryption/ca/generate", map[string]any{}, 403},
		{ops, "ops adds a user", "POST", "/ui/api/users", map[string]string{"name": "eve", "role": "superuser", "password": "eve-password-1"}, 403},
		{ops, "ops makes a role", "PUT", "/ui/api/roles/boss", map[string]any{"permissions": map[string]string{"upgrades": "change"}}, 403},
		{pat, "pat views revisions", "GET", "/ui/api/revisions", nil, 200},
		{pat, "pat rolls back", "POST", "/ui/api/rollback", map[string]int{"revision": 1}, 403},
		{pat, "pat reads logs", "GET", "/ui/api/stats", nil, 403},
	}
	for _, c := range cases {
		if code, out, _ := c.who.do(c.method, c.path, c.body); code != c.want {
			t.Errorf("%s: %d, want %d (%v)", c.name, code, c.want, out)
		}
	}

	// A policy editor changes rules but not the hostname.
	cfg := labJSON(t)
	cfg["rules"] = cfg["rules"].([]any)[:1]
	if code, out, _ := pat.do("PUT", "/ui/api/config/candidate", cfg); code != 200 {
		t.Fatalf("pat edits rules: %d %v", code, out)
	}
	if code, out, _ := pat.do("POST", "/ui/api/commit", map[string]any{"message": "fewer rules"}); code != 200 {
		t.Fatalf("pat commits rules: %d %v", code, out)
	}
	cfg = labJSON(t)
	cfg["rules"] = cfg["rules"].([]any)[:1]
	cfg["system"].(map[string]any)["hostname"] = "pats-fw"
	code, out, _ := pat.do("PUT", "/ui/api/config/candidate", cfg)
	if code != 403 || !strings.Contains(out["error"].(string), "network") {
		t.Fatalf("pat edits the hostname: %d %v", code, out)
	}
	// Someone else's pending hostname change stops pat's commit.
	su.do("PUT", "/ui/api/config/candidate", cfg)
	if code, out, _ := pat.do("POST", "/ui/api/commit", map[string]any{}); code != 403 {
		t.Fatalf("pat commits someone's hostname change: %d %v", code, out)
	}
	revs, _ := d.Revisions()
	if a := revs[len(revs)-1].Author; a != "web:pat" {
		t.Errorf("last revision author %q, want web:pat", a)
	}

	// Disabling a user ends their session at once; a password reset ends
	// the user's sessions too.
	if code, out, _ := su.do("PATCH", "/ui/api/users/reader", map[string]bool{"disabled": true}); code != 200 {
		t.Fatalf("disable: %d %v", code, out)
	}
	if code, _, _ := reader.do("GET", "/ui/api/status", nil); code != 401 {
		t.Errorf("disabled user's session: %d", code)
	}
	if code, out, _ := su.do("POST", "/ui/api/users/ops/password", map[string]string{"password": "ops-password-2"}); code != 200 {
		t.Fatalf("reset: %d %v", code, out)
	}
	if code, _, _ := ops.do("GET", "/ui/api/status", nil); code != 401 {
		t.Errorf("session after a reset: %d", code)
	}
	// Demoting takes effect on the next request.
	ro := "read-only"
	su.do("PATCH", "/ui/api/users/pat", map[string]*string{"role": &ro})
	if code, _, _ := pat.do("PUT", "/ui/api/config/candidate", labJSON(t)); code != 403 {
		t.Errorf("demoted user edits: %d", code)
	}
	// admin is permanent; roles in use can't go.
	if code, _, _ := su.do("DELETE", "/ui/api/users/admin", nil); code != 400 {
		t.Errorf("delete admin: %d", code)
	}
	su.do("PATCH", "/ui/api/users/pat", map[string]string{"role": "policy-editor"})
	if code, _, _ := su.do("DELETE", "/ui/api/roles/policy-editor", nil); code != 400 {
		t.Errorf("delete a role in use: %d", code)
	}
	if code, out, _ := su.do("GET", "/ui/api/users", nil); code != 200 || out != nil {
		// a JSON array: out (a map) stays nil
		t.Errorf("list users: %d %v", code, out)
	}
}

func TestOwnSSHKeys(t *testing.T) {
	h, _, _ := setup(t, nil)
	su := login(t, h)
	su.do("POST", "/ui/api/users", map[string]string{"name": "ops", "role": "admin", "password": "ops-password-1"})
	ops := loginAs(t, su, "ops", "ops-password-1")
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGl0IHN0b3BzIGp1bmsgYXQgdGhlIGJvcmRlcnMgdG9k ops@laptop"
	code, out, _ := ops.do("POST", "/ui/api/users/ops/ssh-keys", map[string]string{"key": key})
	if code != 200 || !strings.HasPrefix(out["fingerprint"].(string), "SHA256:") {
		t.Fatalf("own key: %d %v", code, out)
	}
	if code, _, _ := ops.do("POST", "/ui/api/users/admin/ssh-keys", map[string]string{"key": key}); code != 403 {
		t.Errorf("key for someone else: %d", code)
	}
	if code, out, _ := ops.do("GET", "/ui/api/me", nil); code != 200 || len(out["ssh_keys"].([]any)) != 1 {
		t.Errorf("me: %d %v", code, out)
	}
	if code, _, _ := ops.do("DELETE", "/ui/api/users/ops/ssh-keys/1", nil); code != 200 {
		t.Errorf("delete own key: %d", code)
	}
}
