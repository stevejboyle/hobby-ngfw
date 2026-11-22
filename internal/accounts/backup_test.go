package accounts

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestSnapshotAndRestore(t *testing.T) {
	src, srcSys, _ := newStore(t)
	if err := src.PutRole(su, Role{Name: "auditor", Perms: map[Area]Level{Policy: View, Logging: Change}}); err != nil {
		t.Fatal(err)
	}
	if err := src.AddUser(su, "alice", "auditor", "correct horse battery"); err != nil {
		t.Fatal(err)
	}
	if _, err := src.AddKey(su, "alice", key1); err != nil {
		t.Fatal(err)
	}
	if err := src.AddUser(su, "bob", RoleReadOnly, "another good passphrase"); err != nil {
		t.Fatal(err)
	}
	dis := true
	if err := src.UpdateUser(su, "bob", nil, &dis); err != nil {
		t.Fatal(err)
	}
	snap, warns, err := src.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Users) != 3 || len(snap.Roles) != 1 {
		t.Fatalf("snapshot %+v", snap)
	}
	// admin was made by migration without a login password: a warning, not an error.
	if len(warns) > 1 {
		t.Errorf("warnings %v", warns)
	}

	dst, dstSys, _ := newStore(t)
	if err := dst.AddUser(su, "carol", RoleAdmin, "carol's own password"); err != nil {
		t.Fatal(err)
	}
	adminBefore, _ := dst.User(Admin)
	res, err := dst.Restore(su, snap)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(res.Added, []string{"alice", "bob"}) || !slices.Contains(res.Kept, "carol") || !slices.Contains(res.Skipped, Admin) || !slices.Equal(res.Roles, []string{"auditor"}) {
		t.Fatalf("result %+v", res)
	}
	// Same passwords on the web UI and the login.
	if _, err := dst.Authenticate("alice", "correct horse battery", "test"); err != nil {
		t.Fatalf("alice can't log in: %v", err)
	}
	if dstSys.hashes["alice"] != srcSys.hashes["alice"] || dstSys.hashes["alice"] == "" {
		t.Errorf("login hash %q, want %q", dstSys.hashes["alice"], srcSys.hashes["alice"])
	}
	if !slices.Equal(dstSys.keys["alice"], []string{key1}) {
		t.Errorf("keys %v", dstSys.keys["alice"])
	}
	if en, ok := dstSys.accounts["bob"]; !ok || en {
		t.Errorf("bob should be a locked login: %v %v", en, ok)
	}
	if u, _ := dst.User("bob"); !u.Disabled {
		t.Error("bob should be disabled")
	}
	if adminAfter, _ := dst.User(Admin); adminAfter.PasswordChanged != adminBefore.PasswordChanged {
		t.Error("admin's password changed")
	}
	if p, err := dst.Principal("alice", src.now()); err != nil || !p.Can(Logging, Change) {
		t.Errorf("alice's role: %+v %v", p.Role, err)
	}
	// Restoring again updates instead of adding.
	res, err = dst.Restore(su, snap)
	if err != nil || !slices.Equal(res.Updated, []string{"alice", "bob"}) || len(res.Added) != 0 {
		t.Fatalf("second restore %+v %v", res, err)
	}
}

func TestRestoreRefusesBadSnapshots(t *testing.T) {
	cases := []struct {
		name string
		snap Snapshot
		want string
	}{
		{"unknown role", Snapshot{Users: []SnapshotUser{{Name: "x", Role: "ghost"}}}, "neither the backup nor this firewall"},
		{"bad role", Snapshot{Roles: []Role{{Name: "superuser"}}}, "built-in role"},
		{"bad name", Snapshot{Users: []SnapshotUser{{Name: "Bad Name", Role: RoleAdmin}}}, "backup user"},
		{"twice", Snapshot{Users: []SnapshotUser{{Name: "x", Role: RoleAdmin}, {Name: "x", Role: RoleAdmin}}}, "twice"},
		{"bad hash", Snapshot{Users: []SnapshotUser{{Name: "x", Role: RoleAdmin, UnixHash: "$1$a:b"}}}, "bad login password hash"},
		{"bad web hash", Snapshot{Users: []SnapshotUser{{Name: "x", Role: RoleAdmin, Hash: "plain"}}}, "bad password hash"},
		{"bad key", Snapshot{Users: []SnapshotUser{{Name: "x", Role: RoleAdmin, SSHKeys: []string{"nope"}}}}, "backup user"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, sys, _ := newStore(t)
			_, err := s.Restore(su, tc.snap)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
			if _, ok := sys.accounts["x"]; ok {
				t.Error("an account was created before the check failed")
			}
		})
	}
	// The caller is never changed by their own restore.
	s, _, _ := newStore(t)
	if err := s.AddUser(su, "eve", RoleSuperuser, "eve's long password"); err != nil {
		t.Fatal(err)
	}
	res, err := s.Restore(Caller{Name: "eve", Via: "cli"}, Snapshot{Users: []SnapshotUser{{Name: "eve", Role: RoleReadOnly}}})
	if err != nil || !slices.Contains(res.Skipped, "eve") {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestShadowHash(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "shadow")
	os.WriteFile(path, []byte("root:*:1::::::\nalice:!$y$j9T$abc$def:2::::::\nbob:!:3::::::\n"), 0o600)
	e := &Exec{Shadow: path}
	if h, _ := e.ShadowHash("alice"); h != "$y$j9T$abc$def" {
		t.Errorf("alice %q", h)
	}
	for _, n := range []string{"bob", "root", "nobody"} {
		if h, _ := e.ShadowHash(n); h != "" {
			t.Errorf("%s %q", n, h)
		}
	}
	if err := e.SetPasswordHash("x", "not a hash"); err == nil {
		t.Error("accepted a non-hash")
	}
}
