package accounts

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stevejboyle/hobby-ngfw/internal/config"
)

func init() { Iterations = 1000 }

// fakeSys records what the Store asks of the Unix side.
type fakeSys struct {
	accounts map[string]bool // name -> enabled (ours)
	foreign  map[string]bool // system accounts SJB-OS didn't create
	pw       map[string]string
	keys     map[string][]string
	ended    []string
	resets   []string
	failPW   bool
}

func newFakeSys() *fakeSys {
	return &fakeSys{accounts: map[string]bool{}, foreign: map[string]bool{"daemon2": true}, pw: map[string]string{}, keys: map[string][]string{}}
}

func (f *fakeSys) Lookup(n string) (bool, bool) {
	if f.foreign[n] {
		return true, false
	}
	_, ok := f.accounts[n]
	return ok, ok
}
func (f *fakeSys) Ensure(n string, en bool) error {
	if f.foreign[n] {
		return errors.New("foreign")
	}
	f.accounts[n] = en
	if !en {
		f.ended = append(f.ended, n)
	}
	return nil
}
func (f *fakeSys) Remove(n string) error {
	delete(f.accounts, n)
	f.ended = append(f.ended, n)
	return nil
}
func (f *fakeSys) SetPassword(n, pw string) error {
	if f.failPW {
		return errors.New("chpasswd failed")
	}
	f.pw[n] = pw
	return nil
}
func (f *fakeSys) Terminate(n string)     { f.ended = append(f.ended, n) }
func (f *fakeSys) ResetFailures(n string) { f.resets = append(f.resets, n) }
func (f *fakeSys) WriteKeys(n string, k []string) error {
	f.keys[n] = slices.Clone(k)
	return nil
}
func (f *fakeSys) Ours() []string {
	var out []string
	for n := range f.accounts {
		out = append(out, n)
	}
	return out
}

const key1 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGl0IHN0b3BzIGp1bmsgYXQgdGhlIGJvcmRlcnMgdG9k alice@laptop"
const key2 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHNlY29uZCBrZXkgZm9yIHRlc3RzIG9ubHkgcGxlYXMh"

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newStore(t *testing.T) (*Store, *fakeSys, *clock) {
	t.Helper()
	dir := t.TempDir()
	clk := &clock{t: time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)}
	sys := newFakeSys()
	s := &Store{Path: filepath.Join(dir, "users.json"), RolesPath: filepath.Join(dir, "roles.json"),
		Legacy: filepath.Join(dir, "web-users"), Sys: sys, Now: clk.now}
	if err := s.Open(); err != nil {
		t.Fatal(err)
	}
	return s, sys, clk
}

var su = Caller{Name: Admin, Via: "web"}

func TestBuiltinRoles(t *testing.T) {
	roles := map[string]Role{}
	for _, r := range BuiltinRoles() {
		roles[r.Name] = r
	}
	p := func(role string) Principal { return Principal{Name: "x", Role: roles[role]} }
	cases := []struct {
		role string
		need Need
		ok   bool
	}{
		{RoleSuperuser, SuperuserOnly, true},
		{RoleSuperuser, NeedChange(Upgrades), true},
		{RoleAdmin, SuperuserOnly, false},
		{RoleAdmin, NeedChange(Policy), true},
		{RoleAdmin, NeedChange(Revisions), true},
		{RoleAdmin, NeedChange(Tags), true},
		{RoleAdmin, NeedChange(IPS), true},
		{RoleAdmin, NeedChange(Upgrades), false},
		{RoleAdmin, NeedView(Upgrades), true},
		{RoleAdmin, NeedChange(DecryptionCA), false},
		{RoleAdmin, NeedView(DecryptionCA), true},
		{RoleAdmin, ConfigEdit, true},
		{RoleReadOnly, ConfigView, true},
		{RoleReadOnly, ConfigEdit, false},
		{RoleReadOnly, NeedView(Monitoring), true},
		{RoleReadOnly, NeedChange(Tags), false},
		{RoleReadOnly, Anyone, true},
		{RoleReadOnly, SuperuserOnly, false},
	}
	for _, c := range cases {
		if got := p(c.role).Allows(c.need); got != c.ok {
			t.Errorf("%s allows %s = %v, want %v", c.role, c.need, got, c.ok)
		}
	}
	if (Need{}).Valid() || (Principal{Role: roles[RoleSuperuser]}).Allows(Need{}) {
		t.Error("the zero Need must be invalid and allow nobody")
	}
}

// Every config field must belong to an area, or a change to it would be
// checked against the wrong one.
func TestEveryConfigFieldHasAnArea(t *testing.T) {
	ct := reflect.TypeOf(config.Config{})
	for i := 0; i < ct.NumField(); i++ {
		f := ct.Field(i)
		if f.Name == "System" {
			st := f.Type
			for j := 0; j < st.NumField(); j++ {
				if _, ok := systemFieldArea[st.Field(j).Name]; !ok {
					t.Errorf("config.System.%s has no area in systemFieldArea", st.Field(j).Name)
				}
			}
			continue
		}
		if _, ok := configFieldArea[f.Name]; !ok {
			t.Errorf("config.Config.%s has no area in configFieldArea", f.Name)
		}
	}
	for _, a := range configFieldArea {
		if !slices.Contains(ConfigAreas, a) {
			t.Errorf("area %s maps config but isn't in ConfigAreas", a)
		}
	}
}

func TestChangedAreas(t *testing.T) {
	base := `system: {hostname: fw, mgmt_interface: mgmt}
zones: [{name: inside}]
`
	cases := []struct {
		name, from, to string
		want           []Area
	}{
		{"same", base, base, nil},
		{"hostname", base, strings.Replace(base, "hostname: fw", "hostname: fw2", 1), []Area{Network}},
		{"zones", base, strings.Replace(base, "[{name: inside}]", "[{name: inside}, {name: outside}]", 1), []Area{Policy}},
		{"ips switch", base, strings.Replace(base, "mgmt_interface: mgmt", "mgmt_interface: mgmt, ips: \"off\"", 1), []Area{IPS}},
		{"from nothing", "", base, []Area{Policy, Network}},
		{"unparseable", base, "rules: [", ConfigAreas},
	}
	for _, c := range cases {
		got := ChangedAreas([]byte(c.from), []byte(c.to))
		if !slices.Equal(got, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
	policyOnly := Principal{Name: "pat", Role: Role{Name: "policy-editor", Perms: map[Area]Level{Policy: Change, Network: View}}}
	if err := policyOnly.CheckConfigChange("commit", []byte(base), []byte(strings.Replace(base, "hostname: fw", "hostname: x", 1))); !errors.Is(err, ErrForbidden) || !strings.Contains(err.Error(), "network") {
		t.Errorf("network change by a policy editor: %v", err)
	}
	if err := policyOnly.CheckConfigChange("commit", []byte(base), []byte(strings.Replace(base, "[{name: inside}]", "[{name: inside}, {name: outside}]", 1))); err != nil {
		t.Errorf("policy change by a policy editor: %v", err)
	}
}

func TestMigrateFromWebUsers(t *testing.T) {
	dir := t.TempDir()
	h, _ := HashPassword("old-admin-password")
	os.WriteFile(filepath.Join(dir, "web-users"), []byte("# old\nadmin "+h+"\nBad!Name x\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "authorized_keys"), []byte("# deploy key\n"+key1+"\nnot a key\n"), 0o600)
	s := &Store{Path: filepath.Join(dir, "users.json"), Legacy: filepath.Join(dir, "web-users"), AdminKeys: filepath.Join(dir, "authorized_keys")}
	if err := s.Open(); err != nil {
		t.Fatal(err)
	}
	p, err := s.Authenticate(Admin, "old-admin-password", "test")
	if err != nil || !p.Superuser() {
		t.Fatalf("admin after migration: %+v %v", p, err)
	}
	us, _ := s.Users()
	if len(us) != 1 || len(us[0].SSHKeys) != 1 || us[0].SSHKeys[0].Comment != "alice@laptop" {
		t.Fatalf("users after migration: %+v", us)
	}
	// Opening again changes nothing.
	if err := s.Open(); err != nil {
		t.Fatal(err)
	}
	if us2, _ := s.Users(); len(us2) != 1 {
		t.Fatalf("second open: %+v", us2)
	}
}

func TestFreshStoreHasAdmin(t *testing.T) {
	s, sys, _ := newStore(t)
	us, _ := s.Users()
	if len(us) != 1 || us[0].Name != Admin || us[0].PasswordSet || !us[0].Permanent {
		t.Fatalf("fresh store: %+v", us)
	}
	// Root's recovery command sets admin's password; the legacy file follows.
	if err := s.SetPassword(Root, Admin, "first-boot-password"); err != nil {
		t.Fatal(err)
	}
	if sys.pw[Admin] != "first-boot-password" {
		t.Error("admin's login password not set")
	}
	if _, ok := sys.accounts[Admin]; ok {
		t.Error("admin's Unix account is sjb-migrate's, not the store's")
	}
	if m := readLegacy(s.Legacy); !CheckPassword(m[Admin], "first-boot-password") {
		t.Error("legacy file not updated for rollbacks")
	}
}

func TestLockout(t *testing.T) {
	s, sys, clk := newStore(t)
	s.AddUser(su, "alice", RoleAdmin, "alice-password-1")
	for i := 0; i < LockoutFailures; i++ {
		if _, err := s.Authenticate("alice", "wrong", "10.0.0.9"); !errors.Is(err, ErrBadLogin) {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	if _, err := s.Authenticate("alice", "alice-password-1", "10.0.0.9"); !errors.Is(err, ErrLocked) {
		t.Fatalf("right password while locked: %v", err)
	}
	u, _ := s.User("alice")
	if !u.Locked {
		t.Fatal("not shown as locked")
	}
	clk.t = clk.t.Add(LockoutTime + time.Second)
	if _, err := s.Authenticate("alice", "alice-password-1", "10.0.0.9"); err != nil {
		t.Fatalf("after the lockout: %v", err)
	}
	// A superuser can unlock early, which also resets PAM's counter.
	for i := 0; i < LockoutFailures; i++ {
		s.Authenticate("alice", "wrong", "")
	}
	if err := s.Unlock(su, "alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate("alice", "alice-password-1", ""); err != nil {
		t.Fatalf("after unlock: %v", err)
	}
	if !slices.Contains(sys.resets, "alice") {
		t.Error("SSH/console lockout not reset")
	}
	if _, err := s.Authenticate("nobody-here", "x", ""); !errors.Is(err, ErrBadLogin) {
		t.Errorf("unknown user: %v", err)
	}
}

func TestUserLifecycle(t *testing.T) {
	s, sys, _ := newStore(t)
	if err := s.AddUser(su, "alice", RoleReadOnly, "short"); !errors.Is(err, ErrInvalid) {
		t.Errorf("short password: %v", err)
	}
	for _, bad := range []string{"Alice", "root", "1x", "a b", "sjb-tls", "daemon2"} {
		if err := s.AddUser(su, bad, RoleReadOnly, "long-enough-pw"); !errors.Is(err, ErrInvalid) {
			t.Errorf("name %q: %v", bad, err)
		}
	}
	if err := s.AddUser(su, "alice", "no-such-role", "long-enough-pw"); !errors.Is(err, ErrInvalid) {
		t.Errorf("unknown role: %v", err)
	}
	if err := s.AddUser(su, "alice", RoleReadOnly, "long-enough-pw"); err != nil {
		t.Fatal(err)
	}
	if !sys.accounts["alice"] || sys.pw["alice"] != "long-enough-pw" {
		t.Fatalf("Unix login not created: %+v %+v", sys.accounts, sys.pw)
	}
	if err := s.AddUser(su, "alice", RoleReadOnly, "long-enough-pw"); !errors.Is(err, ErrInvalid) {
		t.Errorf("duplicate: %v", err)
	}
	p, _ := s.Principal("alice", time.Time{})
	if p.Role.Name != RoleReadOnly || p.Allows(ConfigEdit) {
		t.Errorf("alice: %+v", p)
	}
	admin := RoleAdmin
	if err := s.UpdateUser(su, "alice", &admin, nil); err != nil {
		t.Fatal(err)
	}
	if p, _ := s.Principal("alice", time.Time{}); !p.Allows(ConfigEdit) {
		t.Error("role change didn't take effect")
	}
	yes := true
	if err := s.UpdateUser(su, "alice", nil, &yes); err != nil {
		t.Fatal(err)
	}
	if sys.accounts["alice"] {
		t.Error("disabled user's login still enabled")
	}
	if _, err := s.Principal("alice", time.Time{}); !errors.Is(err, ErrForbidden) {
		t.Errorf("disabled principal: %v", err)
	}
	if _, err := s.Authenticate("alice", "long-enough-pw", ""); !errors.Is(err, ErrDisabled) {
		t.Errorf("disabled login: %v", err)
	}
	// admin is permanent; nobody changes their own role or disables themselves.
	s.AddUser(su, "carl", RoleAdmin, "carl-password-1")
	ro := RoleReadOnly
	for name, err := range map[string]error{
		"demote admin":  s.UpdateUser(Caller{Name: "bob", Via: "cli"}, Admin, &ro, nil),
		"disable admin": s.UpdateUser(Caller{Name: "bob", Via: "cli"}, Admin, nil, &yes),
		"delete admin":  s.DeleteUser(Caller{Name: "bob", Via: "cli"}, Admin),
		"delete self":   s.DeleteUser(Caller{Name: "alice", Via: "cli"}, "alice"),
		"disable self":  s.UpdateUser(Caller{Name: "carl", Via: "cli"}, "carl", nil, &yes),
		"demote self":   s.UpdateUser(Caller{Name: "carl", Via: "cli"}, "carl", &ro, nil),
	} {
		if !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := s.DeleteUser(su, "alice"); err != nil {
		t.Fatal(err)
	}
	if _, ok := sys.accounts["alice"]; ok {
		t.Error("deleted user's login still there")
	}
}

func TestPasswordChangeEndsOldSessions(t *testing.T) {
	s, sys, clk := newStore(t)
	s.AddUser(su, "alice", RoleAdmin, "alice-password-1")
	session := clk.t
	clk.t = clk.t.Add(time.Minute)
	if err := s.ChangeOwnPassword(Caller{Name: "alice", Via: "cli"}, "wrong-password", "alice-password-2"); !errors.Is(err, ErrInvalid) {
		t.Errorf("wrong current: %v", err)
	}
	if err := s.ChangeOwnPassword(Caller{Name: "alice", Via: "cli"}, "alice-password-1", "alice-password-2"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Principal("alice", session); !errors.Is(err, ErrForbidden) {
		t.Errorf("session from before the change: %v", err)
	}
	if _, err := s.Principal("alice", clk.t); err != nil {
		t.Errorf("session from after the change: %v", err)
	}
	sys.ended = nil
	if err := s.SetPassword(su, "alice", "reset-by-admin"); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(sys.ended, "alice") {
		t.Error("a reset by a superuser must end the user's CLI sessions")
	}
	sys.failPW = true
	if err := s.SetPassword(su, "alice", "will-not-stick"); err == nil {
		t.Fatal("chpasswd failure ignored")
	}
	if _, err := s.Authenticate("alice", "reset-by-admin", ""); err != nil {
		t.Errorf("a failed change must leave the old password: %v", err)
	}
}

func TestSSHKeys(t *testing.T) {
	s, sys, _ := newStore(t)
	if _, err := ParseKey(`command="sh" ` + key1); err == nil {
		t.Error("key options accepted")
	}
	if _, err := ParseKey("ssh-rsa " + strings.Split(key1, " ")[1]); err == nil {
		t.Error("type mismatch accepted")
	}
	k, err := s.AddKey(su, Admin, key1)
	if err != nil || !strings.HasPrefix(k.Fingerprint, "SHA256:") {
		t.Fatalf("add: %+v %v", k, err)
	}
	if _, err := s.AddKey(su, Admin, key1); !errors.Is(err, ErrInvalid) {
		t.Errorf("duplicate key: %v", err)
	}
	s.AddKey(su, Admin, key2)
	if len(sys.keys[Admin]) != 2 {
		t.Fatalf("keys file: %v", sys.keys[Admin])
	}
	if err := s.DeleteKey(su, Admin, k.Fingerprint); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteKey(su, Admin, "1"); err != nil {
		t.Fatal(err)
	}
	if len(sys.keys[Admin]) != 0 {
		t.Errorf("keys left: %v", sys.keys[Admin])
	}
}

func TestCustomRoles(t *testing.T) {
	s, _, _ := newStore(t)
	for name, r := range map[string]Role{
		"builtin name": {Name: RoleAdmin},
		"bad name":     {Name: "Bad Name"},
		"superuser":    {Name: "boss", Superuser: true},
		"bad area":     {Name: "x", Perms: map[Area]Level{"users": Change}},
		"bad level":    {Name: "x", Perms: map[Area]Level{Policy: "write"}},
	} {
		if err := s.PutRole(su, r); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	err := s.PutRole(su, Role{Name: "policy-editor", Description: "rules only",
		Perms: map[Area]Level{Policy: Change, Monitoring: Change, Network: "none", Revisions: View}})
	if err != nil {
		t.Fatal(err)
	}
	roles, _ := s.Roles()
	var pe Role
	for _, r := range roles {
		if r.Name == "policy-editor" {
			pe = r
		}
	}
	if pe.Perms[Monitoring] != View || pe.Perms[Network] != None || pe.BuiltIn {
		t.Errorf("normalised role: %+v", pe)
	}
	if len(roles) != 4 || roles[0].Name != RoleSuperuser {
		t.Errorf("role order: %v", roles)
	}
	s.AddUser(su, "pat", "policy-editor", "pat-password-1")
	if err := s.DeleteRole(su, "policy-editor"); !errors.Is(err, ErrInvalid) {
		t.Errorf("delete in use: %v", err)
	}
	if err := s.DeleteRole(su, RoleReadOnly); !errors.Is(err, ErrInvalid) {
		t.Errorf("delete built-in: %v", err)
	}
	s.DeleteUser(su, "pat")
	if err := s.DeleteRole(su, "policy-editor"); err != nil {
		t.Errorf("delete unused: %v", err)
	}
}

func TestReconcile(t *testing.T) {
	s, sys, _ := newStore(t)
	s.AddUser(su, "alice", RoleAdmin, "alice-password-1")
	s.AddUser(su, "bob", RoleAdmin, "bob-password-1")
	yes := true
	s.UpdateUser(su, "bob", nil, &yes)
	s.AddKey(su, "alice", key1)
	// After a rollback and re-upgrade: logins locked by sjb-migrate undo,
	// one stray login left from a user deleted meanwhile.
	sys.accounts = map[string]bool{"alice": false, "bob": false, "carol": true}
	sys.keys = map[string][]string{}
	s.Reconcile()
	if !sys.accounts["alice"] || sys.accounts["bob"] || sys.accounts["carol"] {
		t.Errorf("after reconcile: %+v", sys.accounts)
	}
	if len(sys.keys["alice"]) != 1 {
		t.Errorf("alice's keys not rewritten: %v", sys.keys)
	}
}

func TestAuthor(t *testing.T) {
	for c, want := range map[Caller]string{{"alice", "cli"}: "cli:alice", {"bob", "web"}: "web:bob", Root: "root", {"system", "system"}: "system"} {
		if got := c.Author(); got != want {
			t.Errorf("%+v: %q, want %q", c, got, want)
		}
	}
}
