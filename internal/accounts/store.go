package accounts

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Admin is the permanent superuser: it always exists and can't be deleted,
// disabled or given another role.
const Admin = "admin"

// Lockout: an account locks for LockoutTime after LockoutFailures wrong
// passwords in a row (web UI; SSH and the console count separately in PAM).
const (
	LockoutFailures = 5
	LockoutTime     = 15 * time.Minute
	maxKeys         = 20
)

// Login errors. Callers show ErrBadLogin for an unknown user too, so a
// wrong name looks like a wrong password.
var (
	ErrBadLogin = errors.New("wrong user name or password")
	ErrLocked   = errors.New("account locked")
	ErrDisabled = errors.New("account disabled")
)

// Caller is who is asking: the account name and how they came in ("cli",
// "web", "root" for root on the appliance, "system" for ngfwd itself).
type Caller struct {
	Name string `json:"name"`
	Via  string `json:"via"`
}

// Author is how the caller is recorded on revisions and in the log:
// "cli:alice", "web:alice", "root".
func (c Caller) Author() string {
	if c.Via == "" || c.Via == "root" || c.Via == "system" {
		return c.Name
	}
	return c.Via + ":" + c.Name
}

// Root is root on the appliance (the recovery account): a superuser.
var Root = Caller{Name: "root", Via: "root"}

// RootPrincipal is root's resolved identity.
func RootPrincipal() Principal {
	r, _ := builtinRole(RoleSuperuser)
	return Principal{Name: "root", Role: r}
}

// Store is the user and role database. Every operation reads the files
// afresh under a file lock, so ngfwd and root's `fwctl web-passwd` can both
// use them.
type Store struct {
	Path      string // users.json
	RolesPath string // roles.json (custom roles)
	// Legacy, if set, is the pre-RBAC web user file. It is imported once
	// and then kept holding admin's hash, so a rollback to an older SJB-OS
	// still logs admin in.
	Legacy string
	// AdminKeys, if set, is admin's old authorized_keys file, imported
	// once (deploy-time admin_ssh_key).
	AdminKeys string
	Sys       System // nil: no Unix accounts (development, tests)
	Log       *slog.Logger
	Now       func() time.Time
	mu        sync.Mutex
}

type user struct {
	Name            string    `json:"name"`
	Role            string    `json:"role"`
	Source          string    `json:"source"`
	Disabled        bool      `json:"disabled,omitempty"`
	Hash            string    `json:"hash,omitempty"`
	SSHKeys         []string  `json:"ssh_keys,omitempty"`
	Failures        int       `json:"failures,omitempty"`
	LockedUntil     time.Time `json:"locked_until,omitzero"`
	LastLogin       time.Time `json:"last_login,omitzero"`
	PasswordChanged time.Time `json:"password_changed,omitzero"`
	Created         time.Time `json:"created,omitzero"`
	CreatedBy       string    `json:"created_by,omitempty"`
	Changed         time.Time `json:"changed,omitzero"`
	ChangedBy       string    `json:"changed_by,omitempty"`
}

type usersFile struct {
	Users []*user `json:"users"`
}

type rolesFile struct {
	Roles []Role `json:"roles"`
}

type db struct {
	users []*user
	roles []Role // custom only
}

func (d *db) user(name string) *user {
	for _, u := range d.users {
		if u.Name == name {
			return u
		}
	}
	return nil
}

func (d *db) role(name string) (Role, bool) {
	if r, ok := builtinRole(name); ok {
		return r, true
	}
	for _, r := range d.roles {
		if r.Name == name {
			return r, true
		}
	}
	return Role{}, false
}

// UserInfo is a user as the CLI and web UI show it (no password hash).
type UserInfo struct {
	Name            string     `json:"name"`
	Role            string     `json:"role"`
	Source          string     `json:"source"`
	Disabled        bool       `json:"disabled"`
	Locked          bool       `json:"locked"`
	LockedUntil     *time.Time `json:"locked_until,omitempty"`
	Permanent       bool       `json:"permanent"`
	PasswordSet     bool       `json:"password_set"`
	PasswordChanged *time.Time `json:"password_changed,omitempty"`
	LastLogin       *time.Time `json:"last_login,omitempty"`
	SSHKeys         []KeyInfo  `json:"ssh_keys"`
	Created         *time.Time `json:"created,omitempty"`
	CreatedBy       string     `json:"created_by,omitempty"`
	Changed         *time.Time `json:"changed,omitempty"`
	ChangedBy       string     `json:"changed_by,omitempty"`
}

func tp(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

func (s *Store) info(u *user) UserInfo {
	now := s.now()
	i := UserInfo{Name: u.Name, Role: u.Role, Source: u.Source, Disabled: u.Disabled, Permanent: u.Name == Admin,
		PasswordSet: u.Hash != "", PasswordChanged: tp(u.PasswordChanged), LastLogin: tp(u.LastLogin),
		SSHKeys: keyInfos(u.SSHKeys), Created: tp(u.Created), CreatedBy: u.CreatedBy, Changed: tp(u.Changed), ChangedBy: u.ChangedBy}
	if u.LockedUntil.After(now) {
		i.Locked, i.LockedUntil = true, tp(u.LockedUntil)
	}
	return i
}

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Store) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// lock takes the cross-process file lock (and the in-process mutex).
func (s *Store) lock() (func(), error) {
	s.mu.Lock()
	f, err := os.OpenFile(s.Path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		s.mu.Unlock()
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		s.mu.Unlock()
		return nil, err
	}
	return func() {
		syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
		s.mu.Unlock()
	}, nil
}

func (s *Store) load() (*db, error) {
	d := &db{}
	data, err := os.ReadFile(s.Path)
	if err != nil {
		return nil, err
	}
	var uf usersFile
	if err := json.Unmarshal(data, &uf); err != nil {
		return nil, fmt.Errorf("%s: %v", s.Path, err)
	}
	d.users = uf.Users
	if s.RolesPath != "" {
		data, err := os.ReadFile(s.RolesPath)
		if err != nil && !os.IsNotExist(err) {
			return nil, err
		}
		if err == nil {
			var rf rolesFile
			if err := json.Unmarshal(data, &rf); err != nil {
				return nil, fmt.Errorf("%s: %v", s.RolesPath, err)
			}
			d.roles = rf.Roles
		}
	}
	return d, nil
}

func (s *Store) save(d *db) error {
	sort.Slice(d.users, func(i, j int) bool { return d.users[i].Name < d.users[j].Name })
	data, err := json.MarshalIndent(usersFile{Users: d.users}, "", "  ")
	if err != nil {
		return err
	}
	if err := writeAtomic(s.Path, append(data, '\n'), 0o600); err != nil {
		return err
	}
	if s.RolesPath != "" {
		sort.Slice(d.roles, func(i, j int) bool { return d.roles[i].Name < d.roles[j].Name })
		data, err := json.MarshalIndent(rolesFile{Roles: append([]Role{}, d.roles...)}, "", "  ")
		if err != nil {
			return err
		}
		if err := writeAtomic(s.RolesPath, append(data, '\n'), 0o600); err != nil {
			return err
		}
	}
	return nil
}

// errNoSave ends an update without writing.
var errNoSave = errors.New("no change")

// update runs fn on the loaded database under the lock and saves it.
func (s *Store) update(fn func(d *db) error) error {
	unlock, err := s.lock()
	if err != nil {
		return err
	}
	defer unlock()
	d, err := s.load()
	if err != nil {
		return err
	}
	if err := fn(d); err != nil {
		if errors.Is(err, errNoSave) {
			return nil
		}
		return err
	}
	return s.save(d)
}

func (s *Store) read() (*db, error) {
	unlock, err := s.lock()
	if err != nil {
		return nil, err
	}
	defer unlock()
	return s.load()
}

// Open makes sure the user database exists: the first time, it imports the
// old web user file (admin becomes a superuser with the same password)
// and admin's deploy-time SSH key. admin is always present.
func (s *Store) Open() error {
	unlock, err := s.lock()
	if err != nil {
		return err
	}
	defer unlock()
	d, err := s.load()
	if os.IsNotExist(err) {
		d = s.migrate()
		if err := s.save(d); err != nil {
			return err
		}
		s.log().Info("user database created", "users", len(d.users), "path", s.Path)
		return nil
	}
	if err != nil {
		return err
	}
	if d.user(Admin) == nil {
		d.users = append(d.users, &user{Name: Admin, Role: RoleSuperuser, Source: "local", Created: s.now(), CreatedBy: "system"})
		s.log().Warn("user admin was missing from the user database; added back (set its password with fwctl web-passwd)")
		return s.save(d)
	}
	return nil
}

func (s *Store) migrate() *db {
	d := &db{}
	now := s.now()
	for name, hash := range readLegacy(s.Legacy) {
		if name != Admin && checkName(name) != nil {
			s.log().Warn("old web user not imported: not a valid user name", "user", name)
			continue
		}
		// Every old web user could do everything.
		d.users = append(d.users, &user{Name: name, Role: RoleSuperuser, Source: "local", Hash: hash, Created: now, CreatedBy: "migration"})
	}
	if d.user(Admin) == nil {
		d.users = append(d.users, &user{Name: Admin, Role: RoleSuperuser, Source: "local", Created: now, CreatedBy: "migration"})
	}
	if s.AdminKeys != "" {
		if data, err := os.ReadFile(s.AdminKeys); err == nil {
			a := d.user(Admin)
			for _, line := range strings.Split(string(data), "\n") {
				if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
					continue
				}
				k, err := ParseKey(line)
				if err != nil {
					s.log().Warn("admin SSH key not imported", "err", err)
					continue
				}
				a.SSHKeys = append(a.SSHKeys, k.Key)
			}
		}
	}
	return d
}

func readLegacy(path string) map[string]string {
	m := map[string]string{}
	if path == "" {
		return m
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return m
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if f := strings.Fields(line); len(f) == 2 {
			m[f[0]] = f[1]
		}
	}
	return m
}

func (s *Store) writeLegacy(hash string) {
	if s.Legacy == "" {
		return
	}
	data := "# Kept by SJB-OS for rollbacks to versions before multiple users; users live in users.json.\n" + Admin + " " + hash + "\n"
	if err := writeAtomic(s.Legacy, []byte(data), 0o600); err != nil {
		s.log().Warn("could not update the old web user file (only matters for a rollback)", "err", err)
	}
}

var nameRE = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)

// reserved names are refused as user names (system accounts and words
// that would read oddly in the log).
var reserved = map[string]bool{
	"root": true, "daemon": true, "bin": true, "sys": true, "sync": true, "games": true, "man": true, "lp": true,
	"mail": true, "news": true, "uucp": true, "proxy": true, "www-data": true, "backup": true, "list": true,
	"irc": true, "nobody": true, "systemd-network": true, "systemd-timesync": true, "messagebus": true,
	"sshd": true, "sjb-tls": true, "system": true, "bootstrap": true, "migration": true, "web": true, "cli": true,
	"frr": true, "_kea": true, "suricata": true,
}

func checkName(name string) error {
	if !nameRE.MatchString(name) {
		return fmt.Errorf("%w: user name %q: use 1-32 lower-case letters, digits, - or _, starting with a letter", ErrInvalid, name)
	}
	if reserved[name] {
		return fmt.Errorf("%w: %q is reserved", ErrInvalid, name)
	}
	return nil
}

func (s *Store) touch(u *user, by Caller) {
	u.Changed, u.ChangedBy = s.now(), by.Author()
}

// Users lists every user.
func (s *Store) Users() ([]UserInfo, error) {
	d, err := s.read()
	if err != nil {
		return nil, err
	}
	out := []UserInfo{}
	for _, u := range d.users {
		out = append(out, s.info(u))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// User returns one user.
func (s *Store) User(name string) (UserInfo, error) {
	d, err := s.read()
	if err != nil {
		return UserInfo{}, err
	}
	u := d.user(name)
	if u == nil {
		return UserInfo{}, fmt.Errorf("%w: no user %q", ErrNotFound, name)
	}
	return s.info(u), nil
}

// Principal resolves a user's current role. A disabled or unknown user, or
// a session (since) that started before the user's password was last
// changed, is refused. since zero skips that check.
func (s *Store) Principal(name string, since time.Time) (Principal, error) {
	d, err := s.read()
	if err != nil {
		return Principal{}, err
	}
	u := d.user(name)
	if u == nil {
		return Principal{}, fmt.Errorf("%w: %q is not an SJB-OS user", ErrForbidden, name)
	}
	if u.Disabled {
		return Principal{}, fmt.Errorf("%w: account %s is disabled", ErrForbidden, name)
	}
	if !since.IsZero() && u.PasswordChanged.After(since) {
		return Principal{}, fmt.Errorf("%w: the password of %s changed; log in again", ErrForbidden, name)
	}
	r, ok := d.role(u.Role)
	if !ok {
		// A role that has gone (it can't be deleted while in use, but the
		// file may be edited by hand) grants nothing.
		r = Role{Name: u.Role, Perms: map[Area]Level{}}
	}
	return Principal{Name: u.Name, Role: r}, nil
}

// Authenticate checks a web login. Five wrong passwords in a row lock the
// account for 15 minutes.
func (s *Store) Authenticate(name, pw, from string) (Principal, error) {
	var res error
	err := s.update(func(d *db) error {
		u := d.user(name)
		if u == nil || u.Hash == "" {
			CheckPassword(dummy(), pw)
			res = ErrBadLogin
			return errNoSave
		}
		now := s.now()
		if u.LockedUntil.After(now) {
			res = fmt.Errorf("%w: try again in %d minutes, or ask a superuser to unlock it", ErrLocked, int(u.LockedUntil.Sub(now).Minutes())+1)
			return errNoSave
		}
		if !CheckPassword(u.Hash, pw) {
			u.Failures++
			res = ErrBadLogin
			if u.Failures >= LockoutFailures {
				u.Failures, u.LockedUntil = 0, now.Add(LockoutTime)
				s.log().Warn("account locked after failed logins", "user", name, "minutes", int(LockoutTime.Minutes()), "from", from)
			}
			return nil
		}
		if u.Disabled {
			res = ErrDisabled
			return errNoSave
		}
		u.Failures, u.LastLogin = 0, now
		return nil
	})
	if err != nil {
		return Principal{}, err
	}
	if res != nil {
		return Principal{}, res
	}
	return s.Principal(name, time.Time{})
}

// AddUser creates a user with a role and password, and its Unix login.
func (s *Store) AddUser(by Caller, name, role, pw string) error {
	if err := checkName(name); err != nil {
		return err
	}
	if err := CheckNewPassword(pw); err != nil {
		return err
	}
	return s.update(func(d *db) error {
		if d.user(name) != nil {
			return fmt.Errorf("%w: user %q already exists", ErrInvalid, name)
		}
		if _, ok := d.role(role); !ok {
			return fmt.Errorf("%w: no role %q", ErrInvalid, role)
		}
		if s.Sys != nil {
			if exists, ours := s.Sys.Lookup(name); exists && !ours {
				return fmt.Errorf("%w: %q is already a system account on the appliance", ErrInvalid, name)
			}
			if err := s.Sys.Ensure(name, true); err != nil {
				return err
			}
			if err := s.Sys.SetPassword(name, pw); err != nil {
				s.Sys.Remove(name)
				return err
			}
		}
		h, err := HashPassword(pw)
		if err != nil {
			return err
		}
		now := s.now()
		d.users = append(d.users, &user{Name: name, Role: role, Source: "local", Hash: h, PasswordChanged: now,
			Created: now, CreatedBy: by.Author(), Changed: now, ChangedBy: by.Author()})
		s.log().Info("user added", "user", name, "role", role, "by", by.Author())
		return nil
	})
}

// UpdateUser changes a user's role and/or disabled state (nil: unchanged).
func (s *Store) UpdateUser(by Caller, name string, role *string, disabled *bool) error {
	return s.update(func(d *db) error {
		u := d.user(name)
		if u == nil {
			return fmt.Errorf("%w: no user %q", ErrNotFound, name)
		}
		if role != nil && *role != u.Role {
			if name == Admin {
				return fmt.Errorf("%w: admin is always a superuser", ErrInvalid)
			}
			if name == by.Name {
				return fmt.Errorf("%w: you can't change your own role", ErrInvalid)
			}
			if _, ok := d.role(*role); !ok {
				return fmt.Errorf("%w: no role %q", ErrInvalid, *role)
			}
			s.log().Info("user role changed", "user", name, "from", u.Role, "to", *role, "by", by.Author())
			u.Role = *role
			if s.Sys != nil {
				s.Sys.Terminate(name)
			}
		}
		if disabled != nil && *disabled != u.Disabled {
			if name == Admin {
				return fmt.Errorf("%w: admin can't be disabled", ErrInvalid)
			}
			if name == by.Name {
				return fmt.Errorf("%w: you can't disable your own account", ErrInvalid)
			}
			if s.Sys != nil {
				if err := s.Sys.Ensure(name, !*disabled); err != nil {
					return err
				}
			}
			u.Disabled = *disabled
			s.log().Info(map[bool]string{true: "user disabled", false: "user enabled"}[*disabled], "user", name, "by", by.Author())
		}
		s.touch(u, by)
		return nil
	})
}

// DeleteUser removes a user and its Unix login.
func (s *Store) DeleteUser(by Caller, name string) error {
	return s.update(func(d *db) error {
		if name == Admin {
			return fmt.Errorf("%w: admin can't be deleted", ErrInvalid)
		}
		if name == by.Name {
			return fmt.Errorf("%w: you can't delete your own account", ErrInvalid)
		}
		i := slices.IndexFunc(d.users, func(u *user) bool { return u.Name == name })
		if i < 0 {
			return fmt.Errorf("%w: no user %q", ErrNotFound, name)
		}
		if s.Sys != nil {
			if err := s.Sys.Remove(name); err != nil {
				return err
			}
		}
		d.users = slices.Delete(d.users, i, i+1)
		s.log().Info("user deleted", "user", name, "by", by.Author())
		return nil
	})
}

// ChangeOwnPassword changes the caller's password after checking the
// current one (a wrong one counts towards the lockout).
func (s *Store) ChangeOwnPassword(by Caller, current, pw string) error {
	if err := CheckNewPassword(pw); err != nil {
		return err
	}
	var wrong bool
	err := s.update(func(d *db) error {
		u := d.user(by.Name)
		if u == nil {
			return fmt.Errorf("%w: %q is not an SJB-OS user", ErrForbidden, by.Name)
		}
		if u.LockedUntil.After(s.now()) {
			return fmt.Errorf("%w: account locked; ask a superuser to unlock it", ErrInvalid)
		}
		if u.Hash == "" {
			return fmt.Errorf("%w: no password on record; ask a superuser to set one", ErrInvalid)
		}
		if !CheckPassword(u.Hash, current) {
			u.Failures++
			if u.Failures >= LockoutFailures {
				u.Failures, u.LockedUntil = 0, s.now().Add(LockoutTime)
				s.log().Warn("account locked after wrong current passwords", "user", by.Name)
			}
			wrong = true
			return nil
		}
		return s.setPassword(u, by, pw)
	})
	if err != nil {
		return err
	}
	if wrong {
		return fmt.Errorf("%w: current password is wrong", ErrInvalid)
	}
	return nil
}

// SetPassword sets any user's password (superusers, and root's recovery
// command). The user's other sessions end.
func (s *Store) SetPassword(by Caller, name, pw string) error {
	if err := CheckNewPassword(pw); err != nil {
		return err
	}
	return s.update(func(d *db) error {
		u := d.user(name)
		if u == nil {
			return fmt.Errorf("%w: no user %q", ErrNotFound, name)
		}
		if s.Sys != nil && name != Admin {
			if err := s.Sys.Ensure(name, !u.Disabled); err != nil {
				return err
			}
		}
		if err := s.setPassword(u, by, pw); err != nil {
			return err
		}
		if s.Sys != nil && name != by.Name {
			s.Sys.Terminate(name)
		}
		return nil
	})
}

// setPassword: the login password first (if that fails nothing changes),
// then the hash; clears any lockout.
func (s *Store) setPassword(u *user, by Caller, pw string) error {
	if s.Sys != nil {
		if err := s.Sys.SetPassword(u.Name, pw); err != nil {
			return err
		}
		s.Sys.ResetFailures(u.Name)
	}
	h, err := HashPassword(pw)
	if err != nil {
		return err
	}
	u.Hash, u.PasswordChanged, u.Failures, u.LockedUntil = h, s.now(), 0, time.Time{}
	s.touch(u, by)
	if u.Name == Admin {
		s.writeLegacy(h)
	}
	s.log().Info("password changed", "user", u.Name, "by", by.Author())
	return nil
}

// Unlock clears a user's lockout (web, SSH and console).
func (s *Store) Unlock(by Caller, name string) error {
	return s.update(func(d *db) error {
		u := d.user(name)
		if u == nil {
			return fmt.Errorf("%w: no user %q", ErrNotFound, name)
		}
		u.Failures, u.LockedUntil = 0, time.Time{}
		if s.Sys != nil {
			s.Sys.ResetFailures(name)
		}
		s.touch(u, by)
		s.log().Info("user unlocked", "user", name, "by", by.Author())
		return nil
	})
}

// AddKey adds an SSH public key to a user.
func (s *Store) AddKey(by Caller, name, line string) (KeyInfo, error) {
	k, err := ParseKey(line)
	if err != nil {
		return KeyInfo{}, err
	}
	err = s.update(func(d *db) error {
		u := d.user(name)
		if u == nil {
			return fmt.Errorf("%w: no user %q", ErrNotFound, name)
		}
		for _, have := range keyInfos(u.SSHKeys) {
			if have.Fingerprint == k.Fingerprint {
				return fmt.Errorf("%w: %s already has that key", ErrInvalid, name)
			}
		}
		if len(u.SSHKeys) >= maxKeys {
			return fmt.Errorf("%w: at most %d keys per user", ErrInvalid, maxKeys)
		}
		keys := append(slices.Clone(u.SSHKeys), k.Key)
		if s.Sys != nil {
			if err := s.Sys.WriteKeys(name, keys); err != nil {
				return err
			}
		}
		u.SSHKeys = keys
		s.touch(u, by)
		s.log().Info("SSH key added", "user", name, "fingerprint", k.Fingerprint, "by", by.Author())
		return nil
	})
	return k, err
}

// DeleteKey removes a user's SSH key by fingerprint (or its number in the
// list, from 1).
func (s *Store) DeleteKey(by Caller, name, which string) error {
	return s.update(func(d *db) error {
		u := d.user(name)
		if u == nil {
			return fmt.Errorf("%w: no user %q", ErrNotFound, name)
		}
		idx := -1
		infos := keyInfos(u.SSHKeys)
		for i, k := range infos {
			if k.Fingerprint == which || fmt.Sprint(i+1) == which {
				idx = i
			}
		}
		if idx < 0 {
			return fmt.Errorf("%w: %s has no key %q (show ssh-keys lists them)", ErrNotFound, name, which)
		}
		var keys []string
		for i, k := range infos {
			if i != idx {
				keys = append(keys, k.Key)
			}
		}
		if s.Sys != nil {
			if err := s.Sys.WriteKeys(name, keys); err != nil {
				return err
			}
		}
		u.SSHKeys = keys
		s.touch(u, by)
		s.log().Info("SSH key deleted", "user", name, "fingerprint", infos[idx].Fingerprint, "by", by.Author())
		return nil
	})
}

// Roles lists the built-in roles, then the custom ones.
func (s *Store) Roles() ([]Role, error) {
	d, err := s.read()
	if err != nil {
		return nil, err
	}
	out := append(BuiltinRoles(), d.roles...)
	sortRoles(out)
	return out, nil
}

// RoleUsers lists who has each role.
func (s *Store) RoleUsers() (map[string][]string, error) {
	d, err := s.read()
	if err != nil {
		return nil, err
	}
	m := map[string][]string{}
	for _, u := range d.users {
		m[u.Role] = append(m[u.Role], u.Name)
	}
	return m, nil
}

// PutRole creates or replaces a custom role. Users who have it get the new
// permissions on their next request.
func (s *Store) PutRole(by Caller, r Role) error {
	if err := checkCustom(&r); err != nil {
		return err
	}
	return s.update(func(d *db) error {
		i := slices.IndexFunc(d.roles, func(x Role) bool { return x.Name == r.Name })
		if i >= 0 {
			d.roles[i] = r
			s.log().Info("role changed", "role", r.Name, "by", by.Author())
		} else {
			d.roles = append(d.roles, r)
			s.log().Info("role added", "role", r.Name, "by", by.Author())
		}
		return nil
	})
}

// DeleteRole removes a custom role nobody has.
func (s *Store) DeleteRole(by Caller, name string) error {
	return s.update(func(d *db) error {
		if _, ok := builtinRole(name); ok {
			return fmt.Errorf("%w: %q is a built-in role", ErrInvalid, name)
		}
		i := slices.IndexFunc(d.roles, func(x Role) bool { return x.Name == name })
		if i < 0 {
			return fmt.Errorf("%w: no role %q", ErrNotFound, name)
		}
		var users []string
		for _, u := range d.users {
			if u.Role == name {
				users = append(users, u.Name)
			}
		}
		if len(users) > 0 {
			return fmt.Errorf("%w: role %s is in use by %s; give them another role first", ErrInvalid, name, strings.Join(users, ", "))
		}
		d.roles = slices.Delete(d.roles, i, i+1)
		s.log().Info("role deleted", "role", name, "by", by.Author())
		return nil
	})
}

// Reconcile brings the Unix side in line with the database: every user has
// a login (locked when disabled) and its SSH keys; logins SJB-OS created
// for users that are gone are locked. ngfwd runs it at start.
func (s *Store) Reconcile() {
	if s.Sys == nil {
		return
	}
	d, err := s.read()
	if err != nil {
		s.log().Error("user database unreadable; Unix accounts not checked", "err", err)
		return
	}
	known := map[string]bool{}
	for _, u := range d.users {
		known[u.Name] = true
		if u.Name != Admin {
			exists, _ := s.Sys.Lookup(u.Name)
			if err := s.Sys.Ensure(u.Name, !u.Disabled); err != nil {
				s.log().Error("user's login not set up", "user", u.Name, "err", err)
				continue
			}
			if !exists {
				s.log().Warn("user's login re-created without a password; a superuser must set one for SSH and the console", "user", u.Name)
			}
		}
		if err := s.Sys.WriteKeys(u.Name, u.SSHKeys); err != nil {
			s.log().Error("user's SSH keys not written", "user", u.Name, "err", err)
		}
	}
	for _, n := range s.Sys.Ours() {
		if !known[n] {
			if err := s.Sys.Ensure(n, false); err != nil {
				s.log().Error("stray SJB-OS login not locked", "user", n, "err", err)
			} else {
				s.log().Warn("login of a user not in the user database locked", "user", n)
			}
		}
	}
}
