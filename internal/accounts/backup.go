package accounts

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"
	"time"
)

// HashSystem is the part of the Unix side backups need: reading and
// setting a login's password hash, so restored users keep their passwords
// on SSH and the console.
type HashSystem interface {
	// ShadowHash returns the account's crypt(3) password hash, without the
	// lock mark ("" when it has no password).
	ShadowHash(name string) (string, error)
	// SetPasswordHash sets the account's password hash (chpasswd -e).
	SetPasswordHash(name, hash string) error
}

// ShadowHash reads the hash from the shadow file.
func (e *Exec) ShadowHash(name string) (string, error) {
	path := e.Shadow
	if path == "" {
		path = "/etc/shadow"
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		p := strings.Split(sc.Text(), ":")
		if len(p) >= 2 && p[0] == name {
			return usableHash(p[1]), nil
		}
	}
	return "", nil
}

// usableHash strips the lock marks usermod adds and returns "" for no
// password (*, !, empty).
func usableHash(h string) string {
	h = strings.TrimLeft(h, "!")
	if !strings.HasPrefix(h, "$") {
		return ""
	}
	return h
}

// SetPasswordHash sets a hash with chpasswd -e.
func (e *Exec) SetPasswordHash(name, hash string) error {
	if !validCryptHash(hash) || strings.ContainsAny(name, ":\n") {
		return fmt.Errorf("%w: not a password hash", ErrInvalid)
	}
	cmd := exec.Command("chpasswd", "-e")
	cmd.Stdin = strings.NewReader(name + ":" + hash + "\n")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("chpasswd: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func validCryptHash(h string) bool {
	return strings.HasPrefix(h, "$") && len(h) < 512 && !strings.ContainsAny(h, ":\n\r ")
}

// Snapshot is what a backup holds of the users and roles.
type Snapshot struct {
	Users []SnapshotUser `json:"users"`
	Roles []Role         `json:"roles"` // custom roles only
}

// SnapshotUser is one user in a backup: their role, state, keys and both
// password hashes (web UI and Unix login).
type SnapshotUser struct {
	Name     string   `json:"name"`
	Role     string   `json:"role"`
	Disabled bool     `json:"disabled,omitempty"`
	Hash     string   `json:"hash,omitempty"`      // the web UI's (PBKDF2)
	UnixHash string   `json:"unix_hash,omitempty"` // the login's (crypt)
	SSHKeys  []string `json:"ssh_keys,omitempty"`
}

// Snapshot returns every user and custom role, for a backup. Unix
// password hashes are read when the Unix side can give them.
func (s *Store) Snapshot() (Snapshot, []string, error) {
	d, err := s.read()
	if err != nil {
		return Snapshot{}, nil, err
	}
	hs, _ := s.Sys.(HashSystem)
	var warns []string
	snap := Snapshot{Users: []SnapshotUser{}, Roles: slices.Clone(d.roles)}
	if snap.Roles == nil {
		snap.Roles = []Role{}
	}
	for _, u := range d.users {
		su := SnapshotUser{Name: u.Name, Role: u.Role, Disabled: u.Disabled, Hash: u.Hash, SSHKeys: slices.Clone(u.SSHKeys)}
		if hs != nil {
			h, err := hs.ShadowHash(u.Name)
			switch {
			case err != nil:
				warns = append(warns, fmt.Sprintf("%s: login password not backed up: %v", u.Name, err))
			case h == "" && u.Hash != "":
				warns = append(warns, fmt.Sprintf("%s: has no login password to back up", u.Name))
			}
			su.UnixHash = h
		}
		snap.Users = append(snap.Users, su)
	}
	return snap, warns, nil
}

// RestoreResult says what a restore of users and roles did.
type RestoreResult struct {
	Added    []string `json:"added"`
	Updated  []string `json:"updated"`
	Kept     []string `json:"kept"`    // users the backup doesn't have: left as they are
	Skipped  []string `json:"skipped"` // users not restored (admin, the caller)
	Roles    []string `json:"roles"`   // custom roles added or replaced
	Warnings []string `json:"warnings,omitempty"`
}

// Restore merges a backup's users and roles into the database: custom
// roles are added or replaced by name (none deleted); users are added or
// updated with their role, state, SSH keys and both password hashes;
// users the backup lacks are kept. admin and the caller are never
// changed (admin keeps its password and keys). Everything is checked
// before anything changes.
func (s *Store) Restore(by Caller, snap Snapshot) (RestoreResult, error) {
	res := RestoreResult{Added: []string{}, Updated: []string{}, Kept: []string{}, Skipped: []string{}, Roles: []string{}}
	roles := make([]Role, len(snap.Roles))
	for i, r := range snap.Roles {
		r := r
		if err := checkCustom(&r); err != nil {
			return res, fmt.Errorf("backup role %q: %w", snap.Roles[i].Name, err)
		}
		roles[i] = r
	}
	seen := map[string]bool{}
	for _, u := range snap.Users {
		if err := checkName(u.Name); err != nil {
			return res, fmt.Errorf("backup user %q: %w", u.Name, err)
		}
		if seen[u.Name] {
			return res, fmt.Errorf("%w: backup lists user %q twice", ErrInvalid, u.Name)
		}
		seen[u.Name] = true
		if u.UnixHash != "" && !validCryptHash(u.UnixHash) {
			return res, fmt.Errorf("%w: backup user %q: bad login password hash", ErrInvalid, u.Name)
		}
		if u.Hash != "" && !strings.HasPrefix(u.Hash, "pbkdf2") {
			return res, fmt.Errorf("%w: backup user %q: bad password hash", ErrInvalid, u.Name)
		}
		for _, k := range u.SSHKeys {
			if _, err := ParseKey(k); err != nil {
				return res, fmt.Errorf("backup user %q: %w", u.Name, err)
			}
		}
	}
	hs, _ := s.Sys.(HashSystem)
	err := s.update(func(d *db) error {
		for _, r := range roles {
			if i := slices.IndexFunc(d.roles, func(x Role) bool { return x.Name == r.Name }); i >= 0 {
				d.roles[i] = r
			} else {
				d.roles = append(d.roles, r)
			}
			res.Roles = append(res.Roles, r.Name)
		}
		for _, su := range snap.Users {
			if _, ok := d.role(su.Role); !ok {
				return fmt.Errorf("%w: backup user %q has role %q, which neither the backup nor this firewall has", ErrInvalid, su.Name, su.Role)
			}
		}
		for _, su := range snap.Users {
			if su.Name == Admin || su.Name == by.Name {
				res.Skipped = append(res.Skipped, su.Name)
				continue
			}
			u := d.user(su.Name)
			isNew := u == nil
			if s.Sys != nil {
				if exists, ours := s.Sys.Lookup(su.Name); exists && !ours {
					res.Warnings = append(res.Warnings, fmt.Sprintf("%s: a system account of that name exists; not restored", su.Name))
					res.Skipped = append(res.Skipped, su.Name)
					continue
				}
				if err := s.Sys.Ensure(su.Name, !su.Disabled); err != nil {
					return fmt.Errorf("%s: %w", su.Name, err)
				}
				switch {
				case su.UnixHash != "" && hs != nil:
					if err := hs.SetPasswordHash(su.Name, su.UnixHash); err != nil {
						return fmt.Errorf("%s: %w", su.Name, err)
					}
					if su.Disabled { // a new hash unlocks the login
						if err := s.Sys.Ensure(su.Name, false); err != nil {
							return fmt.Errorf("%s: %w", su.Name, err)
						}
					}
				case su.Hash != "":
					res.Warnings = append(res.Warnings, fmt.Sprintf("%s: the backup has no login password: set one (request user password %s) before they use SSH or the console", su.Name, su.Name))
				}
				if err := s.Sys.WriteKeys(su.Name, su.SSHKeys); err != nil {
					return fmt.Errorf("%s: %w", su.Name, err)
				}
				s.Sys.Terminate(su.Name)
			}
			now := s.now()
			if isNew {
				u = &user{Name: su.Name, Source: "local", Created: now, CreatedBy: by.Author()}
				d.users = append(d.users, u)
				res.Added = append(res.Added, su.Name)
			} else {
				res.Updated = append(res.Updated, su.Name)
			}
			if u.Hash != su.Hash {
				u.PasswordChanged = now
			}
			u.Role, u.Disabled, u.Hash, u.SSHKeys = su.Role, su.Disabled, su.Hash, slices.Clone(su.SSHKeys)
			u.Failures, u.LockedUntil = 0, time.Time{}
			s.touch(u, by)
		}
		for _, u := range d.users {
			if !seen[u.Name] {
				res.Kept = append(res.Kept, u.Name)
			}
		}
		return nil
	})
	if err != nil {
		return RestoreResult{}, err
	}
	s.log().Info("users and roles restored from a backup", "added", len(res.Added), "updated", len(res.Updated),
		"roles", len(res.Roles), "by", by.Author())
	return res, nil
}
