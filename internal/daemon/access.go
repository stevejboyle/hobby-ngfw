package daemon

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/stevejboyle/sjb-os/internal/accounts"
	"github.com/stevejboyle/sjb-os/internal/logs"
)

// Access control. Every management call (CLI over the socket, web UI)
// carries a Caller: who is asking, worked out by ngfwd itself (the socket
// peer's Unix user, the web session), never what the client says. Each
// call is checked against the caller's current role; config changes are
// also checked against the areas they touch.

type callerKey struct{}

// WithCaller attaches the caller to a request context.
func WithCaller(ctx context.Context, c accounts.Caller) context.Context {
	return context.WithValue(ctx, callerKey{}, c)
}

// CallerFrom returns the caller attached to ctx.
func CallerFrom(ctx context.Context) (accounts.Caller, bool) {
	c, ok := ctx.Value(callerKey{}).(accounts.Caller)
	return c, ok
}

// SetAccounts sets the user database. Without one (tests, development)
// every caller is treated as a superuser.
func (d *Daemon) SetAccounts(a *accounts.Store) { d.accounts = a }

// Accounts returns the user database (nil if none).
func (d *Daemon) Accounts() *accounts.Store { return d.accounts }

// SetLogs sets where the Logs views read from.
func (d *Daemon) SetLogs(r logs.Reader) { d.logs = r }

// SetAPIKeysFile sets the tag API key file that superusers can read.
func (d *Daemon) SetAPIKeysFile(path string) { d.apiKeysFile = path }

// Principal resolves a caller's current role.
func (d *Daemon) Principal(c accounts.Caller) (accounts.Principal, error) {
	if c.Via == "root" || c.Via == "system" {
		p := accounts.RootPrincipal()
		p.Name = c.Name
		return p, nil
	}
	if d.accounts == nil {
		p := accounts.RootPrincipal()
		p.Name = c.Name
		return p, nil
	}
	return d.accounts.Principal(c.Name, time.Time{})
}

// Authorize returns the caller's principal if it meets need, or an
// ErrForbidden error.
func (d *Daemon) Authorize(c accounts.Caller, need accounts.Need) (accounts.Principal, error) {
	p, err := d.Principal(c)
	if err != nil {
		return p, err
	}
	return p, p.Check(need)
}

// --- config changes, checked by area ---------------------------------------

// SetCandidateAs replaces the candidate if the caller may change every area
// the edit touches.
func (d *Daemon) SetCandidateAs(c accounts.Caller, data []byte) error {
	p, err := d.Authorize(c, accounts.ConfigEdit)
	if err != nil {
		return err
	}
	if _, err := parse(data); err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	old, err := d.store.Candidate()
	if err != nil {
		return err
	}
	if err := p.CheckConfigChange("edit", old, data); err != nil {
		return err
	}
	return d.store.SetCandidate(data)
}

// RevertCandidateAs discards uncommitted changes if the caller may change
// every area they touch (they may be someone else's).
func (d *Daemon) RevertCandidateAs(c accounts.Caller) error {
	p, err := d.Authorize(c, accounts.ConfigEdit)
	if err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	_, run, err := d.store.Running()
	if err != nil {
		return err
	}
	cand, err := d.store.Candidate()
	if err != nil {
		return err
	}
	if err := p.CheckConfigChange("revert", cand, run); err != nil {
		return err
	}
	return d.store.SetCandidate(run)
}

// CommitAs commits the candidate as the caller. The candidate is shared, so
// the whole running-to-candidate change must be within the caller's areas,
// including edits someone else made.
func (d *Daemon) CommitAs(c accounts.Caller, message string, confirm time.Duration) (*CommitResult, error) {
	p, err := d.Authorize(c, accounts.ConfigEdit)
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	cand, err := d.store.Candidate()
	if err != nil {
		return nil, err
	}
	if len(strings.TrimSpace(string(cand))) == 0 {
		return nil, fmt.Errorf("%w: candidate config is empty", ErrInvalid)
	}
	_, run, err := d.store.Running()
	if err != nil {
		return nil, err
	}
	if err := p.CheckConfigChange("commit", run, cand); err != nil {
		return nil, err
	}
	return d.commitLocked(cand, c.Author(), message, confirm)
}

// RollbackAs re-commits revision n as the caller (revisions change, plus
// change on every area the rollback touches).
func (d *Daemon) RollbackAs(c accounts.Caller, n int) (*CommitResult, error) {
	p, err := d.Authorize(c, accounts.NeedChange(accounts.Revisions))
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	data, err := d.store.Get(n)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	_, run, err := d.store.Running()
	if err != nil {
		return nil, err
	}
	if err := p.CheckConfigChange("rollback", run, data); err != nil {
		return nil, err
	}
	return d.commitLocked(data, c.Author(), fmt.Sprintf("rollback to %d", n), 0)
}

// ConfirmAs accepts a pending commit.
func (d *Daemon) ConfirmAs(c accounts.Caller) error {
	if _, err := d.Authorize(c, accounts.NeedChange(accounts.Revisions)); err != nil {
		return err
	}
	if err := d.Confirm(); err != nil {
		return err
	}
	d.log.Info("commit confirmed by", "by", c.Author())
	return nil
}

// RegisterTagsAs and UnregisterTagsAs record who changed the tags.
func (d *Daemon) RegisterTagsAs(c accounts.Caller, ip netip.Addr, tagList []string, ttl time.Duration) error {
	if err := d.RegisterTags(ip, tagList, ttl); err != nil {
		return err
	}
	d.log.Info("tags registered", "ip", ip, "tags", strings.Join(tagList, ","), "ttl", ttl, "by", c.Author())
	return nil
}

func (d *Daemon) UnregisterTagsAs(c accounts.Caller, ip netip.Addr, tagList []string) error {
	if err := d.UnregisterTags(ip, tagList); err != nil {
		return err
	}
	d.log.Info("tags unregistered", "ip", ip, "tags", strings.Join(tagList, ","), "by", c.Author())
	return nil
}

// --- who am I ----------------------------------------------------------------

// Me describes the caller and what their role allows.
type Me struct {
	Name        string                           `json:"name"`
	Via         string                           `json:"via"`
	Role        string                           `json:"role"`
	Superuser   bool                             `json:"superuser"`
	Permissions map[accounts.Area]accounts.Level `json:"permissions"`
	ConfigView  bool                             `json:"config_view"`
	ConfigEdit  bool                             `json:"config_edit"`
	Areas       []accounts.AreaInfo              `json:"areas"`
}

// Me returns the caller's identity and permissions.
func (d *Daemon) Me(c accounts.Caller) (Me, error) {
	p, err := d.Principal(c)
	if err != nil {
		return Me{}, err
	}
	return Me{Name: p.Name, Via: c.Via, Role: p.Role.Name, Superuser: p.Superuser(), Permissions: p.Permissions(),
		ConfigView: p.Allows(accounts.ConfigView), ConfigEdit: p.Allows(accounts.ConfigEdit), Areas: accounts.Areas}, nil
}

// --- users and roles (superusers; a user may see and change their own
// password and SSH keys) ----------------------------------------------------

func (d *Daemon) needAccounts() error {
	if d.accounts == nil {
		return fmt.Errorf("%w: no user database on this host", ErrInvalid)
	}
	return nil
}

// selfOrSuper allows a superuser, or the user acting on their own account.
func (d *Daemon) selfOrSuper(c accounts.Caller, name string) error {
	if err := d.needAccounts(); err != nil {
		return err
	}
	p, err := d.Principal(c)
	if err != nil {
		return err
	}
	if p.Superuser() || (c.Name == name && c.Via != "root") {
		return nil
	}
	return p.Check(accounts.SuperuserOnly)
}

func (d *Daemon) super(c accounts.Caller) error {
	if err := d.needAccounts(); err != nil {
		return err
	}
	_, err := d.Authorize(c, accounts.SuperuserOnly)
	return err
}

// Users lists every user (superusers).
func (d *Daemon) Users(c accounts.Caller) ([]accounts.UserInfo, error) {
	if err := d.super(c); err != nil {
		return nil, err
	}
	return d.accounts.Users()
}

// User shows one user (superusers, or the user themself).
func (d *Daemon) User(c accounts.Caller, name string) (accounts.UserInfo, error) {
	if err := d.selfOrSuper(c, name); err != nil {
		return accounts.UserInfo{}, err
	}
	return d.accounts.User(name)
}

// AddUser creates a user (superusers).
func (d *Daemon) AddUser(c accounts.Caller, name, role, pw string) error {
	if err := d.super(c); err != nil {
		return err
	}
	return d.accounts.AddUser(c, name, role, pw)
}

// UpdateUser changes a user's role or disabled state (superusers).
func (d *Daemon) UpdateUser(c accounts.Caller, name string, role *string, disabled *bool) error {
	if err := d.super(c); err != nil {
		return err
	}
	return d.accounts.UpdateUser(c, name, role, disabled)
}

// DeleteUser removes a user (superusers).
func (d *Daemon) DeleteUser(c accounts.Caller, name string) error {
	if err := d.super(c); err != nil {
		return err
	}
	return d.accounts.DeleteUser(c, name)
}

// SetUserPassword sets another user's password (superusers).
func (d *Daemon) SetUserPassword(c accounts.Caller, name, pw string) error {
	if err := d.super(c); err != nil {
		return err
	}
	return d.accounts.SetPassword(c, name, pw)
}

// UnlockUser clears a lockout (superusers).
func (d *Daemon) UnlockUser(c accounts.Caller, name string) error {
	if err := d.super(c); err != nil {
		return err
	}
	return d.accounts.Unlock(c, name)
}

// ChangeOwnPassword changes the caller's password (current one required).
func (d *Daemon) ChangeOwnPassword(c accounts.Caller, current, pw string) error {
	if err := d.needAccounts(); err != nil {
		return err
	}
	if _, err := d.Principal(c); err != nil {
		return err
	}
	return d.accounts.ChangeOwnPassword(c, current, pw)
}

// AddSSHKey adds a key to a user (superusers, or the user themself).
func (d *Daemon) AddSSHKey(c accounts.Caller, name, key string) (accounts.KeyInfo, error) {
	if err := d.selfOrSuper(c, name); err != nil {
		return accounts.KeyInfo{}, err
	}
	return d.accounts.AddKey(c, name, key)
}

// DeleteSSHKey removes a user's key by fingerprint or number.
func (d *Daemon) DeleteSSHKey(c accounts.Caller, name, which string) error {
	if err := d.selfOrSuper(c, name); err != nil {
		return err
	}
	return d.accounts.DeleteKey(c, name, which)
}

// RoleInfo is a role with who has it.
type RoleInfo struct {
	accounts.Role
	Users []string `json:"users"`
}

// Roles lists every role (superusers).
func (d *Daemon) Roles(c accounts.Caller) ([]RoleInfo, error) {
	if err := d.super(c); err != nil {
		return nil, err
	}
	rs, err := d.accounts.Roles()
	if err != nil {
		return nil, err
	}
	who, err := d.accounts.RoleUsers()
	if err != nil {
		return nil, err
	}
	out := make([]RoleInfo, len(rs))
	for i, r := range rs {
		out[i] = RoleInfo{Role: r, Users: who[r.Name]}
		if out[i].Users == nil {
			out[i].Users = []string{}
		}
	}
	return out, nil
}

// PutRole creates or replaces a custom role (superusers).
func (d *Daemon) PutRole(c accounts.Caller, r accounts.Role) error {
	if err := d.super(c); err != nil {
		return err
	}
	return d.accounts.PutRole(c, r)
}

// DeleteRole removes an unused custom role (superusers).
func (d *Daemon) DeleteRole(c accounts.Caller, name string) error {
	if err := d.super(c); err != nil {
		return err
	}
	return d.accounts.DeleteRole(c, name)
}

// APIKeys returns the tag API key file (superusers: the keys are secrets).
func (d *Daemon) APIKeys(c accounts.Caller) ([]byte, error) {
	if _, err := d.Authorize(c, accounts.SuperuserOnly); err != nil {
		return nil, err
	}
	if d.apiKeysFile == "" {
		return nil, fmt.Errorf("%w: no tag API key file", ErrInvalid)
	}
	data, err := os.ReadFile(d.apiKeysFile)
	if err != nil {
		return nil, fmt.Errorf("%w: no tag API key file", accounts.ErrNotFound)
	}
	return data, nil
}

// Logs reads one of the logs (traffic, threat, decryption, system).
func (d *Daemon) Logs(kind string, n int, q string) (any, error) {
	if d.logs == nil {
		return nil, fmt.Errorf("logs aren't available on this host")
	}
	switch kind {
	case "traffic":
		return d.logs.Traffic(n, q)
	case "system":
		return d.logs.System(n, q)
	case "threat":
		return d.logs.Threat(n, q)
	case "decryption":
		return d.logs.Decryption(n, q)
	}
	return nil, fmt.Errorf("%w: logs are traffic, threat, decryption or system", accounts.ErrNotFound)
}
