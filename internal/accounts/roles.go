// Package accounts is SJB-OS's local user database and role-based access
// control: users (one password for SSH, the console and the web UI, SSH
// keys, lockout), built-in and custom roles, and the permission areas both
// the CLI (through ngfwd's management socket) and the web UI are checked
// against.
//
// Users and roles live in their own files under /etc/ngfw, not in the
// firewall config, so a config rollback never brings back a deleted user or
// an old password. Every user has Source "local" for now; an external
// identity provider (a later phase) adds other sources and maps its groups
// to these roles.
package accounts

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
)

// ErrInvalid marks bad input (HTTP 400); ErrForbidden a caller whose role
// doesn't allow the action (HTTP 403); ErrNotFound an unknown user or role.
var (
	ErrInvalid   = errors.New("invalid")
	ErrForbidden = errors.New("not allowed")
	ErrNotFound  = errors.New("not found")
)

// Area is a part of the firewall a role can view or change.
type Area string

// The permission areas. Users and roles are not an area: only superusers
// manage them, and no custom role can be given that.
const (
	Policy       Area = "policy"
	Network      Area = "network"
	DHCP         Area = "dhcp"
	IPS          Area = "ips"
	Decryption   Area = "decryption"
	DecryptionCA Area = "decryption-ca"
	Certificates Area = "certificates"
	Logging      Area = "logging"
	Tags         Area = "tags"
	Monitoring   Area = "monitoring"
	Revisions    Area = "revisions"
	Upgrades     Area = "upgrades"
)

// AreaInfo describes an area for the CLI and the web UI.
type AreaInfo struct {
	Area     Area   `json:"area"`
	Title    string `json:"title"`
	Covers   string `json:"covers"`
	ViewOnly bool   `json:"view_only,omitempty"`
}

// Areas lists every area in display order.
var Areas = []AreaInfo{
	{Policy, "Policy", "rules, addresses, address groups, services, application groups, zones, NAT, App Identification on/off", false},
	{Network, "Network", "interfaces, static routes, VRFs, BGP/OSPF, prefix lists, hostname", false},
	{DHCP, "DHCP", "DHCP servers, reservations and leases", false},
	{IPS, "IPS", "IPS profiles, exceptions, on/off, disabled signatures; signature updates", false},
	{Decryption, "Decryption", "decryption rules, profiles and exclusions; the learned list", false},
	{DecryptionCA, "Decryption CA", "the decryption CA: generate or import", false},
	{Certificates, "Management certificate", "the web UI and tag API certificate: import, or back to self-signed", false},
	{Logging, "Log forwarding", "syslog servers (a SIEM) the logs are forwarded to", false},
	{Tags, "Tags", "tag registrations (tag API key values: superusers only)", false},
	{Monitoring, "Monitoring", "logs, statistics, applications, ARP, routing status, ping", true},
	{Revisions, "Revisions", "commit history; change: confirm a commit, roll back", false},
	{Upgrades, "Upgrades", "SJB-OS upgrades and upgrade rollback", false},
}

// ConfigAreas are the areas that cover parts of the firewall config.
var ConfigAreas = []Area{Policy, Network, DHCP, IPS, Decryption, Logging}

func knownArea(a Area) (AreaInfo, bool) {
	for _, i := range Areas {
		if i.Area == a {
			return i, true
		}
	}
	return AreaInfo{}, false
}

// Level is what a role may do in an area: "" (nothing), "view" or
// "change" (change includes view).
type Level string

const (
	None   Level = ""
	View   Level = "view"
	Change Level = "change"
)

func (l Level) atLeast(want Level) bool {
	switch want {
	case None:
		return true
	case View:
		return l == View || l == Change
	case Change:
		return l == Change
	}
	return false
}

// Role is a set of permissions. Built-in roles can't be changed or
// deleted.
type Role struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	BuiltIn     bool           `json:"builtin"`
	Superuser   bool           `json:"superuser"`
	Perms       map[Area]Level `json:"permissions"`
}

// LevelOf returns the role's level in area a.
func (r Role) LevelOf(a Area) Level {
	if r.Superuser {
		return Change
	}
	return r.Perms[a]
}

// Built-in role names.
const (
	RoleSuperuser = "superuser"
	RoleAdmin     = "admin"
	RoleReadOnly  = "read-only"
)

// BuiltinRoles returns the built-in roles: superuser (everything, including
// users, roles, upgrades and the decryption CA), admin (changes and commits
// the config, rolls back, tags, IPS updates) and read-only.
func BuiltinRoles() []Role {
	all := func(l Level) map[Area]Level {
		m := map[Area]Level{}
		for _, a := range Areas {
			m[a.Area] = l
			if a.ViewOnly && l == Change {
				m[a.Area] = View
			}
		}
		return m
	}
	admin := all(View)
	for _, a := range []Area{Policy, Network, DHCP, IPS, Decryption, Certificates, Logging, Tags, Revisions} {
		admin[a] = Change
	}
	return []Role{
		{Name: RoleSuperuser, Description: "Everything, including users, roles, upgrades and the decryption CA", BuiltIn: true, Superuser: true, Perms: all(Change)},
		{Name: RoleAdmin, Description: "Change and commit the config, roll back, tags, IPS updates, log forwarding, the management certificate; not users, roles, upgrades or the decryption CA", BuiltIn: true, Perms: admin},
		{Name: RoleReadOnly, Description: "See everything except secrets; change nothing", BuiltIn: true, Perms: all(View)},
	}
}

func builtinRole(name string) (Role, bool) {
	for _, r := range BuiltinRoles() {
		if r.Name == name {
			return r, true
		}
	}
	return Role{}, false
}

var roleNameRE = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)

// checkCustom validates a custom role and normalises its permissions:
// unknown areas and levels are refused, view-only areas cap at view, and
// "none" entries are dropped.
func checkCustom(r *Role) error {
	if !roleNameRE.MatchString(r.Name) {
		return fmt.Errorf("%w: role name %q: use 1-32 lower-case letters, digits, - or _, starting with a letter", ErrInvalid, r.Name)
	}
	if _, ok := builtinRole(r.Name); ok {
		return fmt.Errorf("%w: %q is a built-in role", ErrInvalid, r.Name)
	}
	if r.Superuser {
		return fmt.Errorf("%w: a custom role can't be a superuser role (only superusers manage users and roles)", ErrInvalid)
	}
	if len(r.Description) > 200 {
		return fmt.Errorf("%w: description is longer than 200 characters", ErrInvalid)
	}
	perms := map[Area]Level{}
	for a, l := range r.Perms {
		info, ok := knownArea(a)
		if !ok {
			return fmt.Errorf("%w: unknown area %q (areas: %s)", ErrInvalid, a, areaList())
		}
		switch l {
		case None, "none":
			continue
		case View, Change:
		default:
			return fmt.Errorf("%w: area %s: level must be view, change or none, not %q", ErrInvalid, a, l)
		}
		if info.ViewOnly {
			l = View
		}
		perms[a] = l
	}
	r.Perms, r.BuiltIn = perms, false
	return nil
}

func areaList() string {
	s := ""
	for i, a := range Areas {
		if i > 0 {
			s += ", "
		}
		s += string(a.Area)
	}
	return s
}

// Principal is a resolved caller: who they are and the role they have now.
type Principal struct {
	Name string `json:"name"`
	Role Role   `json:"role"`
}

// Can reports whether the principal has at least level l in area a.
func (p Principal) Can(a Area, l Level) bool { return p.Role.LevelOf(a).atLeast(l) }

// Superuser reports whether the principal is a superuser.
func (p Principal) Superuser() bool { return p.Role.Superuser }

// CanAnyConfig reports whether the principal has at least level l in any
// config area.
func (p Principal) CanAnyConfig(l Level) bool {
	for _, a := range ConfigAreas {
		if p.Can(a, l) {
			return true
		}
	}
	return false
}

// Need is what an API call requires. The zero Need is invalid, so every
// route has to say what it needs.
type Need struct {
	kind  needKind
	area  Area
	level Level
}

type needKind int

const (
	needInvalid needKind = iota
	needAnyone
	needSuperuser
	needArea
	needConfig
)

var (
	// Anyone is any logged-in user (status, their own password and keys).
	Anyone = Need{kind: needAnyone}
	// SuperuserOnly is users, roles and secrets such as tag API keys.
	SuperuserOnly = Need{kind: needSuperuser}
	// ConfigView is view on any config area (the config is shown whole).
	ConfigView = Need{kind: needConfig, level: View}
	// ConfigEdit is change on any config area; the areas a change
	// actually touches are checked by the daemon.
	ConfigEdit = Need{kind: needConfig, level: Change}
)

// NeedView requires view in area a; NeedChange requires change.
func NeedView(a Area) Need   { return Need{kind: needArea, area: a, level: View} }
func NeedChange(a Area) Need { return Need{kind: needArea, area: a, level: Change} }

// Valid reports whether n was built by one of the constructors above.
func (n Need) Valid() bool { return n.kind != needInvalid }

// Allows reports whether p meets n.
func (p Principal) Allows(n Need) bool {
	switch n.kind {
	case needAnyone:
		return true
	case needSuperuser:
		return p.Superuser()
	case needArea:
		return p.Can(n.area, n.level)
	case needConfig:
		return p.CanAnyConfig(n.level)
	}
	return false
}

// String says what n requires, for error messages.
func (n Need) String() string {
	switch n.kind {
	case needAnyone:
		return "a login"
	case needSuperuser:
		return "a superuser"
	case needArea:
		return fmt.Sprintf("%s on %s", n.level, n.area)
	case needConfig:
		return fmt.Sprintf("%s on a config area", n.level)
	}
	return "an unknown permission"
}

// Check returns ErrForbidden, with what was missing, unless p meets n.
func (p Principal) Check(n Need) error {
	if p.Allows(n) {
		return nil
	}
	return fmt.Errorf("%w: %s (role %s) needs %s for this", ErrForbidden, p.Name, p.Role.Name, n)
}

// Permissions lists p's level in every area, for /v1/me and the web UI.
func (p Principal) Permissions() map[Area]Level {
	m := map[Area]Level{}
	for _, a := range Areas {
		if l := p.Role.LevelOf(a.Area); l != None {
			m[a.Area] = l
		}
	}
	return m
}

func sortRoles(rs []Role) {
	sort.SliceStable(rs, func(i, j int) bool {
		if rs[i].BuiltIn != rs[j].BuiltIn {
			return rs[i].BuiltIn
		}
		if rs[i].BuiltIn {
			return false // keep built-in order
		}
		return rs[i].Name < rs[j].Name
	})
}
