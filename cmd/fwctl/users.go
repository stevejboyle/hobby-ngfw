package main

// Users, roles and SSH keys in the captive CLI, and role-aware help. ngfwd
// decides what each caller may do; the CLI only hides what the caller's
// role can't use.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"
	"time"
)

// me is the caller as ngfwd sees them (GET /v1/me).
type me struct {
	Name        string            `json:"name"`
	Role        string            `json:"role"`
	Superuser   bool              `json:"superuser"`
	Permissions map[string]string `json:"permissions"`
	ConfigView  bool              `json:"config_view"`
	ConfigEdit  bool              `json:"config_edit"`
	Areas       []struct {
		Area     string `json:"area"`
		Title    string `json:"title"`
		Covers   string `json:"covers"`
		ViewOnly bool   `json:"view_only"`
	} `json:"areas"`
}

func fetchMe() (*me, error) {
	out, err := call("GET", "/v1/me", nil)
	if err != nil {
		return nil, err
	}
	var m me
	if err := json.Unmarshal(out, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

func (m *me) can(area, level string) bool {
	if m.Superuser {
		return true
	}
	l := m.Permissions[area]
	return l == "change" || (level == "view" && l == "view")
}

// commandNeeds maps the start of a command to what it needs, longest
// prefix first. Commands not listed are for everyone.
var commandNeeds = []struct {
	prefix string
	ok     func(m *me) bool
}{
	{"show decryption ca", func(m *me) bool { return m.can("decryption-ca", "view") }},
	{"request decryption ca", func(m *me) bool { return m.can("decryption-ca", "change") }},
	{"request decryption learned", func(m *me) bool { return m.can("decryption", "change") }},
	{"request ips", func(m *me) bool { return m.can("ips", "change") }},
	{"request user", func(m *me) bool { return m.Superuser }},
	{"request role", func(m *me) bool { return m.Superuser }},
	{"show running", func(m *me) bool { return m.ConfigView }},
	{"show candidate", func(m *me) bool { return m.ConfigView }},
	{"show diff", func(m *me) bool { return m.ConfigView }},
	{"show ruleset", func(m *me) bool { return m.ConfigView }},
	{"show revisions", func(m *me) bool { return m.can("revisions", "view") }},
	{"show revision", func(m *me) bool { return m.can("revisions", "view") }},
	{"show tags", func(m *me) bool { return m.can("tags", "view") }},
	{"show dhcp", func(m *me) bool { return m.can("dhcp", "view") }},
	{"show ips", func(m *me) bool { return m.can("ips", "view") }},
	{"show decryption", func(m *me) bool { return m.can("decryption", "view") }},
	{"show api-keys", func(m *me) bool { return m.Superuser }},
	{"show users", func(m *me) bool { return m.Superuser }},
	{"show user ", func(m *me) bool { return m.Superuser }},
	{"show roles", func(m *me) bool { return m.Superuser }},
	{"show role ", func(m *me) bool { return m.Superuser }},
	{"show app catalog", func(m *me) bool { return true }},
	{"show app categories", func(m *me) bool { return true }},
	{"show log", func(m *me) bool { return m.can("monitoring", "view") }},
	{"show statistics", func(m *me) bool { return m.can("monitoring", "view") }},
	{"show app", func(m *me) bool { return m.can("monitoring", "view") }},
	{"show interfaces", func(m *me) bool { return m.can("monitoring", "view") }},
	{"show arp", func(m *me) bool { return m.can("monitoring", "view") }},
	{"show routes", func(m *me) bool { return m.can("monitoring", "view") }},
	{"show vrf", func(m *me) bool { return m.can("monitoring", "view") }},
	{"show bgp", func(m *me) bool { return m.can("monitoring", "view") }},
	{"show ospf", func(m *me) bool { return m.can("monitoring", "view") }},
	{"show rib", func(m *me) bool { return m.can("monitoring", "view") }},
	{"ping", func(m *me) bool { return m.can("monitoring", "view") }},
	{"load", func(m *me) bool { return m.ConfigEdit }},
	{"revert", func(m *me) bool { return m.ConfigEdit }},
	{"commit", func(m *me) bool { return m.ConfigEdit }},
	{"configure", func(m *me) bool { return m.ConfigEdit }},
	{"confirm", func(m *me) bool { return m.can("revisions", "change") }},
	{"rollback", func(m *me) bool { return m.can("revisions", "change") }},
	{"tags register", func(m *me) bool { return m.can("tags", "change") }},
	{"tags unregister", func(m *me) bool { return m.can("tags", "change") }},
	{"tags", func(m *me) bool { return m.can("tags", "view") }},
}

// allowedCommand reports whether m's role can use the command line. With
// no identity (ngfwd unreachable), everything shows.
func allowedCommand(m *me, line string) bool {
	if m == nil || m.Superuser {
		return true
	}
	line = strings.Join(strings.Fields(line), " ") + " "
	for _, n := range commandNeeds {
		if strings.HasPrefix(line, strings.TrimSpace(n.prefix)+" ") {
			return n.ok(m)
		}
	}
	return true
}

// roleHelp keeps the help lines the role can use: a command line and its
// indented continuation lines go together.
func roleHelp(m *me, help string) string {
	if m == nil {
		return help
	}
	var b strings.Builder
	keep := true
	for _, line := range strings.SplitAfter(help, "\n") {
		trim := strings.TrimLeft(line, " ")
		indent := len(line) - len(trim)
		switch {
		case indent == 2 && trim != "" && trim != "\n":
			cmd := trim
			if i := strings.Index(cmd, "  "); i > 0 {
				cmd = cmd[:i]
			}
			keep = allowedCommand(m, strings.TrimSpace(cmd))
		case indent == 0:
			keep = true
		}
		if keep {
			b.WriteString(line)
		}
	}
	return b.String()
}

// --- show ---------------------------------------------------------------------

func showWhoami() error {
	m, err := fetchMe()
	if err != nil {
		return err
	}
	fmt.Printf("%s, role %s", m.Name, m.Role)
	if m.Superuser {
		fmt.Print(" (superuser: everything, including users and roles)")
	}
	fmt.Println()
	printPerms(m.Permissions, m)
	return nil
}

func printPerms(perms map[string]string, m *me) {
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	defer tw.Flush()
	fmt.Fprintln(tw, "  AREA\tACCESS\tCOVERS")
	for _, a := range m.Areas {
		l := perms[a.Area]
		if l == "" {
			l = "-"
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s\n", a.Area, l, a.Covers)
	}
}

type userInfo struct {
	Name        string     `json:"name"`
	Role        string     `json:"role"`
	Disabled    bool       `json:"disabled"`
	Locked      bool       `json:"locked"`
	LockedUntil *time.Time `json:"locked_until"`
	Permanent   bool       `json:"permanent"`
	PasswordSet bool       `json:"password_set"`
	LastLogin   *time.Time `json:"last_login"`
	SSHKeys     []struct {
		Type, Comment, Fingerprint string
	} `json:"ssh_keys"`
	Created   *time.Time `json:"created"`
	CreatedBy string     `json:"created_by"`
	Changed   *time.Time `json:"changed"`
	ChangedBy string     `json:"changed_by"`
}

func (u userInfo) status() string {
	var s []string
	switch {
	case u.Disabled:
		s = append(s, "disabled")
	case u.Locked:
		s = append(s, "locked until "+u.LockedUntil.Local().Format("15:04"))
	default:
		s = append(s, "active")
	}
	if !u.PasswordSet {
		s = append(s, "no password")
	}
	if u.Permanent {
		s = append(s, "permanent")
	}
	return strings.Join(s, ", ")
}

func when(t *time.Time) string {
	if t == nil {
		return "never"
	}
	return t.Local().Format("2006-01-02 15:04")
}

func showUsers() error {
	out, err := call("GET", "/v1/users", nil)
	if err != nil {
		return err
	}
	var us []userInfo
	if err := json.Unmarshal(out, &us); err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	defer tw.Flush()
	fmt.Fprintln(tw, "USER\tROLE\tSTATUS\tLAST WEB LOGIN\tSSH KEYS")
	for _, u := range us {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\n", u.Name, u.Role, u.status(), when(u.LastLogin), len(u.SSHKeys))
	}
	return nil
}

func getUser(name string) (userInfo, error) {
	var u userInfo
	out, err := call("GET", "/v1/users/"+url.PathEscape(name), nil)
	if err != nil {
		return u, err
	}
	return u, json.Unmarshal(out, &u)
}

func showUser(name string) error {
	u, err := getUser(name)
	if err != nil {
		return err
	}
	fmt.Printf("user      %s\nrole      %s\nstatus    %s\nlast web login %s\n", u.Name, u.Role, u.status(), when(u.LastLogin))
	if u.Created != nil {
		fmt.Printf("created   %s by %s\n", when(u.Created), u.CreatedBy)
	}
	if u.Changed != nil {
		fmt.Printf("changed   %s by %s\n", when(u.Changed), u.ChangedBy)
	}
	printKeys(u)
	return nil
}

func printKeys(u userInfo) {
	if len(u.SSHKeys) == 0 {
		fmt.Println("SSH keys: none")
		return
	}
	fmt.Println("SSH keys:")
	for i, k := range u.SSHKeys {
		fmt.Printf("  %d  %s  %s  %s\n", i+1, k.Type, k.Fingerprint, k.Comment)
	}
}

func showSSHKeys() error {
	u, err := getUser(whoami())
	if err != nil {
		return err
	}
	printKeys(u)
	return nil
}

type roleInfo struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	BuiltIn     bool              `json:"builtin"`
	Superuser   bool              `json:"superuser"`
	Perms       map[string]string `json:"permissions"`
	Users       []string          `json:"users"`
}

func getRoles() ([]roleInfo, error) {
	out, err := call("GET", "/v1/roles", nil)
	if err != nil {
		return nil, err
	}
	var rs []roleInfo
	return rs, json.Unmarshal(out, &rs)
}

func showRoles() error {
	rs, err := getRoles()
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	defer tw.Flush()
	fmt.Fprintln(tw, "ROLE\tKIND\tUSERS\tDESCRIPTION")
	for _, r := range rs {
		kind := "custom"
		if r.BuiltIn {
			kind = "built-in"
		}
		users := strings.Join(r.Users, ",")
		if users == "" {
			users = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", r.Name, kind, users, r.Description)
	}
	return nil
}

func showRole(name string) error {
	rs, err := getRoles()
	if err != nil {
		return err
	}
	m, err := fetchMe()
	if err != nil {
		return err
	}
	for _, r := range rs {
		if r.Name != name {
			continue
		}
		fmt.Printf("%s: %s\n", r.Name, r.Description)
		if r.Superuser {
			fmt.Println("superuser: everything, including users and roles")
		}
		perms := r.Perms
		if r.Superuser {
			perms = map[string]string{}
			for _, a := range m.Areas {
				perms[a.Area] = "change"
				if a.ViewOnly {
					perms[a.Area] = "view"
				}
			}
		}
		printPerms(perms, m)
		return nil
	}
	return fmt.Errorf("no role %q (show roles lists them)", name)
}

// --- changes --------------------------------------------------------------

// askSecret reads a line with echo off on a terminal.
func askSecret(in io.Reader, label string) (string, error) {
	br, ok := in.(*bufio.Reader)
	if !ok {
		br = bufio.NewReader(in)
	}
	if isTerminal() {
		fmt.Fprint(os.Stderr, label)
		setEcho(false)
		defer func() { setEcho(true); fmt.Fprintln(os.Stderr) }()
	}
	line, err := br.ReadString('\n')
	if err != nil && line == "" {
		return "", fmt.Errorf("no input")
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func askNewPassword(in io.Reader, who string) (string, error) {
	a, err := askSecret(in, "New password for "+who+" (10+ characters): ")
	if err != nil {
		return "", err
	}
	b, err := askSecret(in, "Again: ")
	if err != nil {
		return "", err
	}
	if a != b {
		return "", fmt.Errorf("passwords do not match; nothing changed")
	}
	return a, nil
}

func readKeyLine(in io.Reader) (string, error) {
	br, ok := in.(*bufio.Reader)
	if !ok {
		br = bufio.NewReader(in)
	}
	if isTerminal() {
		fmt.Println("Paste the public key (one line, e.g. ssh-ed25519 AAAA... you@laptop):")
	}
	line, err := br.ReadString('\n')
	if err != nil && strings.TrimSpace(line) == "" {
		return "", fmt.Errorf("no key pasted")
	}
	return strings.TrimSpace(line), nil
}

func addKey(name string, in io.Reader) error {
	key, err := readKeyLine(in)
	if err != nil {
		return err
	}
	out, err := call("POST", "/v1/users/"+url.PathEscape(name)+"/ssh-keys", mustJSON(map[string]string{"key": key}))
	if err != nil {
		return err
	}
	var k struct{ Fingerprint string }
	json.Unmarshal(out, &k)
	fmt.Printf("key %s added for %s; it works for SSH logins straight away\n", k.Fingerprint, name)
	return nil
}

func deleteKey(name, which string) error {
	if _, err := call("DELETE", "/v1/users/"+url.PathEscape(name)+"/ssh-keys/"+url.PathEscape(which), nil); err != nil {
		return err
	}
	fmt.Printf("key %s of %s deleted\n", which, name)
	return nil
}

// sshKeyCmd: ssh-key add | ssh-key delete N|FINGERPRINT (your own keys).
func sshKeyCmd(args []string, in io.Reader) error {
	switch {
	case len(args) == 1 && args[0] == "add":
		return addKey(whoami(), in)
	case len(args) == 2 && args[0] == "delete":
		return deleteKey(whoami(), args[1])
	}
	return fmt.Errorf("ssh-key add | ssh-key delete N|FINGERPRINT (show ssh-keys lists yours)")
}

const userUsage = `request user add NAME role ROLE
request user set NAME role ROLE | set NAME disabled yes|no
request user password NAME | unlock NAME | delete NAME
request user ssh-key add NAME | ssh-key delete NAME N|FINGERPRINT`

func requestUser(args []string, in io.Reader) error {
	if len(args) < 2 {
		return fmt.Errorf("%s", userUsage)
	}
	op, name, rest := args[0], args[1], args[2:]
	path := "/v1/users/" + url.PathEscape(name)
	switch {
	case op == "add" && len(rest) == 2 && rest[0] == "role":
		pw, err := askNewPassword(in, name)
		if err != nil {
			return err
		}
		if _, err := call("POST", "/v1/users", mustJSON(map[string]string{"name": name, "role": rest[1], "password": pw})); err != nil {
			return err
		}
		fmt.Printf("user %s added with role %s: one password for SSH, the console and the web UI\n", name, rest[1])
	case op == "set" && len(rest) == 2 && rest[0] == "role":
		if _, err := call("PATCH", path, mustJSON(map[string]string{"role": rest[1]})); err != nil {
			return err
		}
		fmt.Printf("%s now has role %s (their CLI sessions were ended)\n", name, rest[1])
	case op == "set" && len(rest) == 2 && rest[0] == "disabled" && (rest[1] == "yes" || rest[1] == "no"):
		if _, err := call("PATCH", path, mustJSON(map[string]bool{"disabled": rest[1] == "yes"})); err != nil {
			return err
		}
		if rest[1] == "yes" {
			fmt.Printf("%s disabled: no logins, and their sessions were ended\n", name)
		} else {
			fmt.Printf("%s can log in again\n", name)
		}
	case op == "password" && len(rest) == 0:
		pw, err := askNewPassword(in, name)
		if err != nil {
			return err
		}
		if _, err := call("POST", path+"/password", mustJSON(map[string]string{"password": pw})); err != nil {
			return err
		}
		fmt.Printf("password of %s set for SSH, the console and the web UI; their sessions were ended\n", name)
	case op == "unlock" && len(rest) == 0:
		if _, err := call("POST", path+"/unlock", nil); err != nil {
			return err
		}
		fmt.Printf("%s unlocked\n", name)
	case op == "delete" && len(rest) == 0:
		if _, err := call("DELETE", path, nil); err != nil {
			return err
		}
		fmt.Printf("user %s deleted\n", name)
	case op == "ssh-key" && len(args) == 3 && args[1] == "add":
		return addKey(args[2], in)
	case op == "ssh-key" && len(args) == 4 && args[1] == "delete":
		return deleteKey(args[2], args[3])
	default:
		return fmt.Errorf("%s", userUsage)
	}
	return nil
}

const roleUsage = `request role add NAME [description "TEXT"]
request role set NAME AREA view|change|none | set NAME description "TEXT"
request role delete NAME`

func requestRole(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("%s", roleUsage)
	}
	op, name, rest := args[0], args[1], args[2:]
	put := func(r roleInfo) error {
		body := mustJSON(map[string]any{"description": r.Description, "permissions": r.Perms})
		_, err := call("PUT", "/v1/roles/"+url.PathEscape(name), body)
		return err
	}
	find := func() (roleInfo, error) {
		rs, err := getRoles()
		if err != nil {
			return roleInfo{}, err
		}
		for _, r := range rs {
			if r.Name == name {
				if r.BuiltIn {
					return r, fmt.Errorf("%s is a built-in role and can't be changed", name)
				}
				return r, nil
			}
		}
		return roleInfo{}, fmt.Errorf("no role %q (request role add %s first)", name, name)
	}
	switch {
	case op == "add" && (len(rest) == 0 || len(rest) == 2 && rest[0] == "description"):
		if _, err := find(); err == nil {
			return fmt.Errorf("role %s already exists", name)
		}
		r := roleInfo{Perms: map[string]string{}}
		if len(rest) == 2 {
			r.Description = rest[1]
		}
		if err := put(r); err != nil {
			return err
		}
		fmt.Printf("role %s added with no permissions; give it some with request role set %s AREA view|change\n", name, name)
	case op == "set" && len(rest) == 2:
		r, err := find()
		if err != nil {
			return err
		}
		if r.Perms == nil {
			r.Perms = map[string]string{}
		}
		if rest[0] == "description" {
			r.Description = rest[1]
		} else {
			if rest[1] != "view" && rest[1] != "change" && rest[1] != "none" {
				return fmt.Errorf("access is view, change or none")
			}
			r.Perms[rest[0]] = rest[1]
			if rest[1] == "none" {
				delete(r.Perms, rest[0])
			}
		}
		if err := put(r); err != nil {
			return err
		}
		fmt.Printf("role %s changed; users who have it get it on their next command\n", name)
	case op == "delete" && len(rest) == 0:
		if _, err := call("DELETE", "/v1/roles/"+url.PathEscape(name), nil); err != nil {
			return err
		}
		fmt.Printf("role %s deleted\n", name)
	default:
		return fmt.Errorf("%s", roleUsage)
	}
	return nil
}
