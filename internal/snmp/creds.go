// Package snmp runs SJB-OS's SNMP agent: net-snmp's snmpd, read-only, in
// the management VRF. ngfwd compiles the config and the credentials into
// snmpd.conf (Compile), applies it through systemd (Exec), and serves
// SJB-OS's own objects through a pass_persist helper (Pass) that reads the
// monitoring snapshot ngfwd saves.
package snmp

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// CredentialsPath is where the credentials live on the appliance (0600,
// root): never in the config, which is in revisions, diffs and views.
const CredentialsPath = "/etc/ngfw/snmp-credentials"

// Credential kinds.
const (
	KindV3  = "v3"
	KindV2c = "v2c"
)

// Authentication and privacy protocols offered for v3 users.
var (
	AuthProtocols = []string{"SHA-256", "SHA-512"}
	PrivProtocols = []string{"AES", "AES-256"}
)

// MinSecret is the shortest passphrase or community accepted (net-snmp
// needs 8 for v3 passphrases).
const MinSecret = 8

// Credential is a v3 user or a v2c community.
type Credential struct {
	Name     string `json:"name"`
	Kind     string `json:"kind"`
	Auth     string `json:"auth,omitempty"` // v3: SHA-256 or SHA-512
	AuthPass string `json:"auth_pass,omitempty"`
	Priv     string `json:"priv,omitempty"` // v3: AES or AES-256
	PrivPass string `json:"priv_pass,omitempty"`
	// Community is the v2c community string.
	Community string `json:"community,omitempty"`
}

// Info is a credential without its secrets.
type Info struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
	Auth string `json:"auth,omitempty"`
	Priv string `json:"priv,omitempty"`
}

// Info drops the secrets.
func (c Credential) Info() Info { return Info{c.Name, c.Kind, c.Auth, c.Priv} }

// Credentials are every credential, plus the internal user snmpd's own
// trigger queries (traps) use. Its passphrase is random and never shown.
type Credentials struct {
	List         []Credential `json:"credentials"`
	InternalPass string       `json:"internal_pass,omitempty"`
}

// InternalUser is snmpd's internal query user (DISMAN-EVENT triggers).
const InternalUser = "sjb-internal"

var nameRE = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,32}$`)

// Get finds a credential by name.
func (cs *Credentials) Get(name string) (Credential, bool) {
	i := slices.IndexFunc(cs.List, func(c Credential) bool { return c.Name == name })
	if i < 0 {
		return Credential{}, false
	}
	return cs.List[i], true
}

// secretOK: printable ASCII without quotes, backslashes or spaces (it goes
// into snmpd.conf), at least MinSecret long.
func secretOK(s string) bool {
	if len(s) < MinSecret || len(s) > 128 {
		return false
	}
	for _, r := range s {
		if r <= ' ' || r > '~' || r == '"' || r == '\'' || r == '\\' || r == '#' {
			return false
		}
	}
	return true
}

// Check validates a credential.
func (c Credential) Check() error {
	var errs []error
	if !nameRE.MatchString(c.Name) {
		errs = append(errs, fmt.Errorf("name: letters, digits, _ . - only; max 32"))
	}
	if c.Name == InternalUser {
		errs = append(errs, fmt.Errorf("name %q is reserved", InternalUser))
	}
	switch c.Kind {
	case KindV3:
		if !slices.Contains(AuthProtocols, c.Auth) {
			errs = append(errs, fmt.Errorf("auth must be %s", strings.Join(AuthProtocols, " or ")))
		}
		if !slices.Contains(PrivProtocols, c.Priv) {
			errs = append(errs, fmt.Errorf("priv must be %s", strings.Join(PrivProtocols, " or ")))
		}
		if !secretOK(c.AuthPass) || !secretOK(c.PrivPass) {
			errs = append(errs, fmt.Errorf("passphrases: %d-128 printable characters, no spaces, quotes, backslashes or #", MinSecret))
		}
		if c.AuthPass != "" && c.AuthPass == c.PrivPass {
			errs = append(errs, fmt.Errorf("use different authentication and privacy passphrases"))
		}
		if c.Community != "" {
			errs = append(errs, fmt.Errorf("a v3 user has no community"))
		}
	case KindV2c:
		if !secretOK(c.Community) {
			errs = append(errs, fmt.Errorf("community: %d-128 printable characters, no spaces, quotes, backslashes or #", MinSecret))
		}
		if c.Auth != "" || c.Priv != "" || c.AuthPass != "" || c.PrivPass != "" {
			errs = append(errs, fmt.Errorf("a v2c community has no auth or priv"))
		}
	default:
		errs = append(errs, fmt.Errorf("kind must be v3 or v2c"))
	}
	return errors.Join(errs...)
}

// NormalizeAuth and NormalizePriv accept CLI spellings (sha256, aes256).
func NormalizeAuth(s string) string {
	switch strings.ToUpper(strings.ReplaceAll(s, "-", "")) {
	case "SHA256":
		return "SHA-256"
	case "SHA512":
		return "SHA-512"
	}
	return s
}

func NormalizePriv(s string) string {
	switch strings.ToUpper(strings.ReplaceAll(s, "-", "")) {
	case "AES", "AES128":
		return "AES"
	case "AES256":
		return "AES-256"
	}
	return s
}

// internalRE is what an internal passphrase looks like (EnsureInternal
// makes 32 base64url characters).
var internalRE = regexp.MustCompile(`^[A-Za-z0-9_-]{24,128}$`)

// Validate checks the whole store: every credential, unique names, and the
// internal passphrase (when there is one: older stores and backups may
// have none, and EnsureInternal adds it). Errors never quote a secret.
func (cs *Credentials) Validate() error {
	var errs []error
	seen := map[string]bool{}
	for i, c := range cs.List {
		if err := c.Check(); err != nil {
			errs = append(errs, fmt.Errorf("credential %d (%q): %w", i+1, safeName(c.Name), err))
		}
		if seen[c.Name] {
			errs = append(errs, fmt.Errorf("credential %q is listed twice", safeName(c.Name)))
		}
		seen[c.Name] = true
	}
	if cs.InternalPass != "" && !internalRE.MatchString(cs.InternalPass) {
		errs = append(errs, fmt.Errorf("the internal passphrase is malformed"))
	}
	return errors.Join(errs...)
}

// safeName is a name fit for an error message: names are not secrets, but
// one that fails the name check may hold anything.
func safeName(n string) string {
	if nameRE.MatchString(n) {
		return n
	}
	return "(invalid name)"
}

// ErrStore marks a credentials file or backup that is unreadable or
// invalid. Nothing is ever written over it automatically.
var ErrStore = errors.New("SNMP credentials store invalid")

// Load reads and validates the credentials file; a missing file is empty.
func Load(path string) (*Credentials, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return &Credentials{}, nil
	}
	if err != nil {
		return nil, err
	}
	cs, err := Parse(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return cs, nil
}

// Parse reads and validates credentials from JSON (the file, a backup).
// Unknown fields are refused: a store that doesn't look like ours isn't
// guessed at.
func Parse(b []byte) (*Credentials, error) {
	cs := &Credentials{}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(cs); err != nil {
		// A syntax error quotes the character it met, which may be part
		// of a secret: give only where it is.
		var se *json.SyntaxError
		if errors.As(err, &se) {
			return nil, fmt.Errorf("%w: not valid JSON (at byte %d)", ErrStore, se.Offset)
		}
		var te *json.UnmarshalTypeError
		if errors.As(err, &te) {
			return nil, fmt.Errorf("%w: field %q has the wrong type", ErrStore, te.Field)
		}
		return nil, fmt.Errorf("%w: %v", ErrStore, err)
	}
	if err := cs.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrStore, err)
	}
	return cs, nil
}

// EnsureInternal gives the internal user a passphrase if it has none.
func (cs *Credentials) EnsureInternal() error {
	if cs.InternalPass != "" {
		return nil
	}
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return err
	}
	cs.InternalPass = base64.RawURLEncoding.EncodeToString(b)
	return nil
}

// Save validates and writes the credentials atomically, readable by root
// only. On any error the file on disk is unchanged.
func Save(path string, cs *Credentials) error {
	if err := cs.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrStore, err)
	}
	b, err := json.MarshalIndent(cs, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".snmp-credentials-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// Marshal is the credentials as JSON (for backups).
func (cs *Credentials) Marshal() ([]byte, error) { return json.Marshal(cs) }
