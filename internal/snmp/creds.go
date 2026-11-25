// Package snmp runs SJB-OS's SNMP agent: net-snmp's snmpd, read-only, in
// the management VRF. ngfwd compiles the config and the credentials into
// snmpd.conf (Compile), applies it through systemd (Exec), and serves
// SJB-OS's own objects through a pass_persist helper (Pass) that reads the
// monitoring snapshot ngfwd saves.
package snmp

import (
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

// Load reads the credentials file; a missing file is empty.
func Load(path string) (*Credentials, error) {
	cs := &Credentials{}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return cs, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, cs); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return cs, nil
}

// Parse reads credentials from JSON (a backup).
func Parse(b []byte) (*Credentials, error) {
	cs := &Credentials{}
	if err := json.Unmarshal(b, cs); err != nil {
		return nil, err
	}
	for _, c := range cs.List {
		if err := c.Check(); err != nil {
			return nil, fmt.Errorf("credential %q: %w", c.Name, err)
		}
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

// Save writes the credentials atomically, readable by root only.
func Save(path string, cs *Credentials) error {
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
