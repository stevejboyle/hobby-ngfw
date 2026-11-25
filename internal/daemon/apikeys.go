package daemon

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/stevejboyle/sjb-os/internal/accounts"
)

var keyNameRE = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,63}$`)

// apiKeysMu serialises changes to the key file.
var apiKeysMu sync.Mutex

// APIKeyInfo is an API key without its secret.
type APIKeyInfo struct {
	Name   string   `json:"name"`
	Scopes []string `json:"scopes"`
}

// ListAPIKeys lists the API keys' names and scopes (superusers).
func (d *Daemon) ListAPIKeys(c accounts.Caller) ([]APIKeyInfo, error) {
	if _, err := d.Authorize(c, accounts.SuperuserOnly); err != nil {
		return nil, err
	}
	apiKeysMu.Lock()
	d.loadAPIKeysFile()
	apiKeysMu.Unlock()
	out := []APIKeyInfo{}
	for _, k := range d.currentAPIKeys() {
		out = append(out, APIKeyInfo{Name: k.Name, Scopes: keyScopes(k)})
	}
	return out, nil
}

func keyScopes(k APIKey) []string {
	var out []string
	for _, s := range Scopes {
		if k.Scopes[s] {
			out = append(out, s)
		}
	}
	return out
}

// AddAPIKey creates a key with the given scopes and returns it, the only
// time its value is shown besides show api-keys (superusers). It works at
// once, with no restart.
func (d *Daemon) AddAPIKey(c accounts.Caller, name string, scopes []string) (APIKey, error) {
	if _, err := d.Authorize(c, accounts.SuperuserOnly); err != nil {
		return APIKey{}, err
	}
	if !keyNameRE.MatchString(name) {
		return APIKey{}, fmt.Errorf("%w: key name: letters, digits, _ . - only; max 63", ErrInvalid)
	}
	if len(scopes) == 0 {
		return APIKey{}, fmt.Errorf("%w: give at least one scope (%s)", ErrInvalid, strings.Join(Scopes, ", "))
	}
	k := APIKey{Name: name, Scopes: map[string]bool{}}
	for _, s := range scopes {
		if !slices.Contains(Scopes, s) {
			return APIKey{}, fmt.Errorf("%w: unknown scope %q (%s)", ErrInvalid, s, strings.Join(Scopes, ", "))
		}
		k.Scopes[s] = true
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return APIKey{}, err
	}
	k.Key = base64.RawURLEncoding.EncodeToString(b)
	apiKeysMu.Lock()
	defer apiKeysMu.Unlock()
	d.loadAPIKeysFile()
	keys := d.currentAPIKeys()
	for _, o := range keys {
		if o.Name == name {
			return APIKey{}, fmt.Errorf("%w: a key named %q exists (delete it first)", ErrInvalid, name)
		}
	}
	keys = append(slices.Clone(keys), k)
	if err := d.saveAPIKeys(keys); err != nil {
		return APIKey{}, err
	}
	d.log.Info("api key added", "name", name, "scopes", strings.Join(keyScopes(k), ","), "by", c.Author())
	return k, nil
}

// DeleteAPIKey removes a key; requests with it fail at once (superusers).
func (d *Daemon) DeleteAPIKey(c accounts.Caller, name string) error {
	if _, err := d.Authorize(c, accounts.SuperuserOnly); err != nil {
		return err
	}
	apiKeysMu.Lock()
	defer apiKeysMu.Unlock()
	d.loadAPIKeysFile()
	keys := d.currentAPIKeys()
	i := slices.IndexFunc(keys, func(k APIKey) bool { return k.Name == name })
	if i < 0 {
		return fmt.Errorf("%w: no API key named %q", accounts.ErrNotFound, name)
	}
	keys = slices.Delete(slices.Clone(keys), i, i+1)
	if err := d.saveAPIKeys(keys); err != nil {
		return err
	}
	d.log.Info("api key deleted", "name", name, "by", c.Author())
	return nil
}

// saveAPIKeys writes the key file and makes the API use it.
func (d *Daemon) saveAPIKeys(keys []APIKey) error {
	if d.apiKeysFile == "" {
		return fmt.Errorf("%w: no API key file on this host", ErrInvalid)
	}
	var b strings.Builder
	b.WriteString("# <name> <scopes> <key>\n")
	for _, k := range keys {
		fmt.Fprintf(&b, "%s %s %s\n", k.Name, strings.Join(keyScopes(k), ","), k.Key)
	}
	if err := writeFileAtomic(d.apiKeysFile, []byte(b.String()), 0o600); err != nil {
		return err
	}
	d.setAPIKeys(keys)
	return nil
}

// loadAPIKeysFile is used when the API isn't served (keys still managed).
func (d *Daemon) loadAPIKeysFile() {
	if d.apiKeys.Load() != nil || d.apiKeysFile == "" {
		return
	}
	if keys, err := LoadKeys(d.apiKeysFile); err == nil {
		d.setAPIKeys(keys)
	} else if !os.IsNotExist(err) {
		d.log.Warn("api key file unreadable", "err", err)
	}
}
