package decrypt

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// PolicyFile is where ngfwd writes tlsd's policy (no secrets in it).
const PolicyFile = "/var/lib/sjb-os/tlsd-policy.json"

// BuiltinExclusionsFile is SJB-OS's own list of server names never
// decrypted: banking, payment, health and government. Shipped in bundles.
const BuiltinExclusionsFile = "/usr/share/sjb-os/decryption-exclusions.txt"

// Modes.
const (
	ModeObserve = "observe" // read hellos, decide, log; pass everything through
	ModeDecrypt = "decrypt" // decrypt what the rules say
)

// Policy is what ngfwd tells tlsd.
type Policy struct {
	Mode string `json:"mode"`
	// Rules by position: the mark tlsd reads holds position + 1.
	Rules []PolicyRule `json:"rules"`
	// Exclusions are the operator's server-name patterns.
	Exclusions []Exclusion `json:"exclusions"`
	// Builtin: also apply the built-in exclusion list.
	Builtin bool `json:"builtin"`
}

// PolicyRule is one decryption rule as tlsd needs it.
type PolicyRule struct {
	Name           string `json:"name"`
	Profile        string `json:"profile"`
	BadCertificate string `json:"bad_certificate"` // warn or block
	Unsupported    string `json:"unsupported"`     // pass or block
	Pinned         string `json:"pinned"`          // exclude or block
}

// Exclusion is a named list of server-name patterns.
type Exclusion struct {
	Name    string   `json:"name"`
	Domains []string `json:"domains"`
}

// WritePolicy writes p atomically (mode 0644: tlsd reads it).
func WritePolicy(path string, p Policy) error {
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return writeFile(path, append(data, '\n'), 0o644, NoOwner)
}

// ReadPolicy reads a policy file.
func ReadPolicy(path string) (Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Policy{}, err
	}
	var p Policy
	err = json.Unmarshal(data, &p)
	return p, err
}

// Matcher matches server names against patterns: "bank.example" is that
// name and everything under it; "*.bank.example" only what's under it.
type Matcher struct {
	exact map[string]string // name -> list it came from
	under map[string]string // suffix (without "*.") -> list
}

// NewMatcher builds a matcher. lists maps a list's name to its patterns.
func NewMatcher(lists map[string][]string) *Matcher {
	m := &Matcher{exact: map[string]string{}, under: map[string]string{}}
	names := make([]string, 0, len(lists))
	for n := range lists {
		names = append(names, n)
	}
	sort.Strings(names) // the first list wins a name both have
	for _, n := range names {
		for _, p := range lists[n] {
			p = strings.ToLower(strings.TrimSpace(p))
			if p == "" {
				continue
			}
			if s, ok := strings.CutPrefix(p, "*."); ok {
				if _, dup := m.under[s]; !dup {
					m.under[s] = n
				}
				continue
			}
			if _, dup := m.exact[p]; !dup {
				m.exact[p] = n
			}
			if _, dup := m.under[p]; !dup {
				m.under[p] = n
			}
		}
	}
	return m
}

// Match reports the list a server name is excluded by ("" = not excluded).
func (m *Matcher) Match(name string) string {
	if m == nil || name == "" {
		return ""
	}
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if l, ok := m.exact[name]; ok {
		return l
	}
	for s := name; ; {
		i := strings.IndexByte(s, '.')
		if i < 0 {
			return ""
		}
		s = s[i+1:]
		if l, ok := m.under[s]; ok {
			return l
		}
	}
}

// Len is how many patterns the matcher holds.
func (m *Matcher) Len() int { return len(m.exact) + len(m.under) }

// ReadList reads a pattern file: one name per line, # comments.
func ReadList(r io.Reader) []string {
	var out []string
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, strings.ToLower(line))
		}
	}
	return out
}

// Learned remembers servers whose clients rejected the firewall's
// certificate (pinned apps), so they pass through from then on.
type Learned struct {
	mu   sync.Mutex
	path string
	ttl  time.Duration
	m    map[string]time.Time // "name|ip" -> expiry
}

// LearnedEntry is one learned server.
type LearnedEntry struct {
	ServerName string    `json:"server_name"`
	IP         string    `json:"ip"`
	Expires    time.Time `json:"expires"`
}

// LearnedTTL is how long a learned server stays excluded.
const LearnedTTL = 24 * time.Hour

// OpenLearned loads the learned list from path ("" = memory only).
func OpenLearned(path string, ttl time.Duration) *Learned {
	l := &Learned{path: path, ttl: ttl, m: map[string]time.Time{}}
	if path != "" {
		if data, err := os.ReadFile(path); err == nil {
			var es []LearnedEntry
			if json.Unmarshal(data, &es) == nil {
				for _, e := range es {
					l.m[e.ServerName+"|"+e.IP] = e.Expires
				}
			}
		}
	}
	return l
}

// Add remembers a server.
func (l *Learned) Add(name, ip string, now time.Time) {
	l.mu.Lock()
	l.m[name+"|"+ip] = now.Add(l.ttl)
	l.saveLocked(now)
	l.mu.Unlock()
}

// Has reports whether a server is learned and not expired.
func (l *Learned) Has(name, ip string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	exp, ok := l.m[name+"|"+ip]
	return ok && now.Before(exp)
}

// List returns the live entries, soonest expiry first.
func (l *Learned) List(now time.Time) []LearnedEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := []LearnedEntry{}
	for k, exp := range l.m {
		if !now.Before(exp) {
			continue
		}
		name, ip, _ := strings.Cut(k, "|")
		out = append(out, LearnedEntry{ServerName: name, IP: ip, Expires: exp})
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Expires.Equal(out[j].Expires) {
			return out[i].Expires.Before(out[j].Expires)
		}
		return out[i].ServerName+out[i].IP < out[j].ServerName+out[j].IP
	})
	return out
}

// Clear forgets everything.
func (l *Learned) Clear(now time.Time) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, exp := range l.m {
		if now.Before(exp) {
			n++
		}
	}
	l.m = map[string]time.Time{}
	l.saveLocked(now)
	return n
}

func (l *Learned) saveLocked(now time.Time) {
	if l.path == "" {
		return
	}
	var es []LearnedEntry
	for k, exp := range l.m {
		if !now.Before(exp) {
			delete(l.m, k)
			continue
		}
		name, ip, _ := strings.Cut(k, "|")
		es = append(es, LearnedEntry{ServerName: name, IP: ip, Expires: exp})
	}
	data, _ := json.Marshal(es)
	writeFile(l.path, data, 0o600, NoOwner)
}
