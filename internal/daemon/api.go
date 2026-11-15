package daemon

import (
	"bufio"
	"crypto/subtle"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/stevejboyle/hobby-ngfw/internal/tags"
)

// Scopes an API key can hold.
const (
	ScopeTagsRead  = "tags:read"
	ScopeTagsWrite = "tags:write"
)

// APIKey is one credential for the network-facing API.
type APIKey struct {
	Name   string
	Key    string
	Scopes map[string]bool
}

// LoadKeys reads a key file: one key per line, "<name> <scope,scope> <key>".
// Blank lines and lines starting with # are ignored. Keys must be at least
// 24 characters.
func LoadKeys(path string) ([]APIKey, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var keys []APIKey
	sc := bufio.NewScanner(f)
	for line := 1; sc.Scan(); line++ {
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		fields := strings.Fields(text)
		if len(fields) != 3 {
			return nil, fmt.Errorf("%s:%d: want \"<name> <scopes> <key>\"", path, line)
		}
		if len(fields[2]) < 24 {
			return nil, fmt.Errorf("%s:%d: key for %q is shorter than 24 characters", path, line, fields[0])
		}
		k := APIKey{Name: fields[0], Key: fields[2], Scopes: map[string]bool{}}
		for _, s := range strings.Split(fields[1], ",") {
			if s != ScopeTagsRead && s != ScopeTagsWrite {
				return nil, fmt.Errorf("%s:%d: unknown scope %q", path, line, s)
			}
			k.Scopes[s] = true
		}
		keys = append(keys, k)
	}
	return keys, sc.Err()
}

func findKey(keys []APIKey, presented string) *APIKey {
	if presented == "" {
		return nil
	}
	var found *APIKey
	for i := range keys {
		// Compare against every key so timing does not reveal which matched.
		if subtle.ConstantTimeCompare([]byte(keys[i].Key), []byte(presented)) == 1 {
			found = &keys[i]
		}
	}
	return found
}

// APIHandler serves the network-facing tag API: JSON under /api/v1/tags and
// XML user-ID messages (uid-message register/unregister) at /api/, the
// format many NAC, SOAR and EDR integrations already send.
func (d *Daemon) APIHandler(keys []APIKey) http.Handler {
	mux := http.NewServeMux()
	wrap := func(scope string, h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			presented := r.Header.Get("X-API-Key")
			if b, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok {
				presented = b
			}
			k := findKey(keys, presented)
			if k == nil {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
			if !k.Scopes[scope] {
				http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
				return
			}
			d.log.Info("api call", "key", k.Name, "method", r.Method, "path", r.URL.Path)
			h(w, r)
		}
	}
	d.tagRoutes(mux, "/api/v1/tags", wrap)
	mux.HandleFunc("/api/", d.xmlUserID(keys))
	return brandHeader(mux)
}

// uid-message: the tag register/unregister subset of an XML user-ID message.
type uidMessage struct {
	XMLName xml.Name `xml:"uid-message"`
	Type    string   `xml:"type"`
	Payload struct {
		Register   uidEntries `xml:"register"`
		Unregister uidEntries `xml:"unregister"`
	} `xml:"payload"`
}

type uidEntries struct {
	Entries []uidEntry `xml:"entry"`
}

type uidEntry struct {
	IP      string      `xml:"ip,attr"`
	Members []uidMember `xml:"tag>member"`
}

type uidMember struct {
	Timeout int    `xml:"timeout,attr"`
	Name    string `xml:",chardata"`
}

func (d *Daemon) xmlUserID(keys []APIKey) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		if err := r.ParseForm(); err != nil {
			xmlError(w, http.StatusBadRequest, "bad request")
			return
		}
		presented := r.Header.Get("X-API-Key")
		if presented == "" {
			presented = r.Form.Get("key")
		}
		k := findKey(keys, presented)
		if k == nil {
			xmlError(w, http.StatusForbidden, "Invalid credentials.")
			return
		}
		if r.Form.Get("type") != "user-id" {
			xmlError(w, http.StatusBadRequest, "only type=user-id is supported")
			return
		}
		if !k.Scopes[ScopeTagsWrite] {
			xmlError(w, http.StatusForbidden, "key lacks tags:write")
			return
		}
		var msg uidMessage
		if err := xml.Unmarshal([]byte(r.Form.Get("cmd")), &msg); err != nil {
			xmlError(w, http.StatusBadRequest, "cmd is not a valid uid-message")
			return
		}
		if msg.Type != "update" {
			xmlError(w, http.StatusBadRequest, "uid-message type must be update")
			return
		}
		d.log.Info("api call", "key", k.Name, "path", "/api/ user-id",
			"register", len(msg.Payload.Register.Entries), "unregister", len(msg.Payload.Unregister.Entries))
		if err := d.applyUID(msg); err != nil {
			code := http.StatusInternalServerError
			if errors.Is(err, ErrInvalid) {
				code = http.StatusBadRequest
			}
			xmlError(w, code, err.Error())
			return
		}
		fmt.Fprint(w, `<response status="success"><result><uid-response><version>2.0</version><payload/></uid-response></result></response>`)
	}
}

// applyUID validates every entry before changing anything, then applies
// unregistrations followed by registrations.
func (d *Daemon) applyUID(msg uidMessage) error {
	type op struct {
		ip  netip.Addr
		tag string
		ttl time.Duration
	}
	collect := func(es []uidEntry) ([]op, error) {
		var ops []op
		for _, e := range es {
			ip, err := netip.ParseAddr(e.IP)
			if err != nil {
				return nil, fmt.Errorf("%w: bad ip %q", ErrInvalid, e.IP)
			}
			for _, m := range e.Members {
				tag := strings.TrimSpace(m.Name)
				if err := validateTag(ip, tag); err != nil {
					return nil, err
				}
				ops = append(ops, op{ip, tag, time.Duration(m.Timeout) * time.Second})
			}
		}
		return ops, nil
	}
	unreg, err := collect(msg.Payload.Unregister.Entries)
	if err != nil {
		return err
	}
	reg, err := collect(msg.Payload.Register.Entries)
	if err != nil {
		return err
	}
	for _, o := range unreg {
		if err := d.UnregisterTags(o.ip, []string{o.tag}); err != nil {
			return err
		}
	}
	for _, o := range reg {
		if err := d.RegisterTags(o.ip, []string{o.tag}, o.ttl); err != nil {
			return err
		}
	}
	return nil
}

func validateTag(ip netip.Addr, tag string) error {
	if err := tags.Validate(ip, tag); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	return nil
}

func xmlError(w http.ResponseWriter, code int, msg string) {
	w.WriteHeader(code)
	var b strings.Builder
	xml.EscapeText(&b, []byte(msg))
	fmt.Fprintf(w, `<response status="error"><msg><line>%s</line></msg></response>`, b.String())
}
