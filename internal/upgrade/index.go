package upgrade

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// The release index is what an update server publishes: a small JSON file
// naming the newest release, and a detached ed25519 signature over its exact
// bytes, made with the same release key that signs bundles. The signature
// covers a domain prefix as well, so a bundle signature can never pass as an
// index signature or the other way round.
const (
	IndexSchema  = 1
	IndexChannel = "stable"
	// IndexPath and IndexSigPath are where an index lives under a server URL.
	IndexPath    = "v1/stable.json"
	IndexSigPath = "v1/stable.json.sig"
	// MaxIndexSize bounds what a client reads of an index or its signature.
	MaxIndexSize = 64 << 10
	indexDomain  = "sjb-os-release-index-v1\n"
)

// Release is one release an index lists.
type Release struct {
	Version        string `json:"version"`
	MinFromVersion string `json:"min_from_version,omitempty"`
	URL            string `json:"url"`
	Size           int64  `json:"size"`
	SHA256         string `json:"sha256"`
	Notes          string `json:"notes,omitempty"`
}

// Index is a release index.
type Index struct {
	Schema    int       `json:"schema"`
	Channel   string    `json:"channel"`
	Published time.Time `json:"published"`
	Latest    Release   `json:"latest"`
}

// Check validates an index's contents (not its signature).
func (ix *Index) Check() error {
	if ix.Schema != IndexSchema {
		return fmt.Errorf("release index: schema %d, want %d", ix.Schema, IndexSchema)
	}
	if ix.Channel != IndexChannel {
		return fmt.Errorf("release index: channel %q, want %q", ix.Channel, IndexChannel)
	}
	if ix.Published.IsZero() {
		return fmt.Errorf("release index: no published time")
	}
	r := ix.Latest
	if _, err := ParseVersion(r.Version); err != nil {
		return fmt.Errorf("release index: %v", err)
	}
	if r.MinFromVersion != "" {
		if _, err := ParseVersion(r.MinFromVersion); err != nil {
			return fmt.Errorf("release index: min_from_version: %v", err)
		}
	}
	if err := HTTPSURL(r.URL); err != nil {
		return fmt.Errorf("release index: bundle URL: %v", err)
	}
	if r.Size <= 0 || r.Size > MaxBundleSize {
		return fmt.Errorf("release index: bundle size %d outside 1..%d", r.Size, MaxBundleSize)
	}
	if b, err := hex.DecodeString(r.SHA256); err != nil || len(b) != 32 {
		return fmt.Errorf("release index: bad sha256")
	}
	if r.Notes != "" {
		if err := HTTPSURL(r.Notes); err != nil {
			return fmt.Errorf("release index: notes URL: %v", err)
		}
	}
	return nil
}

// HTTPSURL reports whether s is an absolute https URL with a host and no
// user info.
func HTTPSURL(s string) error {
	u, err := url.Parse(s)
	if err != nil {
		return err
	}
	if u.Scheme != "https" {
		return fmt.Errorf("%q is not https", s)
	}
	if u.Host == "" || u.User != nil || u.Opaque != "" {
		return fmt.Errorf("%q: want https://host/...", s)
	}
	return nil
}

// MarshalIndex renders an index the way it is signed and published.
func MarshalIndex(ix *Index) ([]byte, error) {
	if err := ix.Check(); err != nil {
		return nil, err
	}
	b, err := json.MarshalIndent(ix, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// SignIndex signs index bytes; the result is the .sig file (base64, one
// line).
func SignIndex(data []byte, key ed25519.PrivateKey) []byte {
	sig := ed25519.Sign(key, append([]byte(indexDomain), data...))
	return []byte(base64.StdEncoding.EncodeToString(sig) + "\n")
}

// VerifyIndex checks data against sig with the trusted keys, then parses and
// validates it. It returns the index and the name of the key that signed it.
func VerifyIndex(data, sig []byte, keys []PublicKey) (*Index, string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sig)))
	if err != nil || len(raw) != ed25519.SignatureSize {
		return nil, "", fmt.Errorf("release index: bad signature file")
	}
	msg := append([]byte(indexDomain), data...)
	signer := ""
	for _, k := range keys {
		if ed25519.Verify(k.Key, msg, raw) {
			signer = k.Name
			break
		}
	}
	if signer == "" {
		return nil, "", fmt.Errorf("release index: signature does not match any trusted key")
	}
	// Unknown fields are ignored, so later servers can add some; an
	// incompatible change bumps the schema.
	var ix Index
	if err := json.NewDecoder(bytes.NewReader(data)).Decode(&ix); err != nil {
		return nil, "", fmt.Errorf("release index: %v", err)
	}
	if err := ix.Check(); err != nil {
		return nil, "", err
	}
	return &ix, signer, nil
}
