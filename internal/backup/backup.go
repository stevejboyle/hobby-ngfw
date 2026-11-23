// Package backup is SJB-OS's config backup file: an armoured text block
// (so it can be pasted into the captive CLI) holding a JSON header and a
// payload of the running config and, optionally, the users, roles and tag
// API keys. Backups with accounts are always encrypted (AES-256-GCM with a
// key from the passphrase, PBKDF2-SHA256); config-only ones may be. The
// header is authenticated with the payload when encrypted; otherwise a
// SHA-256 of the payload catches corruption (not tampering).
package backup

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/stevejboyle/sjb-os/internal/accounts"
)

// Format names the file format in every header.
const (
	Format  = "sjb-os-backup"
	Version = 1

	Begin = "-----BEGIN SJB-OS BACKUP-----"
	End   = "-----END SJB-OS BACKUP-----"

	// MinPassphrase is the shortest passphrase accepted.
	MinPassphrase = 12
	// Iterations is the PBKDF2 work factor for new backups.
	Iterations = 600000
	// MaxSize caps a backup file (bytes).
	MaxSize = 4 << 20
)

// Contents of a backup.
const (
	ContentConfig   = "config"
	ContentAccounts = "accounts"
)

// ErrInvalid marks a file that isn't a usable backup; ErrPassphrase a
// missing or wrong passphrase.
var (
	ErrInvalid    = errors.New("not a valid SJB-OS backup")
	ErrPassphrase = errors.New("backup passphrase")
)

// Header describes a backup; it is readable without the passphrase.
type Header struct {
	Format     string      `json:"format"`
	Version    int         `json:"version"`
	SJBOS      string      `json:"sjb_os,omitempty"` // SJB-OS version that made it
	Created    time.Time   `json:"created"`
	By         string      `json:"by"` // verified author, e.g. web:admin
	Hostname   string      `json:"hostname,omitempty"`
	Revision   int         `json:"revision,omitempty"` // running revision backed up
	Contents   []string    `json:"contents"`
	SHA256     string      `json:"sha256"` // of the payload JSON (before encryption)
	Encryption *Encryption `json:"encryption,omitempty"`
}

// Encryption says how the payload was encrypted.
type Encryption struct {
	Cipher     string `json:"cipher"` // aes-256-gcm
	KDF        string `json:"kdf"`    // pbkdf2-sha256
	Iterations int    `json:"iterations"`
	Salt       string `json:"salt"`  // base64
	Nonce      string `json:"nonce"` // base64
}

// Has reports whether the backup holds c.
func (h Header) Has(c string) bool { return slices.Contains(h.Contents, c) }

// Encrypted reports whether the payload is encrypted.
func (h Header) Encrypted() bool { return h.Encryption != nil }

// Payload is what a backup restores.
type Payload struct {
	Config   string             `json:"config"` // YAML
	Accounts *accounts.Snapshot `json:"accounts,omitempty"`
	APIKeys  *string            `json:"api_keys,omitempty"` // the tag API key file
}

type envelope struct {
	Header  json.RawMessage `json:"header"`
	Payload string          `json:"payload"` // base64
}

// Seal makes a backup file. h.Contents and h.SHA256 are filled in from p;
// a passphrase is required when p holds accounts, and encrypts the
// payload whenever given.
func Seal(h Header, p Payload, passphrase string) ([]byte, error) {
	h.Format, h.Version = Format, Version
	h.Contents = []string{ContentConfig}
	if p.Accounts != nil || p.APIKeys != nil {
		h.Contents = append(h.Contents, ContentAccounts)
	}
	if strings.TrimSpace(p.Config) == "" {
		return nil, fmt.Errorf("%w: there is no config to back up", ErrInvalid)
	}
	if h.Has(ContentAccounts) && passphrase == "" {
		return nil, fmt.Errorf("%w: a backup with users, roles and API keys must be encrypted: give a passphrase", ErrPassphrase)
	}
	if passphrase != "" && len([]rune(passphrase)) < MinPassphrase {
		return nil, fmt.Errorf("%w: use at least %d characters", ErrPassphrase, MinPassphrase)
	}
	plain, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(plain)
	h.SHA256 = hex.EncodeToString(sum[:])
	body := plain
	var aead cipher.AEAD
	var nonce []byte
	if passphrase != "" {
		salt := make([]byte, 16)
		if _, err := rand.Read(salt); err != nil {
			return nil, err
		}
		if aead, err = newAEAD(passphrase, salt, Iterations); err != nil {
			return nil, err
		}
		nonce = make([]byte, aead.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			return nil, err
		}
		enc := base64.StdEncoding
		h.Encryption = &Encryption{Cipher: "aes-256-gcm", KDF: "pbkdf2-sha256", Iterations: Iterations,
			Salt: enc.EncodeToString(salt), Nonce: enc.EncodeToString(nonce)}
	}
	hj, err := json.Marshal(h)
	if err != nil {
		return nil, err
	}
	if aead != nil {
		body = aead.Seal(nil, nonce, plain, hj) // the header is authenticated too
	}
	env, err := json.Marshal(envelope{Header: hj, Payload: base64.StdEncoding.EncodeToString(body)})
	if err != nil {
		return nil, err
	}
	return armor(h, env), nil
}

func newAEAD(passphrase string, salt []byte, iter int) (cipher.AEAD, error) {
	key, err := pbkdf2.Key(sha256.New, passphrase, salt, iter, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func armor(h Header, env []byte) []byte {
	var b bytes.Buffer
	how := "not encrypted"
	if h.Encrypted() {
		how = "encrypted"
	}
	fmt.Fprintf(&b, "SJB-OS backup of %s, %s, by %s: %s, %s\n", orDash(h.Hostname), h.Created.UTC().Format(time.RFC3339), h.By,
		strings.Join(h.Contents, " and "), how)
	b.WriteString(Begin + "\n")
	s := base64.StdEncoding.EncodeToString(env)
	for len(s) > 76 {
		b.WriteString(s[:76] + "\n")
		s = s[76:]
	}
	if s != "" {
		b.WriteString(s + "\n")
	}
	b.WriteString(End + "\n")
	return b.Bytes()
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func unarmor(data []byte) (envelope, Header, error) {
	if len(data) > MaxSize {
		return envelope{}, Header{}, fmt.Errorf("%w: larger than %d MB", ErrInvalid, MaxSize>>20)
	}
	s := string(data)
	i := strings.Index(s, Begin)
	j := strings.Index(s, End)
	if i < 0 || j < i {
		return envelope{}, Header{}, fmt.Errorf("%w: no %s ... %s block", ErrInvalid, Begin, End)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(s[i+len(Begin):j]), ""))
	if err != nil {
		return envelope{}, Header{}, fmt.Errorf("%w: damaged (base64): %v", ErrInvalid, err)
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return envelope{}, Header{}, fmt.Errorf("%w: damaged: %v", ErrInvalid, err)
	}
	var h Header
	if err := json.Unmarshal(env.Header, &h); err != nil {
		return envelope{}, Header{}, fmt.Errorf("%w: damaged header: %v", ErrInvalid, err)
	}
	if h.Format != Format {
		return envelope{}, Header{}, fmt.Errorf("%w: format %q", ErrInvalid, h.Format)
	}
	if h.Version > Version {
		return envelope{}, Header{}, fmt.Errorf("%w: made by a newer SJB-OS (%s, backup format %d); upgrade this firewall first", ErrInvalid, orDash(h.SJBOS), h.Version)
	}
	return env, h, nil
}

// Inspect reads a backup's header without the passphrase.
func Inspect(data []byte) (Header, error) {
	_, h, err := unarmor(data)
	return h, err
}

// Open checks and decrypts a backup.
func Open(data []byte, passphrase string) (Header, Payload, error) {
	env, h, err := unarmor(data)
	if err != nil {
		return Header{}, Payload{}, err
	}
	body, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return Header{}, Payload{}, fmt.Errorf("%w: damaged payload", ErrInvalid)
	}
	if e := h.Encryption; e != nil {
		if passphrase == "" {
			return Header{}, Payload{}, fmt.Errorf("%w: this backup is encrypted: give its passphrase", ErrPassphrase)
		}
		if e.Cipher != "aes-256-gcm" || e.KDF != "pbkdf2-sha256" || e.Iterations < 1 || e.Iterations > 10_000_000 {
			return Header{}, Payload{}, fmt.Errorf("%w: unknown encryption %s/%s", ErrInvalid, e.Cipher, e.KDF)
		}
		salt, err1 := base64.StdEncoding.DecodeString(e.Salt)
		nonce, err2 := base64.StdEncoding.DecodeString(e.Nonce)
		if err1 != nil || err2 != nil {
			return Header{}, Payload{}, fmt.Errorf("%w: damaged encryption header", ErrInvalid)
		}
		aead, err := newAEAD(passphrase, salt, e.Iterations)
		if err != nil {
			return Header{}, Payload{}, err
		}
		if len(nonce) != aead.NonceSize() {
			return Header{}, Payload{}, fmt.Errorf("%w: damaged encryption header", ErrInvalid)
		}
		if body, err = aead.Open(nil, nonce, body, env.Header); err != nil {
			return Header{}, Payload{}, fmt.Errorf("%w: wrong passphrase, or the file was changed", ErrPassphrase)
		}
	}
	sum := sha256.Sum256(body)
	if hex.EncodeToString(sum[:]) != h.SHA256 {
		return Header{}, Payload{}, fmt.Errorf("%w: checksum mismatch (the file was damaged or changed)", ErrInvalid)
	}
	var p Payload
	if err := json.Unmarshal(body, &p); err != nil {
		return Header{}, Payload{}, fmt.Errorf("%w: damaged payload: %v", ErrInvalid, err)
	}
	if (p.Accounts != nil || p.APIKeys != nil) != h.Has(ContentAccounts) {
		return Header{}, Payload{}, fmt.Errorf("%w: contents don't match the header", ErrInvalid)
	}
	if h.Has(ContentAccounts) && !h.Encrypted() {
		return Header{}, Payload{}, fmt.Errorf("%w: users and API keys in an unencrypted backup are refused", ErrInvalid)
	}
	return h, p, nil
}

// FileName is the suggested name for a backup.
func FileName(h Header) string {
	host := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' {
			return r
		}
		return '-'
	}, orDash(h.Hostname))
	return fmt.Sprintf("sjb-os-%s-%s.backup", host, h.Created.UTC().Format("20060102-150405"))
}
