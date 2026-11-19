package accounts

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
)

// keyTypes are the public key types accepted for SSH logins.
var keyTypes = map[string]bool{
	"ssh-ed25519":                        true,
	"ssh-rsa":                            true,
	"ecdsa-sha2-nistp256":                true,
	"ecdsa-sha2-nistp384":                true,
	"ecdsa-sha2-nistp521":                true,
	"sk-ssh-ed25519@openssh.com":         true,
	"sk-ecdsa-sha2-nistp256@openssh.com": true,
}

// KeyInfo describes a user's SSH public key.
type KeyInfo struct {
	Type        string `json:"type"`
	Comment     string `json:"comment,omitempty"`
	Fingerprint string `json:"fingerprint"`
	Key         string `json:"key"`
}

// ParseKey checks one authorized_keys line in plain form ("TYPE BASE64
// [COMMENT]"; options such as command= are refused) and returns it
// normalised with its fingerprint (SHA256:..., as ssh-keygen -l prints it).
func ParseKey(line string) (KeyInfo, error) {
	line = strings.TrimSpace(line)
	if strings.ContainsAny(line, "\n\r\x00") {
		return KeyInfo{}, fmt.Errorf("%w: one key per line", ErrInvalid)
	}
	f := strings.Fields(line)
	if len(f) < 2 {
		return KeyInfo{}, fmt.Errorf("%w: an SSH public key looks like \"ssh-ed25519 AAAA... comment\"", ErrInvalid)
	}
	if !keyTypes[f[0]] {
		return KeyInfo{}, fmt.Errorf("%w: unsupported key type %q (options such as command= aren't accepted)", ErrInvalid, f[0])
	}
	blob, err := base64.StdEncoding.DecodeString(f[1])
	if err != nil {
		return KeyInfo{}, fmt.Errorf("%w: the key isn't valid base64", ErrInvalid)
	}
	// The blob starts with the key type as an SSH string.
	if len(blob) < 4 {
		return KeyInfo{}, fmt.Errorf("%w: the key is truncated", ErrInvalid)
	}
	n := binary.BigEndian.Uint32(blob)
	if uint64(n)+4 > uint64(len(blob)) || string(blob[4:4+n]) != f[0] {
		return KeyInfo{}, fmt.Errorf("%w: the key data doesn't match its type %s", ErrInvalid, f[0])
	}
	comment := strings.Join(f[2:], " ")
	if len(comment) > 200 {
		return KeyInfo{}, fmt.Errorf("%w: key comment longer than 200 characters", ErrInvalid)
	}
	sum := sha256.Sum256(blob)
	k := KeyInfo{Type: f[0], Comment: comment, Fingerprint: "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])}
	k.Key = f[0] + " " + f[1]
	if comment != "" {
		k.Key += " " + comment
	}
	return k, nil
}

func keyInfos(keys []string) []KeyInfo {
	out := []KeyInfo{}
	for _, k := range keys {
		if ki, err := ParseKey(k); err == nil {
			out = append(out, ki)
		}
	}
	return out
}
