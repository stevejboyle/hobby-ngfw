package accounts

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"sync"
)

// Iterations is the PBKDF2-SHA256 work factor (OWASP's 2023 figure). Tests
// lower it.
var Iterations = 600_000

// MinPasswordLen applies to every password set through the UI or the CLI.
const MinPasswordLen = 10

// HashPassword returns "pbkdf2-sha256$<iter>$<salt>$<hash>".
func HashPassword(pw string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	h, err := pbkdf2.Key(sha256.New, pw, salt, Iterations, 32)
	if err != nil {
		return "", err
	}
	enc := base64.RawStdEncoding
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s", Iterations, enc.EncodeToString(salt), enc.EncodeToString(h)), nil
}

// CheckPassword reports whether pw matches an encoded hash.
func CheckPassword(encoded, pw string) bool {
	f := strings.Split(encoded, "$")
	if len(f) != 4 || f[0] != "pbkdf2-sha256" {
		return false
	}
	iter, err := strconv.Atoi(f[1])
	if err != nil || iter < 1 {
		return false
	}
	enc := base64.RawStdEncoding
	salt, err1 := enc.DecodeString(f[2])
	want, err2 := enc.DecodeString(f[3])
	if err1 != nil || err2 != nil {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, pw, salt, iter, len(want))
	return err == nil && subtle.ConstantTimeCompare(got, want) == 1
}

// dummy is checked against when a user does not exist, so a wrong user
// name takes as long as a wrong password.
var dummy = sync.OnceValue(func() string { h, _ := HashPassword("stops junk at the border"); return h })

// CheckNewPassword applies the password rules.
func CheckNewPassword(pw string) error {
	if len(pw) < MinPasswordLen {
		return fmt.Errorf("%w: password must be at least %d characters", ErrInvalid, MinPasswordLen)
	}
	if strings.ContainsAny(pw, "\n\r") {
		return fmt.Errorf("%w: password must not contain line breaks", ErrInvalid)
	}
	return nil
}
