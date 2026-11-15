package webui

import (
	"bufio"
	"bytes"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// Iterations is the PBKDF2-SHA256 work factor (OWASP's 2023 figure). Tests
// lower it.
var Iterations = 600_000

// MinPasswordLen applies to passwords set through the UI or fwctl.
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

func checkPassword(encoded, pw string) bool {
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

// Users is the web user file: one "<name> <hash>" per line, mode 0600.
type Users struct {
	Path string
	// System, if set, also sets the user's login password (SSH and
	// console), so one password works everywhere. It runs first: if it
	// fails, nothing changes.
	System func(name, pw string) error
	mu     sync.Mutex
}

// SetUnixPassword sets a local account's password with chpasswd.
func SetUnixPassword(name, pw string) error {
	if strings.ContainsAny(pw, "\n\r") || strings.ContainsAny(name, ":\n") {
		return fmt.Errorf("password or user name contains a line break")
	}
	cmd := exec.Command("chpasswd")
	cmd.Stdin = strings.NewReader(name + ":" + pw + "\n")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("chpasswd: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (u *Users) load() (map[string]string, error) {
	data, err := os.ReadFile(u.Path)
	if err != nil {
		return nil, err
	}
	m := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) == 2 {
			m[f[0]] = f[1]
		}
	}
	return m, sc.Err()
}

// dummy is checked against when the user does not exist, so a wrong user
// name takes as long as a wrong password.
var dummy = sync.OnceValue(func() string { h, _ := HashPassword("stops junk at the border"); return h })

// Verify reports whether name/pw is a valid login.
func (u *Users) Verify(name, pw string) bool {
	u.mu.Lock()
	m, err := u.load()
	u.mu.Unlock()
	h, ok := m[name]
	if err != nil || !ok {
		checkPassword(dummy(), pw)
		return false
	}
	return checkPassword(h, pw)
}

// Set creates or changes a user's password.
func (u *Users) Set(name, pw string) error {
	if strings.ContainsAny(name, " \t\n") || name == "" {
		return fmt.Errorf("bad user name")
	}
	if len(pw) < MinPasswordLen {
		return fmt.Errorf("password must be at least %d characters", MinPasswordLen)
	}
	if strings.ContainsAny(pw, "\n\r") {
		return fmt.Errorf("password must not contain line breaks")
	}
	h, err := HashPassword(pw)
	if err != nil {
		return err
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.System != nil {
		if err := u.System(name, pw); err != nil {
			return err
		}
	}
	m, err := u.load()
	if os.IsNotExist(err) {
		m, err = map[string]string{}, nil
	}
	if err != nil {
		return err
	}
	m[name] = h
	var b strings.Builder
	b.WriteString("# SJB-OS web UI users: <name> <pbkdf2 hash>. Change with `sudo fwctl web-passwd`.\n")
	for n, h := range m {
		fmt.Fprintf(&b, "%s %s\n", n, h)
	}
	tmp, err := os.CreateTemp(filepath.Dir(u.Path), ".web-users-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(b.String()); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), u.Path)
}
