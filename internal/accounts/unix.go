package accounts

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// System is the Unix side of an account: the login that lands in the
// captive CLI over SSH and on the console. Every method runs fixed tools
// with checked arguments (names are validated before they get here).
type System interface {
	// Lookup reports whether a Unix account exists and whether SJB-OS
	// created it (Marker in its comment field).
	Lookup(name string) (exists, ours bool)
	// Ensure creates the account if needed (no usable password yet) and
	// sets whether it may log in.
	Ensure(name string, enabled bool) error
	// Remove ends the account's sessions and deletes it.
	Remove(name string) error
	// SetPassword sets the login password (SSH and console).
	SetPassword(name, pw string) error
	// Terminate ends every login session of the account.
	Terminate(name string)
	// ResetFailures clears the SSH/console lockout counter.
	ResetFailures(name string)
	// WriteKeys writes the account's authorized SSH keys (none: removed).
	WriteKeys(name string, keys []string) error
	// Ours lists the accounts SJB-OS created.
	Ours() []string
}

// Marker is the comment (GECOS) field of the Unix accounts SJB-OS creates.
const Marker = "SJB-OS user"

// Exec is the appliance's System.
type Exec struct {
	Shell  string // the captive CLI login shim
	Group  string // may use ngfwd's management socket
	KeyDir string // authorized keys, one file per user (sshd's AuthorizedKeysFile)
	Passwd string // /etc/passwd
	Shadow string // /etc/shadow (password hashes, for backups)
}

// DefaultExec is the appliance layout.
func DefaultExec() *Exec {
	return &Exec{Shell: "/usr/lib/sjb-os/login-shell", Group: "sjbadm", KeyDir: "/etc/ssh/sjb-keys", Passwd: "/etc/passwd", Shadow: "/etc/shadow"}
}

func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %v: %s", name, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (e *Exec) entries() map[string]string {
	m := map[string]string{}
	f, err := os.Open(e.Passwd)
	if err != nil {
		return m
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		p := strings.Split(sc.Text(), ":")
		if len(p) >= 5 {
			m[p[0]] = p[4]
		}
	}
	return m
}

func (e *Exec) Lookup(name string) (bool, bool) {
	gecos, ok := e.entries()[name]
	return ok, ok && gecos == Marker
}

func (e *Exec) Ours() []string {
	var out []string
	for n, g := range e.entries() {
		if g == Marker {
			out = append(out, n)
		}
	}
	return out
}

func (e *Exec) Ensure(name string, enabled bool) error {
	exists, ours := e.Lookup(name)
	if exists && !ours {
		return fmt.Errorf("Unix account %q exists and wasn't created by SJB-OS; leaving it alone", name)
	}
	if !exists {
		// No home directory: the captive CLI needs none, and sshd reads
		// keys from KeyDir. The password stays locked until one is set.
		if err := run("useradd", "--no-create-home", "--home-dir", "/nonexistent", "--shell", e.Shell,
			"--comment", Marker, "--groups", e.Group, "--", name); err != nil {
			return err
		}
	}
	if enabled {
		// Back in the group (sjb-migrate undo takes it out), no expiry;
		// unlocking fails harmlessly when no password is set yet.
		if err := run("usermod", "--shell", e.Shell, "--append", "--groups", e.Group, "--expiredate", "", "--", name); err != nil {
			return err
		}
		run("usermod", "--unlock", "--", name)
		return nil
	}
	run("gpasswd", "--delete", name, e.Group)
	if err := run("usermod", "--lock", "--expiredate", "1", "--", name); err != nil {
		return err
	}
	e.Terminate(name)
	return nil
}

func (e *Exec) Remove(name string) error {
	if _, ours := e.Lookup(name); !ours {
		return nil
	}
	e.Terminate(name)
	os.Remove(filepath.Join(e.KeyDir, name))
	return run("userdel", "--", name)
}

func (e *Exec) SetPassword(name, pw string) error { return SetUnixPassword(name, pw) }

func (e *Exec) Terminate(name string) {
	// Both: logind sessions (SSH, console), then any process left over.
	run("loginctl", "terminate-user", name)
	run("pkill", "-KILL", "-u", name)
}

func (e *Exec) ResetFailures(name string) { run("faillock", "--user", name, "--reset") }

func (e *Exec) WriteKeys(name string, keys []string) error {
	path := filepath.Join(e.KeyDir, name)
	if len(keys) == 0 {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	if err := os.MkdirAll(e.KeyDir, 0o755); err != nil {
		return err
	}
	// Root-owned and world-readable: sshd reads it with the user's rights.
	return writeAtomic(path, []byte(strings.Join(keys, "\n")+"\n"), 0o644)
}

// SetUnixPassword sets a local account's password with chpasswd.
func SetUnixPassword(name, pw string) error {
	if strings.ContainsAny(pw, "\n\r") || strings.ContainsAny(name, ":\n") {
		return fmt.Errorf("%w: password or user name contains a line break", ErrInvalid)
	}
	cmd := exec.Command("chpasswd")
	cmd.Stdin = strings.NewReader(name + ":" + pw + "\n")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("chpasswd: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
