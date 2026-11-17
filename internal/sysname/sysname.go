// Package sysname applies the configured hostname to the system: the live
// hostname, /etc/hostname and the 127.0.1.1 line in /etc/hosts. First boot
// sets them from the deployment settings; afterwards the config's
// system.hostname is the source, so a commit renames the appliance.
package sysname

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// MaxLen is the kernel's limit on a hostname (HOST_NAME_MAX).
const MaxLen = 64

// Valid reports whether name works as a system hostname: dot-separated
// labels of letters, digits and hyphens, each 1-63 characters and not
// starting or ending with a hyphen, at most MaxLen in all.
func Valid(name string) bool {
	if name == "" || len(name) > MaxLen {
		return false
	}
	for _, l := range strings.Split(name, ".") {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for _, c := range l {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// Syncer applies a hostname. Sync reports whether anything changed.
type Syncer interface {
	Sync(name string) (bool, error)
}

// Noop applies nothing (tests, development).
type Noop struct{}

func (Noop) Sync(string) (bool, error) { return false, nil }

// Host applies the hostname under Etc (normally /etc) and to the running
// system through Get and Set.
type Host struct {
	Etc string
	Get func() (string, error)
	Set func(string) error
}

// Sync makes the system's hostname name. It is cheap when nothing differs,
// so it can run on every pass.
func (h *Host) Sync(name string) (bool, error) {
	name = strings.TrimSpace(name)
	if !Valid(name) {
		return false, fmt.Errorf("%q isn't a valid hostname (letters, digits and hyphens, dot-separated, at most %d characters); the system keeps its current name", name, MaxLen)
	}
	changed := false
	hn := filepath.Join(h.Etc, "hostname")
	if b, err := os.ReadFile(hn); err != nil || strings.TrimSpace(string(b)) != name {
		if err := writeAtomic(hn, []byte(name+"\n")); err != nil {
			return changed, err
		}
		changed = true
	}
	hosts := filepath.Join(h.Etc, "hosts")
	b, err := os.ReadFile(hosts)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return changed, err
	}
	if want := hostsWith(string(b), name); want != string(b) {
		if err := writeAtomic(hosts, []byte(want)); err != nil {
			return changed, err
		}
		changed = true
	}
	if cur, err := h.Get(); err != nil || cur != name {
		if err := h.Set(name); err != nil {
			return changed, fmt.Errorf("setting the hostname: %w", err)
		}
		changed = true
	}
	return changed, nil
}

// hostsWith returns hosts with its 127.0.1.1 entry naming name, the Debian
// convention first boot follows; every other line is kept.
func hostsWith(hosts, name string) string {
	want := "127.0.1.1 " + name
	var out []string
	found := false
	for _, l := range strings.Split(strings.TrimSuffix(hosts, "\n"), "\n") {
		if f := strings.Fields(l); len(f) > 0 && f[0] == "127.0.1.1" {
			if !found {
				out = append(out, want)
				found = true
			}
			continue
		}
		out = append(out, l)
	}
	if hosts == "" {
		out = nil
	}
	if !found {
		out = append(out, want)
	}
	return strings.Join(out, "\n") + "\n"
}

func writeAtomic(path string, data []byte) error {
	mode := os.FileMode(0o644)
	if st, err := os.Stat(path); err == nil {
		mode = st.Mode().Perm()
	}
	tmp := path + ".sjb-tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}
