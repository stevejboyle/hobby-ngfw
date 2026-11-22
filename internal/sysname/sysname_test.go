package sysname

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValid(t *testing.T) {
	for name, want := range map[string]bool{
		"sjb-fw": true, "fw1.lab.example": true, "FW-2": true, strings.Repeat("a", 63): true,
		"": false, "-fw": false, "fw-": false, "fw_1": false, "fw 1": false, "fw..lab": false,
		strings.Repeat("a", 64): false, strings.Repeat("a.", 32) + "a": false,
	} {
		if Valid(name) != want {
			t.Errorf("Valid(%q) = %v, want %v", name, !want, want)
		}
	}
}

type fakeSys struct {
	name string
	sets int
	err  error
}

func (f *fakeSys) host(etc string) *Host {
	return &Host{Etc: etc,
		Get: func() (string, error) { return f.name, nil },
		Set: func(n string) error {
			if f.err != nil {
				return f.err
			}
			f.name, f.sets = n, f.sets+1
			return nil
		}}
}

func TestSync(t *testing.T) {
	etc := t.TempDir()
	os.WriteFile(filepath.Join(etc, "hostname"), []byte("old-fw\n"), 0o644)
	os.WriteFile(filepath.Join(etc, "hosts"), []byte("127.0.0.1 localhost\n127.0.1.1 old-fw\n::1 localhost ip6-localhost\n"), 0o644)
	f := &fakeSys{name: "old-fw"}
	h := f.host(etc)

	changed, err := h.Sync("sjb-lab")
	if err != nil || !changed || f.name != "sjb-lab" || f.sets != 1 {
		t.Fatalf("first sync: changed %v err %v name %q sets %d", changed, err, f.name, f.sets)
	}
	if b, _ := os.ReadFile(filepath.Join(etc, "hostname")); string(b) != "sjb-lab\n" {
		t.Errorf("/etc/hostname = %q", b)
	}
	if b, _ := os.ReadFile(filepath.Join(etc, "hosts")); string(b) != "127.0.0.1 localhost\n127.0.1.1 sjb-lab\n::1 localhost ip6-localhost\n" {
		t.Errorf("/etc/hosts = %q", b)
	}
	// Nothing differs: nothing is written or set.
	if changed, err := h.Sync("sjb-lab"); err != nil || changed || f.sets != 1 {
		t.Errorf("second sync: changed %v err %v sets %d", changed, err, f.sets)
	}
	// Someone changed the live name behind ngfwd's back: it is put back.
	f.name = "other"
	if changed, err := h.Sync("sjb-lab"); err != nil || !changed || f.name != "sjb-lab" {
		t.Errorf("live drift: changed %v err %v name %q", changed, err, f.name)
	}
}

func TestSyncRefusesInvalid(t *testing.T) {
	etc := t.TempDir()
	os.WriteFile(filepath.Join(etc, "hostname"), []byte("old-fw\n"), 0o644)
	f := &fakeSys{name: "old-fw"}
	if changed, err := f.host(etc).Sync("my firewall"); err == nil || changed || f.name != "old-fw" {
		t.Errorf("invalid name: changed %v err %v name %q", changed, err, f.name)
	}
	if b, _ := os.ReadFile(filepath.Join(etc, "hostname")); string(b) != "old-fw\n" {
		t.Errorf("/etc/hostname changed: %q", b)
	}
}

func TestSyncSetError(t *testing.T) {
	f := &fakeSys{name: "old-fw", err: errors.New("operation not permitted")}
	if _, err := f.host(t.TempDir()).Sync("sjb-lab"); err == nil || !strings.Contains(err.Error(), "not permitted") {
		t.Errorf("err = %v", err)
	}
}

func TestHostsWith(t *testing.T) {
	for in, want := range map[string]string{
		"":                      "127.0.1.1 fw\n",
		"127.0.0.1 localhost\n": "127.0.0.1 localhost\n127.0.1.1 fw\n",
		"127.0.1.1 a\n127.0.0.1 localhost\n127.0.1.1 b\n": "127.0.1.1 fw\n127.0.0.1 localhost\n",
		"# comment\n127.0.1.1\told.name old\n":            "# comment\n127.0.1.1 fw\n",
	} {
		if got := hostsWith(in, "fw"); got != want {
			t.Errorf("hostsWith(%q) = %q, want %q", in, got, want)
		}
	}
}
