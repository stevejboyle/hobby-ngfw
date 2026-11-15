package tags

import (
	"net/netip"
	"path/filepath"
	"testing"
	"time"
)

func TestRegistry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tags.json")
	r, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	a := netip.MustParseAddr("10.0.0.5")
	b := netip.MustParseAddr("10.0.0.6")

	if err := r.Register(a, []string{"quarantine", "iot"}, time.Hour, now); err != nil {
		t.Fatal(err)
	}
	if err := r.Register(b, []string{"quarantine"}, 0, now); err != nil {
		t.Fatal(err)
	}
	if got := r.List("quarantine", now); len(got) != 2 {
		t.Fatalf("quarantine members = %v", got)
	}
	if got := r.List("", now); len(got) != 3 {
		t.Fatalf("all entries = %v", got)
	}

	// Expiry: after two hours only the permanent entry is left.
	later := now.Add(2 * time.Hour)
	if got := r.List("", later); len(got) != 1 || got[0].IP != b {
		t.Fatalf("after expiry = %v", got)
	}

	if err := r.Unregister(b, []string{"quarantine", "never-registered"}, now); err != nil {
		t.Fatal(err)
	}

	// Persistence: reopen and see what survived.
	r2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	got := r2.List("", now)
	if len(got) != 2 || got[0].Tag != "iot" || got[1].Tag != "quarantine" || got[1].IP != a {
		t.Fatalf("reloaded = %v", got)
	}
	if rem := got[0].Remaining(now); rem != time.Hour {
		t.Fatalf("remaining = %v", rem)
	}
}

func TestValidate(t *testing.T) {
	if err := Validate(netip.MustParseAddr("2001:db8::1"), "x"); err == nil {
		t.Error("IPv6 should be rejected")
	}
	if err := Validate(netip.MustParseAddr("10.0.0.1"), "bad tag"); err == nil {
		t.Error("bad tag should be rejected")
	}
	if err := Validate(netip.Addr{}, "x"); err == nil {
		t.Error("zero addr should be rejected")
	}
}
