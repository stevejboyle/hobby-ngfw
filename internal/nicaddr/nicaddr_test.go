package nicaddr

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fake struct {
	dir   string
	calls []string
	addrs map[string]string // nic -> address the kernel shows
	fail  bool
}

func (f *fake) networkctl(args ...string) error {
	f.calls = append(f.calls, strings.Join(args, " "))
	if f.fail {
		return errors.New("networkctl failed")
	}
	return nil
}

func (f *fake) hasAddr(nic, addr string) bool { return f.addrs[nic] == addr }

func (f *fake) syncer() *Networkd {
	return &Networkd{Dir: f.dir, NICs: []string{"inside", "outside"}, Networkctl: f.networkctl, HasAddr: f.hasAddr, Wait: 1}
}

func setup(t *testing.T) *fake {
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("20-inside.network", "[Match]\nName=inside\n\n[Network]\nAddress=10.10.1.1/24\nConfigureWithoutCarrier=yes\n")
	write("20-outside.network", "[Match]\nName=outside\n\n[Network]\nDHCP=ipv4\nDNS=1.1.1.1\nDNS=9.9.9.9\n")
	return &fake{dir: dir, addrs: map[string]string{}}
}

func TestOverrideWrittenAndRemoved(t *testing.T) {
	f := setup(t)
	f.addrs["outside"] = "192.168.1.20/24" // networkd applies it
	st, err := f.syncer().Sync(map[string]string{"outside": "192.168.1.20/24", "inside": "10.10.1.1/24"}, Commit)
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(f.dir, "10-outside-sjb.network"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Name=outside", "DHCP=no", "DNS=1.1.1.1\nDNS=9.9.9.9\n\n[Address]\nAddress=192.168.1.20/24\nDuplicateAddressDetection=ipv4\n"} {
		if !strings.Contains(string(body), want) {
			t.Errorf("override lacks %q:\n%s", want, body)
		}
	}
	// inside's address matches the deployment: no override, no reconfigure.
	if _, err := os.Stat(filepath.Join(f.dir, "10-inside-sjb.network")); err == nil {
		t.Error("inside override written though the deployment already has that address")
	}
	if got := strings.Join(f.calls, "; "); got != "reload; reconfigure outside" {
		t.Errorf("networkctl calls: %q", got)
	}
	// inside isn't shown with its address by the fake: reported, not reconfigured.
	if len(st) != 2 || st[0].Applied || st[1].Name != "outside" || !st[1].Applied {
		t.Errorf("states: %+v", st)
	}

	// Unchanged: no networkctl at all.
	f.calls = nil
	f.addrs["inside"] = "10.10.1.1/24"
	n := f.syncer()
	if _, err := n.Sync(map[string]string{"outside": "192.168.1.20/24", "inside": "10.10.1.1/24"}, Commit); err != nil {
		t.Fatal(err)
	}
	if len(f.calls) != 0 {
		t.Errorf("unchanged sync ran networkctl: %q", f.calls)
	}

	// Address removed from the config: back to the deployment settings.
	if _, err := n.Sync(map[string]string{}, Commit); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(f.dir, "10-outside-sjb.network")); err == nil {
		t.Error("override still there after the address was removed")
	}
	if got := strings.Join(f.calls, "; "); got != "reload; reconfigure outside" {
		t.Errorf("networkctl calls on removal: %q", got)
	}
}

func TestNotAppliedIsReportedAndRetried(t *testing.T) {
	f := setup(t)
	f.fail = true
	n := f.syncer()
	want := map[string]string{"outside": "192.168.1.20/24"}
	st, err := n.Sync(want, Commit)
	if err != nil {
		t.Fatal(err)
	}
	if st[0].Applied || !strings.Contains(st[0].Error, "networkctl failed") {
		t.Fatalf("state: %+v", st[0])
	}
	// Next pass: file unchanged, but the failed NIC is retried.
	f.fail, f.calls = false, nil
	f.addrs["outside"] = "192.168.1.20/24"
	st, _ = n.Sync(want, Commit)
	if got := strings.Join(f.calls, "; "); got != "reload; reconfigure outside" || !st[0].Applied {
		t.Fatalf("retry: calls %q state %+v", got, st[0])
	}
	// And then left alone.
	f.calls = nil
	n.Sync(want, Commit)
	if len(f.calls) != 0 {
		t.Fatalf("calls after success: %q", f.calls)
	}
}

func TestUnmanagedNIC(t *testing.T) {
	f := setup(t)
	st, err := f.syncer().Sync(map[string]string{"eth5": "10.9.9.1/24"}, Commit)
	if err != nil {
		t.Fatal(err)
	}
	if len(st) != 1 || st[0].Applied || !strings.Contains(st[0].Error, "doesn't manage") {
		t.Fatalf("state: %+v", st)
	}
	if len(f.calls) != 0 {
		t.Fatalf("networkctl ran: %q", f.calls)
	}
}

// An upgrade that changes the override's content (r05 -> r06 added the
// [Address] section) must not make ngfwd's start call networkctl or wait:
// systemd waits for ngfwd's socket. The periodic pass applies it.
func TestStartDefersApplying(t *testing.T) {
	f := setup(t)
	path := filepath.Join(f.dir, FileName("outside"))
	if err := os.WriteFile(path, []byte("older render\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f.addrs["outside"] = "192.168.1.20/24" // the old file's address is still up
	n := f.syncer()
	n.Wait = time.Hour // a wait would hang the test
	want := map[string]string{"outside": "192.168.1.20/24"}
	if _, err := n.Sync(want, Deferred); err != nil {
		t.Fatal(err)
	}
	if body, _ := os.ReadFile(path); !strings.Contains(string(body), "DuplicateAddressDetection") {
		t.Fatalf("override not rewritten at start:\n%s", body)
	}
	if len(f.calls) != 0 {
		t.Fatalf("start ran networkctl: %q", f.calls)
	}
	// Periodic pass: applies the pending change, without waiting.
	delete(f.addrs, "outside") // mid-reconfigure, conflict detection running
	st, _ := n.Sync(want, Background)
	if got := strings.Join(f.calls, "; "); got != "reload; reconfigure outside" {
		t.Fatalf("periodic pass calls: %q", got)
	}
	if st[0].Applied {
		t.Fatalf("state: %+v", st[0])
	}
	f.calls = nil
	n.Sync(want, Background)
	if len(f.calls) != 0 {
		t.Fatalf("applied twice: %q", f.calls)
	}
}

func TestTrunkOverrideHasNoAddress(t *testing.T) {
	f := setup(t)
	// inside's deployment file sets 10.10.1.1/24; as a trunk it gets none.
	st, err := f.syncer().Sync(map[string]string{"inside": TrunkOnly}, Commit)
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(f.dir, "10-inside-sjb.network"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "Name=inside") || !strings.Contains(string(body), "DHCP=no") ||
		strings.Contains(string(body), "Address=") {
		t.Errorf("trunk override:\n%s", body)
	}
	if len(st) != 1 || !st[0].Applied {
		t.Errorf("states: %+v", st)
	}
	if strings.Join(f.calls, ",") != "reload,reconfigure inside" {
		t.Errorf("networkctl calls: %v", f.calls)
	}
	// Back to a zone with no address: the deployment's settings return.
	if _, err := f.syncer().Sync(map[string]string{}, Commit); err != nil {
		t.Fatal(err)
	}
	if HasOverride(f.dir, "inside") {
		t.Error("override left behind")
	}
}
