package daemon

import (
	"bytes"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stevejboyle/sjb-os/internal/accounts"
	"github.com/stevejboyle/sjb-os/internal/metrics"
)

func TestRebootNeedsUpgradeRights(t *testing.T) {
	d, _ := setup(t)
	withAccounts(t, d)
	old := rebootDelay
	rebootDelay = 10 * time.Millisecond
	defer func() { rebootDelay = old }()
	var reboots atomic.Int32
	d.SetReboot(func() error { reboots.Add(1); return nil })
	h := d.MgmtHandler()
	ops := &accounts.Caller{Name: "ops", Via: "cli"}       // admin: no upgrades
	reader := &accounts.Caller{Name: "reader", Via: "cli"} // read-only
	for _, c := range []*accounts.Caller{nil, reader, ops} {
		if code, _ := sock(t, h, c, "POST", "/v1/reboot", "{}"); code != 403 {
			t.Errorf("%v: %d, want 403", c, code)
		}
	}
	time.Sleep(50 * time.Millisecond)
	if reboots.Load() != 0 {
		t.Fatal("rebooted for a caller without upgrade rights")
	}
	if code, body := sock(t, h, &accounts.Root, "POST", "/v1/reboot", "{}"); code != 200 || !strings.Contains(body, "rebooting") {
		t.Fatalf("root: %d %s", code, body)
	}
	deadline := time.Now().Add(2 * time.Second)
	for reboots.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if reboots.Load() != 1 {
		t.Fatalf("reboots %d, want 1", reboots.Load())
	}
}

func TestOSStateInMetrics(t *testing.T) {
	d, _ := setup(t)
	var calls atomic.Int32
	d.SetOSStatus(func() *metrics.OS {
		calls.Add(1)
		return &metrics.OS{PackagesState: "ok", PackagesPending: 2, RebootRequired: true, Kernel: "6.12.116+deb13-amd64"}
	})
	s := d.Metrics()
	if s.System.OS == nil || !s.System.OS.RebootRequired || s.System.OS.PackagesPending != 2 {
		t.Fatalf("snapshot OS %+v", s.System.OS)
	}
	var buf bytes.Buffer
	metrics.WritePrometheus(&buf, s)
	for _, want := range []string{
		`sjbos_reboot_required{kernel="6.12.116+deb13-amd64"} 1`,
		`sjbos_os_packages_state{state="ok"} 1`,
		`sjbos_os_packages_state{state="failed"} 0`,
		`sjbos_os_packages_pending 2`,
	} {
		if !strings.Contains(buf.String(), want+"\n") {
			t.Errorf("missing %s", want)
		}
	}
	// Read at most once per osStatusTTL, however often monitoring asks.
	for i := 0; i < 5; i++ {
		d.osState()
	}
	if calls.Load() != 1 {
		t.Errorf("OS status read %d times, want 1 (cached)", calls.Load())
	}
	// Off the appliance: no OS section, no made-up values.
	d.SetOSStatus(nil)
	if d.osState() != nil {
		t.Error("OS state without a reader")
	}
}
