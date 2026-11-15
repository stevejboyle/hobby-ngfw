package daemon

import (
	"strings"
	"testing"

	"github.com/stevejboyle/hobby-ngfw/internal/ips"
	"github.com/stevejboyle/hobby-ngfw/internal/nfqueue"
)

// The IPS reports what it does to traffic, from the kernel's queue table,
// not from whether a process runs: a running engine that isn't bound to its
// queue is not inspecting, and traffic passes uninspected (fail-open).
func TestIPSStateFollowsTheQueueNotTheProcess(t *testing.T) {
	d, _ := setup(t)
	fs := &fakeSuricata{mem: 8 << 30}
	d.SetIPS(fs, &ips.Engine{Dir: t.TempDir(), URL: "http://127.0.0.1:1/none"})
	var q nfqueue.State
	d.Queues = func(...int) nfqueue.State { return q }

	if st := d.IPS(); st.State != "off" {
		t.Fatalf("no config yet: %+v", st)
	}
	cfg := strings.Replace(string(lab(t)), "    service: [web]\n    action: allow\n    log: true", "    service: [web]\n    action: allow\n    log: true\n    ips_profile: default", 1)
	d.SetCandidate([]byte(cfg))
	if _, err := d.Commit("steve", "ips", 0); err != nil {
		t.Fatal(err)
	}
	fs.running = false
	if st := d.IPS(); st.State != "unavailable" || !strings.Contains(st.Detail, "passes uninspected") {
		t.Fatalf("engine down: %s: %s", st.State, st.Detail)
	}
	fs.running = true // the process runs, the queue has no listener yet
	if st := d.IPS(); st.State != "starting" || !strings.Contains(st.Detail, "passes uninspected") {
		t.Fatalf("running, unbound: %s: %s", st.State, st.Detail)
	}
	q = nfqueue.State{Bound: true}
	if st := d.IPS(); st.State != "inspecting" {
		t.Fatalf("bound: %s: %s", st.State, st.Detail)
	}
	q.Dropped = 12
	if st := d.IPS(); !strings.Contains(st.Detail, "12 packets passed uninspected") {
		t.Fatalf("queue overflow not reported: %s", st.Detail)
	}
}

func TestAppIdentificationState(t *testing.T) {
	d, _ := setup(t)
	var q nfqueue.State
	d.Queues = func(...int) nfqueue.State { return q }
	if st := d.Apps(); st.State != "unavailable" || !strings.Contains(st.Detail, "at most 40 packets") {
		t.Fatalf("appidd not bound: %s: %s", st.State, st.Detail)
	}
	q.Bound = true
	if st := d.Apps(); st.State != "classifying" {
		t.Fatalf("bound: %s: %s", st.State, st.Detail)
	}
	off := strings.Replace(string(lab(t)), "  hostname: fw-lab\n", "  hostname: fw-lab\n  app_id: \"off\"\n", 1)
	d.SetCandidate([]byte(off))
	if _, err := d.Commit("steve", "app id off", 0); err != nil {
		t.Fatal(err)
	}
	if st := d.Apps(); st.State != "off" {
		t.Fatalf("off: %s: %s", st.State, st.Detail)
	}
}
