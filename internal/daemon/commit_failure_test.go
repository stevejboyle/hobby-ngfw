package daemon

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stevejboyle/hobby-ngfw/internal/conntrack"
	"github.com/stevejboyle/hobby-ngfw/internal/nft"
	"github.com/stevejboyle/hobby-ngfw/internal/store"
)

// Failure injection for the commit pipeline: a commit either takes effect
// and is recorded, or leaves enforcement, the running revision and any
// pending confirmation as they were; when it can't even restore those, the
// daemon says so in Status.

var errDisk = errors.New("injected disk failure")

// committed sets up a daemon running the lab config as revision 1.
func committed(t *testing.T) (*Daemon, *store.Store, func() string) {
	t.Helper()
	d, f := setup(t)
	if err := d.SetCandidate(lab(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Commit("steve", "lab", 0); err != nil {
		t.Fatal(err)
	}
	return d, d.store, f.Last
}

func failOn(st *store.Store, op string) {
	st.Fail = func(o string) error {
		if o == op {
			return errDisk
		}
		return nil
	}
}

// expectUnchanged checks revision 1 still runs, is the only revision, and
// is what nftables enforces.
func expectUnchanged(t *testing.T, d *Daemon, last func() string, ruleset string) {
	t.Helper()
	n, _, err := d.store.Running()
	if err != nil || n != 1 {
		t.Fatalf("running revision %d, %v; want 1", n, err)
	}
	revs, _ := d.store.List()
	if len(revs) != 1 {
		t.Fatalf("revisions %v; the failed commit must not leave one behind", revs)
	}
	if last() != ruleset {
		t.Fatalf("enforced ruleset is not revision 1's:\n%s", last())
	}
}

func TestCommitFailsBeforeApplyWhenRevisionCantBeSaved(t *testing.T) {
	d, st, last := committed(t)
	before := last()
	d.SetCandidate(withoutWeb(t))
	failOn(st, "revision")
	if _, err := d.Commit("steve", "drop web", 0); err == nil || !strings.Contains(err.Error(), "nothing applied") {
		t.Fatalf("err = %v", err)
	}
	expectUnchanged(t, d, last, before)
}

func TestCommitRestoresPreviousRulesetWhenRunningPointerFails(t *testing.T) {
	d, st, last := committed(t)
	before := last()
	d.SetCandidate(withoutWeb(t))
	failOn(st, "running")
	_, err := d.Commit("steve", "drop web", 0)
	if err == nil || !strings.Contains(err.Error(), "previous ruleset was restored") {
		t.Fatalf("err = %v", err)
	}
	st.Fail = nil
	expectUnchanged(t, d, last, before)
	if s, _ := d.Status(); s.Recovery != "" {
		t.Fatalf("restored cleanly, yet recovery = %q", s.Recovery)
	}
}

func TestCommitReportsRecoveryWhenRestoreFails(t *testing.T) {
	d, st, _ := committed(t)
	d.SetCandidate(withoutWeb(t))
	failOn(st, "running")
	// The new ruleset applies; putting the old one back fails.
	applied := 0
	d.nft.(*nft.Fake).ApplyErr = func(string) error {
		applied++
		if applied > 1 {
			return errors.New("injected nft failure")
		}
		return nil
	}
	if _, err := d.Commit("steve", "drop web", 0); err == nil || !strings.Contains(err.Error(), "restoring the previous ruleset failed") {
		t.Fatalf("err = %v", err)
	}
	s, _ := d.Status()
	if s.Running != 1 || !strings.Contains(s.Recovery, "could not be restored") {
		t.Fatalf("status %+v", s)
	}
	// A later good commit clears the recovery state.
	st.Fail = nil
	d.nft.(*nft.Fake).ApplyErr = nil
	if _, err := d.Commit("steve", "drop web, again", 0); err != nil {
		t.Fatal(err)
	}
	if s, _ := d.Status(); s.Recovery != "" || s.Running != 2 {
		t.Fatalf("status after a good commit %+v", s)
	}
}

func TestConfirmedCommitFailsWhenDeadlineCantBeRecorded(t *testing.T) {
	d, st, last := committed(t)
	before := last()
	d.SetCandidate(withoutWeb(t))
	failOn(st, "pending")
	if _, err := d.Commit("steve", "drop web", time.Minute); err == nil || !strings.Contains(err.Error(), "confirmation deadline") {
		t.Fatalf("err = %v", err)
	}
	st.Fail = nil
	expectUnchanged(t, d, last, before)
	if s, _ := d.Status(); s.ConfirmBy != nil {
		t.Fatal("no confirmation may be pending")
	}
	if p, _ := st.LoadPending(); p != nil {
		t.Fatalf("pending on disk: %+v", p)
	}
}

func TestFailedCommitKeepsEarlierPendingConfirmation(t *testing.T) {
	d, st, _ := committed(t)
	d.SetCandidate(withoutWeb(t))
	res, err := d.Commit("steve", "drop web, confirmed", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Confirm() })
	deadline := *res.ConfirmBy
	// A later commit fails after the new deadline was written.
	d.SetCandidate(lab(t))
	failOn(st, "running")
	if _, err := d.Commit("steve", "web back", time.Minute); err == nil {
		t.Fatal("commit should fail")
	}
	st.Fail = nil
	s, _ := d.Status()
	if s.Running != 2 || s.ConfirmBy == nil || !s.ConfirmBy.Equal(deadline) {
		t.Fatalf("status %+v; want revision 2 still pending until %v", s, deadline)
	}
	p, err := st.LoadPending()
	if err != nil || p == nil || p.Revision != 2 || p.Previous != 1 || !p.Deadline.Equal(deadline) {
		t.Fatalf("pending on disk %+v, %v", p, err)
	}
}

func TestAutoRollbackFailureIsReportedAndRetried(t *testing.T) {
	d, st, _ := committed(t)
	d.SetCandidate(withoutWeb(t))
	if _, err := d.Commit("steve", "drop web, confirmed", 50*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	failOn(st, "revision") // the rollback can't record its revision
	waitFor(t, func() bool { s, _ := d.Status(); return s.Recovery != "" })
	s, _ := d.Status()
	if s.Running != 2 || !strings.Contains(s.Recovery, "rollback failed") {
		t.Fatalf("status %+v", s)
	}
	if p, _ := st.LoadPending(); p == nil || p.Revision != 2 {
		t.Fatalf("the confirmation must stay on disk for a restart to retry: %+v", p)
	}
	// Once the disk works again, the retry restores revision 1.
	st.Fail = nil
	d.mu.Lock()
	p := d.pending
	p.timer.Stop()
	d.mu.Unlock()
	d.autoRollback(p)
	if s, _ := d.Status(); s.Recovery != "" || s.ConfirmBy != nil {
		t.Fatalf("status after retry %+v", s)
	}
	_, run, _ := d.store.Running()
	if string(run) != string(lab(t)) {
		t.Fatal("revision 1's config should be running again")
	}
}

// Policy changes reset existing connections; commits that don't change the
// policy leave them alone. Manual and automatic rollbacks are commits too.
func TestPolicyChangesFlushConntrack(t *testing.T) {
	d, _, _ := committed(t)
	ct := d.ct.(*conntrack.Fake)
	flushes := ct.Count
	base := flushes()

	d.SetCandidate(lab(t))
	if _, err := d.Commit("steve", "same policy, new message", 0); err != nil {
		t.Fatal(err)
	}
	if flushes() != base {
		t.Fatal("a commit that doesn't change the policy must not reset connections")
	}
	d.SetCandidate(withoutWeb(t))
	if _, err := d.Commit("steve", "drop web", 0); err != nil {
		t.Fatal(err)
	}
	if flushes() != base+1 {
		t.Fatalf("policy change: flushes %d, want %d", flushes(), base+1)
	}
	if _, err := d.Rollback(1, "steve"); err != nil {
		t.Fatal(err)
	}
	if flushes() != base+2 {
		t.Fatalf("manual rollback: flushes %d, want %d", flushes(), base+2)
	}
	d.SetCandidate(withoutWeb(t))
	if _, err := d.Commit("steve", "drop web, confirmed", 50*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { s, _ := d.Status(); return s.ConfirmBy == nil })
	if flushes() != base+4 {
		t.Fatalf("confirmed commit + auto-rollback: flushes %d, want %d", flushes(), base+4)
	}
}
