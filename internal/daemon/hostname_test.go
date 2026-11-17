package daemon

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/stevejboyle/hobby-ngfw/internal/sysname"
)

type fakeHost struct{ applied []string }

func (f *fakeHost) Sync(name string) (bool, error) {
	if !sysname.Valid(name) {
		return false, fmt.Errorf("%q isn't a valid hostname", name)
	}
	f.applied = append(f.applied, name)
	return true, nil
}

// A commit applies system.hostname to the system, so the CLI prompt, web
// UI and console follow the config; an unusable name is a commit warning,
// not a failed commit.
func TestCommitAppliesHostname(t *testing.T) {
	d, _ := setup(t)
	h := &fakeHost{}
	d.SetHostname(h)
	cfg := strings.Replace(string(lab(t)), "  hostname: fw-lab\n", "  hostname: sjb-lab\n", 1)
	d.SetCandidate([]byte(cfg))
	if _, err := d.Commit("steve", "rename", 0); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(h.applied, "sjb-lab") {
		t.Fatalf("hostname not applied: %v", h.applied)
	}
	bad := strings.Replace(string(lab(t)), "  hostname: fw-lab\n", "  hostname: my firewall\n", 1)
	d.SetCandidate([]byte(bad))
	res, err := d.Commit("steve", "bad name", 0)
	if err != nil {
		t.Fatalf("an unusable hostname failed the commit: %v", err)
	}
	if !slices.ContainsFunc(res.Warnings, func(w string) bool { return strings.Contains(w, "hostname not applied") }) {
		t.Fatalf("no warning for an unusable hostname: %v", res.Warnings)
	}
}
