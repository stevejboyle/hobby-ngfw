package daemon

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stevejboyle/hobby-ngfw/internal/decrypt"
)

type fakeTLSD struct {
	running       bool
	answering     bool
	starts, stops int
	reloads       int
	cleared       int
}

func (f *fakeTLSD) Available() bool { return true }
func (f *fakeTLSD) Start() error    { f.starts++; f.running, f.answering = true, true; return nil }
func (f *fakeTLSD) Stop() error     { f.stops++; f.running, f.answering = false, false; return nil }
func (f *fakeTLSD) Running() bool   { return f.running }
func (f *fakeTLSD) Status() (decrypt.Status, error) {
	if !f.answering {
		return decrypt.Status{}, errors.New("not answering")
	}
	return decrypt.Status{Mode: decrypt.ModeObserve, Counts: map[string]int64{"would-decrypt": 3}, Active: 1, Learned: 2}, nil
}
func (f *fakeTLSD) Reload() error { f.reloads++; return nil }
func (f *fakeTLSD) Learned() ([]decrypt.LearnedEntry, error) {
	return []decrypt.LearnedEntry{{ServerName: "app.example", IP: "203.0.113.5"}}, nil
}
func (f *fakeTLSD) ClearLearned() (int, error) { f.cleared++; return 1, nil }
func (f *fakeTLSD) Owner() decrypt.Owner       { return decrypt.NoOwner }

const decryptCfg = `
decryption_exclusions:
  - name: bank
    domains: [bank.example]
decryption_rules:
  - name: users-out
    from: [users]
    to: [internet]
    service: [web]
    action: decrypt
`

func TestDecryptionLifecycle(t *testing.T) {
	d, nf := setup(t)
	ft := &fakeTLSD{}
	dir := t.TempDir()
	policy := filepath.Join(dir, "policy.json")
	d.SetDecrypt(ft, filepath.Join(dir, "ca"), policy)
	d.dec.cpus = func() int { return 2 }

	cfg := string(lab(t)) + decryptCfg
	if err := d.SetCandidate([]byte(cfg)); err != nil {
		t.Fatal(err)
	}
	res, err := d.Commit("t", "decrypt", 0)
	if err != nil {
		t.Fatal(err)
	}
	w := strings.Join(res.Warnings, "\n")
	for _, want := range []string{"with 2 vCPU: give it 4", "no decryption CA yet"} {
		if !strings.Contains(w, want) {
			t.Errorf("warnings lack %q:\n%s", want, w)
		}
	}
	if ft.starts != 1 || !strings.Contains(nf.Last(), "add element inet ngfw decrypt_ready { 0.0.0.0/0 }") {
		t.Fatalf("tlsd started %d times; last nft: %s", ft.starts, nf.Last())
	}
	p, err := decrypt.ReadPolicy(policy)
	if err != nil || p.Mode != decrypt.ModeDecrypt || len(p.Rules) != 1 || p.Rules[0].BadCertificate != "warn" || !p.Builtin || p.Exclusions[0].Domains[0] != "bank.example" {
		t.Fatalf("policy %+v %v", p, err)
	}
	st := d.Decryption()
	if st.State != "no-ca" || !st.Ready || st.Counts["would-decrypt"] != 3 {
		t.Fatalf("status %+v", st)
	}

	info, err := d.GenerateDecryptionCA("t")
	if err != nil || !info.Present || ft.reloads != 1 {
		t.Fatalf("generate: %+v %v reloads=%d", info, err, ft.reloads)
	}
	if st := d.Decryption(); st.State != "decrypting" || st.CA.Fingerprint != info.Fingerprint || st.CA.PEM != "" {
		t.Fatalf("status after CA: %+v", st)
	}
	if ca := d.DecryptionCA(); !strings.HasPrefix(ca.PEM, "-----BEGIN CERTIFICATE") {
		t.Fatal("the CA's certificate is downloadable")
	}

	// tlsd stops answering: connections take the normal path (fail open).
	ft.answering = false
	d.checkDecryptLocked()
	if !strings.Contains(nf.Last(), "flush set inet ngfw decrypt_ready") {
		t.Fatalf("set not flushed: %s", nf.Last())
	}
	if st := d.Decryption(); st.State != "unavailable" || st.Ready {
		t.Fatalf("status while down: %+v", st)
	}
	ft.answering = true
	d.checkDecryptLocked()
	if !strings.Contains(nf.Last(), "add element") {
		t.Fatal("set refilled once tlsd answers")
	}

	// The periodic pass doesn't rewrite or reload an unchanged policy.
	d.ReconcileRoutes()
	if ft.reloads != 1 || ft.starts != 1 {
		t.Fatalf("periodic pass: reloads=%d starts=%d", ft.reloads, ft.starts)
	}
	if n, err := d.ClearDecryptionLearned("t"); err != nil || n != 1 || ft.cleared != 1 {
		t.Fatalf("clear learned: %d %v", n, err)
	}

	// Observe: tlsd only logs.
	if err := d.SetCandidate([]byte(strings.Replace(cfg, "hostname: ", "decryption: observe\n  hostname: ", 1))); err != nil {
		t.Fatal(err)
	}
	res, err = d.Commit("t", "observe", 0)
	if err != nil {
		t.Fatal(err)
	}
	if p, _ := decrypt.ReadPolicy(policy); p.Mode != decrypt.ModeObserve || !strings.Contains(strings.Join(res.Warnings, "\n"), "set to observe") {
		t.Fatalf("observe: mode %q, warnings %q", p.Mode, res.Warnings)
	}
	if st := d.Decryption(); st.State != "observing" {
		t.Fatalf("status observing: %+v", st)
	}

	// Decryption off: tlsd stops.
	if err := d.SetCandidate([]byte(strings.Replace(cfg, "hostname: ", "decryption: \"off\"\n  hostname: ", 1))); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Commit("t", "off", 0); err != nil {
		t.Fatal(err)
	}
	if ft.stops != 1 || strings.Contains(nf.Last(), "chain decrypt") {
		t.Fatalf("stops=%d", ft.stops)
	}
	if st := d.Decryption(); st.State != "off" {
		t.Fatalf("status off: %+v", st)
	}
}

func TestImportDecryptionCARejectsBadInput(t *testing.T) {
	d, _ := setup(t)
	d.SetDecrypt(&fakeTLSD{}, t.TempDir(), filepath.Join(t.TempDir(), "p.json"))
	if _, err := d.ImportDecryptionCA("t", []byte("nope"), []byte("nope")); !errors.Is(err, ErrInvalid) {
		t.Fatalf("want ErrInvalid, got %v", err)
	}
}
