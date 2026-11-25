package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stevejboyle/sjb-os/internal/accounts"
	"github.com/stevejboyle/sjb-os/internal/metrics"
	"github.com/stevejboyle/sjb-os/internal/snmp"
)

// fakeSNMPD records what ngfwd asks of snmpd.
type fakeSNMPD struct {
	mu      sync.Mutex
	applied []string
	running bool
}

func (f *fakeSNMPD) Available() bool { return true }
func (f *fakeSNMPD) Running() bool   { f.mu.Lock(); defer f.mu.Unlock(); return f.running }
func (f *fakeSNMPD) Apply(conf string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.applied = append(f.applied, conf)
	f.running = conf != ""
	return nil
}
func (f *fakeSNMPD) last() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.applied) == 0 {
		return "<none>"
	}
	return f.applied[len(f.applied)-1]
}

const snmpYAML = `
snmp:
  enabled: "on"
  location: Lab rack 1
  v3_users: [nms]
snmp_trap_receivers:
  - {name: graylog, address: 192.168.1.62, credential: nms, inform: "on"}
`

func TestSNMPLifecycle(t *testing.T) {
	d, _ := setup(t)
	withAccounts(t, d)
	fake := &fakeSNMPD{}
	creds := filepath.Join(t.TempDir(), "snmp-credentials")
	d.SetSNMP(fake, creds)
	root := accounts.Root
	ops := accounts.Caller{Name: "ops", Via: "cli"}

	// A config naming a credential that doesn't exist is refused whole.
	d.SetCandidate(append(lab(t), []byte(snmpYAML)...))
	if _, err := d.Commit("steve", "snmp", 0); err == nil || !strings.Contains(err.Error(), `no SNMP credential "nms"`) {
		t.Fatalf("commit without the credential: %v", err)
	}
	nms := snmp.Credential{Name: "nms", Kind: "v3", Auth: "sha256", AuthPass: "auth-pass-1", Priv: "aes", PrivPass: "priv-pass-1"}
	if err := d.AddSNMPCredential(ops, nms, false); err == nil {
		t.Error("an admin added an SNMP credential")
	}
	if err := d.AddSNMPCredential(root, nms, false); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(creds); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("credentials file: %v %v", fi, err)
	}
	if _, err := d.Commit("steve", "snmp", 0); err != nil {
		t.Fatal(err)
	}
	conf := fake.last()
	for _, want := range []string{`createUser nms SHA-256 "auth-pass-1" AES "priv-pass-1"`, "sysLocation Lab rack 1", "trapsess -Ci", "192.168.1.62:162", "createUser sjb-internal SHA-256"} {
		if !strings.Contains(conf, want) {
			t.Errorf("snmpd.conf lacks %q:\n%s", want, conf)
		}
	}
	// The status never shows secrets.
	st := d.SNMP()
	if !st.Enabled || !st.Running || len(st.Credentials) != 1 || st.Credentials[0] != (snmp.Info{Name: "nms", Kind: "v3", Auth: "SHA-256", Priv: "AES"}) {
		t.Errorf("status: %+v", st)
	}
	n := len(fake.applied)
	d.ReconcileRoutes()
	if len(fake.applied) != n {
		t.Error("an unchanged config was applied again")
	}

	// In use: can't delete, can't change kind; changing secrets applies.
	if err := d.DeleteSNMPCredential(root, "nms"); err == nil || !strings.Contains(err.Error(), "uses SNMP credential") {
		t.Errorf("deleted a credential in use: %v", err)
	}
	if err := d.AddSNMPCredential(root, snmp.Credential{Name: "nms", Kind: "v2c", Community: "community-x"}, true); err == nil {
		t.Error("changed a used v3 credential into v2c")
	}
	nms.AuthPass = "auth-pass-2"
	if err := d.AddSNMPCredential(root, nms, false); err == nil {
		t.Error("added a duplicate")
	}
	if err := d.AddSNMPCredential(root, nms, true); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(fake.last(), `"auth-pass-2"`) {
		t.Errorf("rotated secret not applied:\n%s", fake.last())
	}

	// The snapshot is saved while SNMP is on.
	snap := filepath.Join(t.TempDir(), "run", "metrics.json")
	if err := d.SaveMetricsSnapshot(snap); err != nil {
		t.Fatal(err)
	}
	if s, err := metrics.Load(snap); err != nil || s.Config.RunningRevision != 1 {
		t.Errorf("snapshot: %+v %v", s.Config, err)
	}

	// Off: snmpd stopped, the snapshot removed, the credential free.
	d.SetCandidate(lab(t))
	if _, err := d.Commit("steve", "snmp off", 0); err != nil {
		t.Fatal(err)
	}
	if fake.last() != "" || fake.Running() {
		t.Errorf("snmpd not stopped: %q", fake.last())
	}
	if err := d.SaveMetricsSnapshot(snap); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(snap); !os.IsNotExist(err) {
		t.Error("snapshot left behind with SNMP off")
	}
	if err := d.DeleteSNMPCredential(root, "nms"); err != nil {
		t.Error(err)
	}
	// The package starts snmpd with its own config on install: the next
	// pass stops it.
	fake.mu.Lock()
	fake.running = true
	fake.mu.Unlock()
	d.ReconcileRoutes()
	if fake.Running() {
		t.Error("an snmpd started outside ngfwd kept running with SNMP off")
	}
}

func TestSNMPCredentialsInBackups(t *testing.T) {
	d, _ := setup(t)
	withAccounts(t, d)
	creds := filepath.Join(t.TempDir(), "snmp-credentials")
	d.SetSNMP(&fakeSNMPD{}, creds)
	d.SetCandidate(lab(t))
	d.Commit("steve", "lab", 0)
	if err := d.AddSNMPCredential(accounts.Root, snmp.Credential{Name: "ro", Kind: "v2c", Community: "lab-community"}, false); err != nil {
		t.Fatal(err)
	}
	b, err := d.ExportBackup(accounts.Root, true, "a-good-passphrase")
	if err != nil {
		t.Fatal(err)
	}
	data := b.Data
	if strings.Contains(data, "lab-community") {
		t.Fatal("community in the clear in an encrypted backup")
	}
	os.Remove(creds)
	res, err := d.RestoreBackup(accounts.Root, RestoreRequest{Data: data, Passphrase: "a-good-passphrase", Accounts: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.SNMPCredentials == nil || *res.SNMPCredentials != 1 {
		t.Errorf("restored: %+v", res)
	}
	cs, err := snmp.Load(creds)
	if c, ok := cs.Get("ro"); err != nil || !ok || c.Community != "lab-community" {
		t.Errorf("after restore: %+v %v", cs, err)
	}
}
