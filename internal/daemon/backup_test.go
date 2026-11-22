package daemon

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stevejboyle/hobby-ngfw/internal/accounts"
	"github.com/stevejboyle/hobby-ngfw/internal/backup"
)

var (
	cliAdmin  = accounts.Caller{Name: accounts.Admin, Via: "cli"}
	cliOps    = accounts.Caller{Name: "ops", Via: "cli"}
	cliReader = accounts.Caller{Name: "reader", Via: "cli"}
)

func commitCfg(t *testing.T, d *Daemon, cfg []byte) {
	t.Helper()
	if err := d.SetCandidate(cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Commit("test", "base", 0); err != nil {
		t.Fatal(err)
	}
}

func TestBackupConfigRoundTrip(t *testing.T) {
	d, _ := setup(t)
	withAccounts(t, d)
	d.SetVersion("0.9.11-r01")
	if _, err := d.ExportBackup(cliOps, false, ""); err == nil || !strings.Contains(err.Error(), "nothing has been committed") {
		t.Fatalf("export with nothing committed: %v", err)
	}
	commitCfg(t, d, lab(t))
	b, err := d.ExportBackup(cliReader, false, "")
	if err != nil {
		t.Fatal(err)
	}
	if b.Header.Revision != 1 || b.Header.By != "cli:reader" || b.Header.SJBOS != "0.9.11-r01" || !strings.HasSuffix(b.FileName, ".backup") {
		t.Fatalf("header %+v %s", b.Header, b.FileName)
	}
	// Change the running config, then restore the backup: it lands in the
	// candidate only.
	commitCfg(t, d, withoutWeb(t))
	runBefore, _, _ := d.Running()
	if _, err := d.RestoreBackup(cliReader, RestoreRequest{Data: b.Data, Config: true}); !errors.Is(err, accounts.ErrForbidden) {
		t.Fatalf("read-only restore: %v", err)
	}
	res, err := d.RestoreBackup(cliOps, RestoreRequest{Data: b.Data, Config: true})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Config || !strings.Contains(res.Diff, "allow-web") {
		t.Fatalf("restore %+v", res)
	}
	if n, _, _ := d.Running(); n != runBefore {
		t.Fatal("restore changed the running config")
	}
	cand, _ := d.store.Candidate()
	if string(cand) != string(lab(t)) {
		t.Fatal("candidate isn't the backup's config")
	}
	// Accounts need a superuser, and a backup that has them.
	if _, err := d.RestoreBackup(cliOps, RestoreRequest{Data: b.Data, Accounts: true}); !errors.Is(err, accounts.ErrForbidden) {
		t.Fatalf("admin restoring accounts: %v", err)
	}
	if _, err := d.RestoreBackup(cliAdmin, RestoreRequest{Data: b.Data, Accounts: true}); err == nil || !strings.Contains(err.Error(), "has no users") {
		t.Fatalf("accounts from a config-only backup: %v", err)
	}
	if _, err := d.RestoreBackup(cliOps, RestoreRequest{Data: b.Data}); err == nil {
		t.Fatal("restore of nothing")
	}
}

func TestBackupRestoreChecksAreas(t *testing.T) {
	d, _ := setup(t)
	a := withAccounts(t, d)
	if err := a.PutRole(accounts.Root, accounts.Role{Name: "netops", Perms: map[accounts.Area]accounts.Level{
		accounts.Network: accounts.Change, accounts.Policy: accounts.View, accounts.DHCP: accounts.View,
		accounts.IPS: accounts.View, accounts.Decryption: accounts.View, accounts.Logging: accounts.View}}); err != nil {
		t.Fatal(err)
	}
	if err := a.AddUser(accounts.Root, "net", "netops", "a-long-password"); err != nil {
		t.Fatal(err)
	}
	commitCfg(t, d, lab(t))
	b, err := d.ExportBackup(cliOps, false, "")
	if err != nil {
		t.Fatal(err)
	}
	commitCfg(t, d, withoutWeb(t))
	// The backup changes policy, which netops can't change.
	_, err = d.RestoreBackup(accounts.Caller{Name: "net", Via: "cli"}, RestoreRequest{Data: b.Data, Config: true})
	if !errors.Is(err, accounts.ErrForbidden) || !strings.Contains(err.Error(), "policy") {
		t.Fatalf("got %v", err)
	}
}

func TestBackupWithAccounts(t *testing.T) {
	d, _ := setup(t)
	a := withAccounts(t, d)
	keyFile := filepath.Join(t.TempDir(), "api-keys")
	os.WriteFile(keyFile, []byte("tagger tags:read,tags:write 0123456789abcdef01234567\n"), 0o600)
	d.SetAPIKeysFile(keyFile)
	d.APIHandler(nil)
	commitCfg(t, d, lab(t))
	if _, err := d.ExportBackup(cliOps, true, "a long passphrase"); !errors.Is(err, accounts.ErrForbidden) {
		t.Fatalf("admin exporting accounts: %v", err)
	}
	if _, err := d.ExportBackup(cliAdmin, true, ""); err == nil || !strings.Contains(err.Error(), "passphrase") {
		t.Fatalf("no passphrase: %v", err)
	}
	b, err := d.ExportBackup(cliAdmin, true, "a long passphrase")
	if err != nil {
		t.Fatal(err)
	}
	if !b.Header.Encrypted() || !b.Header.Has(backup.ContentAccounts) {
		t.Fatalf("header %+v", b.Header)
	}
	if h, err := d.InspectBackup(cliReader, []byte(b.Data)); err != nil || h.By != "cli:admin" {
		t.Fatalf("inspect %+v %v", h, err)
	}
	// Lose a user and the keys, then restore the accounts.
	if err := a.DeleteUser(accounts.Root, "reader"); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(keyFile, nil, 0o600)
	d.setAPIKeys(nil)
	if _, err := d.RestoreBackup(cliAdmin, RestoreRequest{Data: b.Data, Accounts: true, Passphrase: "wrong passphrase!"}); err == nil {
		t.Fatal("wrong passphrase accepted")
	}
	res, err := d.RestoreBackup(cliAdmin, RestoreRequest{Data: b.Data, Accounts: true, Passphrase: "a long passphrase"})
	if err != nil {
		t.Fatal(err)
	}
	out, _ := json.Marshal(res)
	if res.Accounts == nil || len(res.Accounts.Added) != 1 || res.Accounts.Added[0] != "reader" || res.APIKeys == nil || *res.APIKeys != 1 || res.Config {
		t.Fatalf("result %s", out)
	}
	if _, err := a.Authenticate("reader", "a-long-password", "test"); err != nil {
		t.Fatalf("restored user can't log in: %v", err)
	}
	if len(d.currentAPIKeys()) != 1 {
		t.Fatal("tag API keys not reloaded")
	}
	if fi, _ := os.Stat(keyFile); fi.Mode().Perm() != 0o600 {
		t.Errorf("key file mode %v", fi.Mode())
	}
}
