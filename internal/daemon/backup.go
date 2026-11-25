package daemon

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/stevejboyle/sjb-os/internal/accounts"
	"github.com/stevejboyle/sjb-os/internal/backup"
	"github.com/stevejboyle/sjb-os/internal/config"
	"github.com/stevejboyle/sjb-os/internal/snmp"
)

// SetVersion records the SJB-OS version (for backup headers and logs).
func (d *Daemon) SetVersion(v string) { d.version = v }

// Backup is an exported backup file.
type Backup struct {
	FileName string        `json:"file_name"`
	Data     string        `json:"data"` // the armoured file
	Header   backup.Header `json:"header"`
	Warnings []string      `json:"warnings,omitempty"`
}

// ExportBackup backs up the running config and, for superusers who ask,
// the users, roles and tag API keys (which need a passphrase). Viewing
// every config area is required: a backup is the whole config.
func (d *Daemon) ExportBackup(c accounts.Caller, withAccounts bool, passphrase string) (*Backup, error) {
	need := accounts.ConfigView
	if withAccounts {
		need = accounts.SuperuserOnly
	}
	p, err := d.Authorize(c, need)
	if err != nil {
		return nil, err
	}
	for _, a := range accounts.ConfigAreas {
		if !p.Can(a, accounts.View) {
			return nil, fmt.Errorf("%w: a backup holds the whole config, and role %s can't view %s", accounts.ErrForbidden, p.Role.Name, a)
		}
	}
	rev, run, err := d.store.Running()
	if err != nil {
		return nil, err
	}
	if rev == 0 || len(bytes.TrimSpace(run)) == 0 {
		return nil, fmt.Errorf("%w: nothing has been committed yet, so there is no config to back up", ErrInvalid)
	}
	h := backup.Header{SJBOS: d.version, Created: d.Now().UTC(), By: c.Author(), Revision: rev}
	if cfg, err := config.Parse(run); err == nil {
		h.Hostname = cfg.System.Hostname
	}
	pl := backup.Payload{Config: string(run)}
	var warns []string
	if withAccounts {
		if d.accounts == nil {
			return nil, fmt.Errorf("%w: there are no user accounts here to back up", ErrInvalid)
		}
		snap, w, err := d.accounts.Snapshot()
		if err != nil {
			return nil, err
		}
		warns = append(warns, w...)
		pl.Accounts = &snap
		if d.apiKeysFile != "" {
			if keys, err := os.ReadFile(d.apiKeysFile); err == nil {
				s := string(keys)
				pl.APIKeys = &s
			} else if !os.IsNotExist(err) {
				return nil, err
			}
		}
		if d.snmp.credsPath != "" {
			if b, err := os.ReadFile(d.snmp.credsPath); err == nil {
				s := string(b)
				pl.SNMPCredentials = &s
			} else if !os.IsNotExist(err) {
				return nil, err
			}
		}
	}
	data, err := backup.Seal(h, pl, passphrase)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	h, _ = backup.Inspect(data)
	d.log.Info("backup exported", "contents", strings.Join(h.Contents, ","), "encrypted", h.Encrypted(), "revision", rev, "by", c.Author())
	return &Backup{FileName: backup.FileName(h), Data: string(data), Header: h, Warnings: warns}, nil
}

// InspectBackup reads a backup's header (no passphrase needed).
func (d *Daemon) InspectBackup(c accounts.Caller, data []byte) (backup.Header, error) {
	if _, err := d.Authorize(c, accounts.ConfigView); err != nil {
		return backup.Header{}, err
	}
	h, err := backup.Inspect(data)
	if err != nil {
		return backup.Header{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	return h, nil
}

// RestoreRequest says what to restore from a backup.
type RestoreRequest struct {
	Data       string `json:"data"`
	Passphrase string `json:"passphrase"`
	Config     bool   `json:"config"`   // into the candidate, to commit as usual
	Accounts   bool   `json:"accounts"` // users, roles and API keys (superusers)
}

// RestoreResult reports a restore.
type RestoreResult struct {
	Header backup.Header `json:"header"`
	// Config: the backup's config is now the candidate; Diff is running
	// vs. the new candidate. Nothing is applied until a commit.
	Config   bool                    `json:"config"`
	Diff     string                  `json:"diff,omitempty"`
	Accounts *accounts.RestoreResult `json:"accounts,omitempty"`
	APIKeys  *int                    `json:"api_keys,omitempty"` // keys restored
	// SNMPCredentials is how many SNMP credentials were restored.
	SNMPCredentials *int     `json:"snmp_credentials,omitempty"`
	Warnings        []string `json:"warnings,omitempty"`
}

// RestoreBackup restores a backup. The config only ever goes into the
// candidate, with the same checks as any edit (the caller must be able to
// change every area it touches); a commit, ideally confirmed, applies it.
// Users, roles and API keys are for superusers and take effect at once,
// as account changes always do (they aren't config revisions).
func (d *Daemon) RestoreBackup(c accounts.Caller, req RestoreRequest) (*RestoreResult, error) {
	if !req.Config && !req.Accounts {
		return nil, fmt.Errorf("%w: choose what to restore: the config, the accounts, or both", ErrInvalid)
	}
	need := accounts.ConfigEdit
	if req.Accounts {
		need = accounts.SuperuserOnly
	}
	if _, err := d.Authorize(c, need); err != nil {
		return nil, err
	}
	h, pl, err := backup.Open([]byte(req.Data), req.Passphrase)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if req.Accounts && !h.Has(backup.ContentAccounts) {
		return nil, fmt.Errorf("%w: this backup has no users, roles or API keys (it was made without them)", ErrInvalid)
	}
	res := &RestoreResult{Header: h}
	var keys []APIKey
	if req.Accounts && pl.APIKeys != nil {
		if d.apiKeysFile == "" {
			return nil, fmt.Errorf("%w: no tag API key file here to restore into", ErrInvalid)
		}
		if keys, err = ParseKeys(strings.NewReader(*pl.APIKeys), "backup api-keys"); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
		}
	}
	var snmpCreds *snmp.Credentials
	if req.Accounts && pl.SNMPCredentials != nil {
		if d.snmp.credsPath == "" {
			res.Warnings = append(res.Warnings, "the backup's SNMP credentials weren't restored: the SNMP agent isn't available here")
		} else if snmpCreds, err = snmp.Parse([]byte(*pl.SNMPCredentials)); err != nil {
			return nil, fmt.Errorf("%w: the backup's SNMP credentials: %v", ErrInvalid, err)
		}
	}
	if req.Config {
		// Check it before anything changes, so a bad config doesn't leave
		// the accounts half restored.
		if _, err := parse([]byte(pl.Config)); err != nil {
			return nil, fmt.Errorf("%w: the backup's config doesn't load here: %v", ErrInvalid, err)
		}
	}
	if req.Config {
		if err := d.SetCandidateAs(c, []byte(pl.Config)); err != nil {
			return nil, err
		}
		res.Config = true
		if res.Diff, err = d.Diff(); err != nil {
			res.Warnings = append(res.Warnings, "could not diff: "+err.Error())
		}
		d.log.Info("backup restored into the candidate", "backup_revision", h.Revision, "backup_by", h.By, "by", c.Author())
	}
	if req.Accounts {
		if pl.Accounts != nil {
			if d.accounts == nil {
				return nil, fmt.Errorf("%w: no user accounts here to restore into", ErrInvalid)
			}
			ar, err := d.accounts.Restore(c, *pl.Accounts)
			if err != nil {
				return nil, err
			}
			res.Accounts = &ar
			res.Warnings = append(res.Warnings, ar.Warnings...)
		}
		if pl.APIKeys != nil {
			if err := writeFileAtomic(d.apiKeysFile, []byte(*pl.APIKeys), 0o600); err != nil {
				return nil, err
			}
			d.setAPIKeys(keys)
			n := len(keys)
			res.APIKeys = &n
			d.log.Info("tag API keys restored from a backup", "keys", n, "by", c.Author())
		}
		if snmpCreds != nil {
			d.snmp.credsMu.Lock()
			err := snmp.Save(d.snmp.credsPath, snmpCreds)
			d.snmp.credsMu.Unlock()
			if err != nil {
				return nil, err
			}
			n := len(snmpCreds.List)
			res.SNMPCredentials = &n
			d.log.Info("snmp credentials restored from a backup", "credentials", n, "by", c.Author())
			d.mu.Lock()
			if w := d.syncSNMPLocked(); len(w) > 0 {
				res.Warnings = append(res.Warnings, w...)
			}
			d.mu.Unlock()
		}
	}
	return res, nil
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
