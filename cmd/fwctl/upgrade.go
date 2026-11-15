package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/stevejboyle/hobby-ngfw/internal/upgrade"
)

// upgradeRoot is "/" on the appliance; tests and dry runs can point it
// elsewhere with NGFW_ROOT.
func installer() *upgrade.Installer {
	root := envOr("NGFW_ROOT", "/")
	in := &upgrade.Installer{Root: root, Sys: &appliance{wantRev: -1}}
	migrate := filepath.Join(root, "usr/local/sbin/sjb-migrate")
	in.BeforeRollback = func() error {
		if _, err := os.Stat(migrate); err != nil {
			return nil // this version made no system changes to undo
		}
		// The version being rolled back to: the undo depends on what it knows.
		target := ""
		if st, err := in.Status(); err == nil {
			target = st.RollbackTo
		}
		out, err := exec.Command(migrate, "undo", target).CombinedOutput()
		if err != nil {
			return fmt.Errorf("%s undo: %v: %s", migrate, err, strings.TrimSpace(string(out)))
		}
		fmt.Print(string(out))
		return nil
	}
	return in
}

func upgradeCmd(args []string) error {
	if len(args) == 0 {
		args = []string{"status"}
	}
	in := installer()
	switch args[0] {
	case "status":
		st, err := in.Status()
		if err != nil {
			return err
		}
		if len(args) > 1 && args[1] == "-json" {
			b, _ := json.MarshalIndent(st, "", "  ")
			fmt.Println(string(b))
			return nil
		}
		fmt.Printf("installed: SJB-OS %s\n", st.Version)
		if st.RollbackTo != "" {
			fmt.Printf("rollback:  `fwctl upgrade rollback` returns to %s\n", st.RollbackTo)
		}
		if st.InProgress {
			fmt.Println("an upgrade is in progress")
		}
		for _, e := range st.History {
			line := fmt.Sprintf("%s  %-8s %s -> %s  %s", e.Time.Local().Format("2006-01-02 15:04"), e.Action, e.From, e.To, e.Result)
			if e.Error != "" {
				line += ": " + e.Error
			}
			fmt.Println(line)
		}
		return nil
	case "verify":
		if len(args) != 2 {
			return fmt.Errorf("usage: upgrade verify FILE")
		}
		b, err := readBundle(in, args[1])
		if err != nil {
			return err
		}
		cur, _ := in.CurrentVersion()
		fmt.Printf("OK: SJB-OS %s, signed by %q, %d files (installed: %s)\n", b.Manifest.Version, b.KeyName, len(b.Manifest.Files), cur)
		if err := upgrade.CheckVersion(b.Manifest, cur, false); err != nil {
			fmt.Println("note:", err)
		}
		return nil
	case "apply":
		fl := flag.NewFlagSet("upgrade apply", flag.ExitOnError)
		reinstall := fl.Bool("reinstall", false, "apply even if this version is already installed")
		fl.Parse(args[1:])
		if fl.NArg() != 1 {
			return fmt.Errorf("usage: upgrade apply [-reinstall] FILE")
		}
		b, err := readBundle(in, fl.Arg(0))
		if err != nil {
			return err
		}
		if err := noPendingCommit(); err != nil {
			return err
		}
		cur, _ := in.CurrentVersion()
		fmt.Printf("upgrading SJB-OS %s -> %s (signed by %q)\n", cur, b.Manifest.Version, b.KeyName)
		in.Sys.(*appliance).expectCurrentRevision()
		if err := in.Apply(b, *reinstall); err != nil {
			return err
		}
		fmt.Printf("SJB-OS %s is running. Fresh paint on the gatehouse, same guard.\n", b.Manifest.Version)
		return nil
	case "rollback":
		if err := noPendingCommit(); err != nil {
			return err
		}
		st, err := in.Status()
		if err != nil {
			return err
		}
		in.Sys.(*appliance).expectCurrentRevision()
		res, err := in.Rollback()
		if err != nil {
			return err
		}
		fmt.Printf("rolled back to SJB-OS %s\n", st.RollbackTo)
		if res.ConfigRestored {
			fmt.Printf("config: revision %d is the config that was running at the upgrade (revision %d); "+
				"changes made since then are in revisions %d-%d (`show revision N`)\n",
				res.Revision, res.UpgradeTime, res.UpgradeTime+1, res.From)
		}
		return nil
	}
	return fmt.Errorf("usage: upgrade status|verify FILE|apply FILE|rollback")
}

func readBundle(in *upgrade.Installer, path string) (*upgrade.Bundle, error) {
	keys, err := in.Keys()
	if err != nil {
		return nil, err
	}
	return upgrade.ReadFile(path, keys)
}

// appliance is the real System: systemd and ngfwd's management socket.
type appliance struct {
	wantRev int // running revision ngfwd must report after restart; -1 = any
}

func (a *appliance) expectCurrentRevision() {
	if rev, err := runningRevision(); err == nil {
		a.wantRev = rev
	}
}

// ExpectRevision is called when a rollback commits the upgrade-time config.
func (a *appliance) ExpectRevision(n int) { a.wantRev = n }

func (a *appliance) Reload(changed []string) error {
	if err := systemctl("daemon-reload"); err != nil {
		return err
	}
	for _, p := range changed {
		switch {
		case strings.HasPrefix(p, "etc/sysctl.d/"):
			if out, err := exec.Command("sysctl", "--system").CombinedOutput(); err != nil {
				return fmt.Errorf("sysctl --system: %v: %s", err, out)
			}
		case strings.HasPrefix(p, "etc/ssh/sshd_config.d/"):
			if err := systemctl("reload", "ssh"); err != nil {
				return err
			}
		}
	}
	return nil
}

func (a *appliance) RestartDaemon() error { return systemctl("restart", "ngfwd") }

func (a *appliance) Healthy() error {
	deadline := time.Now().Add(30 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		rev, err := runningRevision()
		switch {
		case err != nil:
			last = err
		case a.wantRev >= 0 && rev != a.wantRev:
			return fmt.Errorf("ngfwd is running revision %d, expected %d", rev, a.wantRev)
		default:
			// Stay up for a few seconds: catch a daemon that starts and dies.
			time.Sleep(3 * time.Second)
			if _, err := runningRevision(); err != nil {
				return fmt.Errorf("ngfwd stopped answering: %w", err)
			}
			return nil
		}
		time.Sleep(time.Second)
	}
	return fmt.Errorf("ngfwd did not answer within 30s: %v", last)
}

func runningRevision() (int, error) {
	out, err := call("GET", "/v1/status", nil)
	if err != nil {
		return 0, err
	}
	var s struct {
		Running int `json:"running_revision"`
	}
	return s.Running, json.Unmarshal(out, &s)
}

func systemctl(args ...string) error {
	out, err := exec.Command("systemctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// noPendingCommit refuses to restart ngfwd (upgrade or rollback) while a
// commit awaits confirmation: the restart must not race its auto-rollback.
func noPendingCommit() error {
	out, err := call("GET", "/v1/status", nil)
	if err != nil {
		return nil // ngfwd down: nothing pending to race
	}
	var st struct {
		ConfirmBy *time.Time `json:"confirm_by"`
	}
	if json.Unmarshal(out, &st) == nil && st.ConfirmBy != nil {
		return fmt.Errorf("a commit is waiting for confirmation; run `fwctl confirm` (or let it roll back) first")
	}
	return nil
}
