package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/stevejboyle/sjb-os/internal/accounts"
	"github.com/stevejboyle/sjb-os/internal/backup"
)

// requestBackup runs request backup export|restore ....
func requestBackup(args []string, in io.Reader) error {
	usage := fmt.Errorf("request backup export [accounts] | request backup restore [config] [accounts]")
	if len(args) == 0 {
		return usage
	}
	opts := map[string]bool{}
	for _, a := range args[1:] {
		if a != "config" && a != "accounts" {
			return usage
		}
		opts[a] = true
	}
	br := buffered(in)
	switch args[0] {
	case "export":
		if opts["config"] {
			return usage
		}
		return backupExport(br, opts["accounts"])
	case "restore":
		if len(opts) == 0 {
			opts["config"] = true
		}
		return backupRestore(br, opts["config"], opts["accounts"])
	}
	return usage
}

func backupExport(br *bufio.Reader, withAccounts bool) error {
	var pass string
	if withAccounts {
		fmt.Fprintln(os.Stderr, "Backups with users, roles and API keys are encrypted. Keep the passphrase safe: without it the backup can't be restored.")
		a, err := askSecret(br, fmt.Sprintf("Passphrase (%d+ characters): ", backup.MinPassphrase))
		if err != nil {
			return err
		}
		b, err := askSecret(br, "Again: ")
		if err != nil {
			return err
		}
		if a != b {
			return fmt.Errorf("the passphrases don't match")
		}
		pass = a
	}
	body, _ := json.Marshal(map[string]any{"accounts": withAccounts, "passphrase": pass})
	out, err := call("POST", "/v1/backup/export", body)
	if err != nil {
		return err
	}
	var b struct {
		FileName string   `json:"file_name"`
		Data     string   `json:"data"`
		Warnings []string `json:"warnings"`
	}
	if err := json.Unmarshal(out, &b); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Copy everything from the first line to the END line into a file (e.g. %s).\n", b.FileName)
	fmt.Fprintln(os.Stderr, "request backup restore takes it back by paste; the web UI's Backup page takes the file.")
	fmt.Print(b.Data)
	for _, w := range b.Warnings {
		fmt.Fprintln(os.Stderr, "warning:", w)
	}
	return nil
}

func backupRestore(br *bufio.Reader, cfg, accts bool) error {
	fmt.Println("Paste the backup (the lines from " + backup.Begin + " to " + backup.End + "):")
	data, err := readPEMBlock(br, false)
	if err != nil {
		return err
	}
	ib, _ := json.Marshal(map[string]string{"data": data})
	out, err := call("POST", "/v1/backup/inspect", ib)
	if err != nil {
		return err
	}
	var h backup.Header
	if err := json.Unmarshal(out, &h); err != nil {
		return err
	}
	how := "not encrypted"
	if h.Encrypted() {
		how = "encrypted"
	}
	fmt.Printf("Backup of %s, revision %d, made %s by %s with SJB-OS %s: %s, %s.\n", orDash(h.Hostname), h.Revision,
		h.Created.Local().Format("2006-01-02 15:04"), h.By, orDash(h.SJBOS), strings.Join(h.Contents, " and "), how)
	var pass string
	if h.Encrypted() {
		if pass, err = askSecret(br, "Passphrase: "); err != nil {
			return err
		}
	}
	body, _ := json.Marshal(map[string]any{"data": data, "passphrase": pass, "config": cfg, "accounts": accts})
	out, err = call("POST", "/v1/backup/restore", body)
	if err != nil {
		return err
	}
	var res struct {
		Config   bool                    `json:"config"`
		Diff     string                  `json:"diff"`
		Accounts *accounts.RestoreResult `json:"accounts"`
		APIKeys  *int                    `json:"api_keys"`
		Warnings []string                `json:"warnings"`
	}
	if err := json.Unmarshal(out, &res); err != nil {
		return err
	}
	if a := res.Accounts; a != nil {
		fmt.Printf("Users: added %s; updated %s; kept as they were (not in the backup) %s; not changed %s.\n",
			names(a.Added), names(a.Updated), names(a.Kept), names(a.Skipped))
		fmt.Printf("Custom roles added or replaced: %s.\n", names(a.Roles))
	}
	if res.APIKeys != nil {
		fmt.Printf("Tag API keys restored: %d (in use now).\n", *res.APIKeys)
	}
	for _, w := range res.Warnings {
		fmt.Println("warning:", w)
	}
	if res.Config {
		if strings.TrimSpace(res.Diff) == "" {
			fmt.Println("The backup's config is the same as the running config: nothing to commit.")
		} else {
			fmt.Println("The backup's config is now the candidate. Changes from the running config:")
			fmt.Print(res.Diff)
			if !strings.HasSuffix(res.Diff, "\n") {
				fmt.Println()
			}
			fmt.Println("Nothing is applied yet. Commit it with a confirm timer, so it rolls back if you lose access:")
			fmt.Println("  commit -m \"restore backup\" -confirm 10m    (then: confirm)")
			fmt.Println("or discard it with revert.")
		}
	}
	return nil
}

func names(s []string) string {
	if len(s) == 0 {
		return "none"
	}
	return strings.Join(s, ", ")
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
