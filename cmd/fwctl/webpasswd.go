package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/stevejboyle/hobby-ngfw/internal/accounts"
)

// webPasswd is root's recovery command: it sets a user's one password
// (SSH, console, web UI) and clears any lockout, straight in the user
// database, so it works even when ngfwd doesn't. First boot uses it to set
// admin's password.
func webPasswd(args []string) error {
	fl := flag.NewFlagSet("web-passwd", flag.ExitOnError)
	name := fl.String("user", accounts.Admin, "user")
	file := fl.String("file", "/etc/ngfw/web-users", "the old web user file (imported once; then kept with admin's password for rollbacks)")
	db := fl.String("users", "", "user database (default: users.json next to -file)")
	webOnly := fl.Bool("web-only", false, "development: set only the web UI password, not the account's SSH/console password")
	fl.Parse(args)
	if *db == "" {
		*db = filepath.Join(filepath.Dir(*file), "users.json")
	}

	var pw string
	if isTerminal() {
		a, err := prompt("New password (SSH, console and web UI): ")
		if err != nil {
			return err
		}
		b, err := prompt("Again: ")
		if err != nil {
			return err
		}
		if a != b {
			return fmt.Errorf("passwords do not match")
		}
		pw = a
	} else {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			return fmt.Errorf("reading password from stdin: %w", err)
		}
		pw = strings.TrimRight(line, "\r\n")
	}
	st := &accounts.Store{Path: *db, RolesPath: filepath.Join(filepath.Dir(*db), "roles.json"), Legacy: *file}
	what := "SSH, console and web UI"
	if *webOnly {
		what = "web UI"
	} else {
		st.Sys = accounts.DefaultExec()
		if u, err := user.Lookup(accounts.Admin); err == nil && u.HomeDir != "" {
			st.AdminKeys = filepath.Join(u.HomeDir, ".ssh", "authorized_keys")
		}
	}
	if err := st.Open(); err != nil {
		return err
	}
	if err := st.SetPassword(accounts.Root, *name, pw); err != nil {
		return err
	}
	if err := st.Unlock(accounts.Root, *name); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "%s password for %s set (and any lockout cleared)\n", what, *name)
	return nil
}

func isTerminal() bool {
	fi, err := os.Stdin.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// prompt reads a line with echo off (stty, so no extra dependency).
func prompt(label string) (string, error) {
	fmt.Fprint(os.Stderr, label)
	setEcho(false)
	defer func() { setEcho(true); fmt.Fprintln(os.Stderr) }()
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.TrimRight(line, "\r\n"), err
}

// setEcho turns terminal echo on or off with stty (no extra dependency).
func setEcho(on bool) {
	arg := "-echo"
	if on {
		arg = "echo"
	}
	c := exec.Command("stty", arg)
	c.Stdin = os.Stdin
	c.Run()
}
