package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/stevejboyle/hobby-ngfw/internal/webui"
)

func webPasswd(args []string) error {
	fl := flag.NewFlagSet("web-passwd", flag.ExitOnError)
	user := fl.String("user", "admin", "user")
	file := fl.String("file", "/etc/ngfw/web-users", "web user file")
	webOnly := fl.Bool("web-only", false, "development: set only the web UI password, not the account's SSH/console password")
	fl.Parse(args)

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
	users := &webui.Users{Path: *file, System: webui.SetUnixPassword}
	what := "SSH, console and web UI"
	if *webOnly {
		users.System, what = nil, "web UI"
	}
	if err := users.Set(*user, pw); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "%s password for %s set\n", what, *user)
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
