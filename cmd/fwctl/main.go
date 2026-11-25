// Command fwctl is the firewall CLI. It talks to ngfwd over its Unix
// socket, except validate and compile, which work offline on files.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/user"
	"strconv"
	"strings"
	"time"

	"github.com/stevejboyle/sjb-os/internal/compiler"
	"github.com/stevejboyle/sjb-os/internal/config"
	"github.com/stevejboyle/sjb-os/internal/metrics"
	"github.com/stevejboyle/sjb-os/internal/snmp"
)

const usage = `usage: fwctl [-socket PATH] <command> [args]

offline:
  validate FILE...            check config files against the schema
  compile FILE                print the nftables ruleset for a config file

against ngfwd:
  status                      running revision, pending confirmation
  load FILE                   replace the candidate config
  show [candidate|running]    print a config (default: candidate)
  diff                        running vs candidate
  preview                     ruleset the candidate would compile to
  commit [-m MSG] [-confirm DURATION]
                              apply the candidate; with -confirm, roll back
                              automatically unless confirmed in time
  confirm                     accept a pending commit
  rollback N                  re-commit revision N
  revisions                   list commits
  tags [TAG]                  list tag registrations
  tags register IP TAG... [-ttl DURATION]
  tags unregister IP TAG...

appliance (run with sudo):
  upgrade [status [-json]]    installed version and upgrade history
  upgrade verify FILE         check a bundle's signature and contents
  upgrade apply [-reinstall] FILE
                              install a signed bundle; restores the previous
                              version if ngfwd does not come back healthy
  upgrade rollback            return to the version before the last upgrade
  web-passwd [-user NAME] [-file PATH]
                              set a user's password for SSH, the console and
                              the web UI (prompts, or reads one line from
                              stdin when not a terminal)

  shell [-c COMMAND]          the captive CLI (user admin's login shell)

  sjb                         a word from the border guard
`

var socket string

func main() {
	fs := flag.NewFlagSet("fwctl", flag.ExitOnError)
	fs.StringVar(&socket, "socket", envOr("NGFW_SOCKET", "/run/ngfw/ngfwd.sock"), "ngfwd management socket")
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	fs.Parse(os.Args[1:])
	args := fs.Args()
	if len(args) == 0 {
		fs.Usage()
		os.Exit(2)
	}
	if err := dispatch(args[0], args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "fwctl:", err)
		os.Exit(1)
	}
}

func dispatch(cmd string, args []string) error {
	switch cmd {
	case "validate":
		return validate(args)
	case "compile":
		return compileFile(args)
	case "status":
		return printJSON(call("GET", "/v1/status", nil))
	case "load":
		if len(args) != 1 {
			return fmt.Errorf("usage: load FILE")
		}
		data, err := os.ReadFile(args[0])
		if err != nil {
			return err
		}
		_, err = call("PUT", "/v1/config/candidate", data)
		if err == nil {
			fmt.Println("candidate updated; review with `fwctl diff`, apply with `fwctl commit`")
		}
		return err
	case "show":
		which := "candidate"
		if len(args) > 0 {
			which = args[0]
		}
		if which != "candidate" && which != "running" {
			return fmt.Errorf("show candidate|running")
		}
		return printRaw(call("GET", "/v1/config/"+which, nil))
	case "diff":
		out, err := call("GET", "/v1/config/diff", nil)
		if err == nil && len(out) == 0 {
			out = []byte("no changes\n")
		}
		return printRaw(out, err)
	case "preview":
		out, err := call("GET", "/v1/config/compiled", nil)
		if err != nil {
			return err
		}
		return printCompiled(out)
	case "commit":
		return commit(args)
	case "confirm":
		return printJSON(call("POST", "/v1/confirm", nil))
	case "rollback":
		if len(args) != 1 {
			return fmt.Errorf("usage: rollback N")
		}
		n, err := strconv.Atoi(args[0])
		if err != nil {
			return fmt.Errorf("revision must be a number")
		}
		return printJSON(call("POST", "/v1/rollback", mustJSON(map[string]any{"revision": n, "author": whoami()})))
	case "revisions":
		return printJSON(call("GET", "/v1/revisions", nil))
	case "tags":
		return tagsCmd(args)
	case "upgrade":
		return upgradeCmd(args)
	case "shell":
		return shellCmd(args)
	case "web-passwd":
		return webPasswd(args)
	case "sjb":
		return sjbCmd()
	case "snmp-pass":
		// snmpd's pass_persist helper for SJB-OS-MIB (run by snmpd, not people).
		return snmp.Pass(os.Stdin, os.Stdout, metrics.SnapshotPath, time.Now)
	case "help", "-h", "--help":
		fmt.Print(usage)
		return nil
	}
	return fmt.Errorf("unknown command %q (try fwctl help)", cmd)
}

func validate(files []string) error {
	if len(files) == 0 {
		return fmt.Errorf("validate: no files given")
	}
	bad := 0
	for _, f := range files {
		c, err := config.Load(f)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: INVALID\n%v\n", f, err)
			bad++
			continue
		}
		fmt.Printf("%s: OK (%d zones, %d rules)\n", f, len(c.Zones), len(c.Rules))
	}
	if bad > 0 {
		return fmt.Errorf("%d invalid file(s)", bad)
	}
	return nil
}

func compileFile(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: compile FILE")
	}
	c, err := config.Load(args[0])
	if err != nil {
		return err
	}
	res, err := compiler.Compile(c, nil)
	if err != nil {
		return err
	}
	fmt.Print(res.Ruleset)
	for _, w := range res.Warnings {
		fmt.Fprintln(os.Stderr, "warning:", w)
	}
	return nil
}

func commit(args []string) error {
	fs := flag.NewFlagSet("commit", flag.ContinueOnError)
	msg := fs.String("m", "", "commit message")
	confirm := fs.Duration("confirm", 0, "roll back unless confirmed within this time, e.g. 5m")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected %q (quote the message: -m \"...\")", fs.Arg(0))
	}
	body := mustJSON(map[string]any{
		"author": whoami(), "message": *msg, "confirm_seconds": int(confirm.Seconds()),
	})
	out, err := call("POST", "/v1/commit", body)
	if err != nil {
		return err
	}
	var res struct {
		Revision  struct{ N int } `json:"revision"`
		Warnings  []string        `json:"warnings"`
		ConfirmBy *time.Time      `json:"confirm_by"`
	}
	if err := json.Unmarshal(out, &res); err != nil {
		return err
	}
	fmt.Printf("committed revision %d\n", res.Revision.N)
	fmt.Println("New rules, same vigilance.")
	for _, w := range res.Warnings {
		fmt.Println("warning:", w)
	}
	if res.ConfirmBy != nil {
		fmt.Printf("run `fwctl confirm` before %s or it rolls back\n", res.ConfirmBy.Local().Format(time.Kitchen))
	}
	return nil
}

func tagsCmd(args []string) error {
	if len(args) == 0 || (args[0] != "register" && args[0] != "unregister") {
		path := "/v1/tags"
		if len(args) == 1 {
			path += "/" + args[0]
		}
		return printJSON(call("GET", path, nil))
	}
	fs := flag.NewFlagSet("tags", flag.ContinueOnError)
	ttl := fs.Duration("ttl", 0, "expiry, e.g. 1h (register only; 0 = never)")
	// Allow -ttl anywhere: pull flags out of the positional list.
	var pos []string
	rest := args[1:]
	for len(rest) > 0 {
		if err := fs.Parse(rest); err != nil {
			return err
		}
		rest = fs.Args()
		if len(rest) > 0 {
			pos = append(pos, rest[0])
			rest = rest[1:]
		}
	}
	if len(pos) < 2 {
		return fmt.Errorf("usage: tags %s IP TAG...", args[0])
	}
	body := map[string]any{"ip": pos[0], "tags": pos[1:]}
	if args[0] == "register" {
		body["ttl"] = int(ttl.Seconds())
	}
	return printJSON(call("POST", "/v1/tags/"+args[0], mustJSON(body)))
}

func call(method, path string, body []byte) ([]byte, error) {
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socket)
			},
		},
	}
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, "http://ngfwd"+path, r)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cannot reach ngfwd at %s: %w", socket, err)
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		var e struct{ Error string }
		if json.Unmarshal(out, &e) == nil && e.Error != "" {
			return nil, fmt.Errorf("%s", e.Error)
		}
		return nil, fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(out)))
	}
	return out, nil
}

func printRaw(out []byte, err error) error {
	if err != nil {
		return err
	}
	os.Stdout.Write(out)
	return nil
}

func printJSON(out []byte, err error) error {
	if err != nil {
		return err
	}
	var v any
	if json.Unmarshal(out, &v) != nil {
		return printRaw(out, nil)
	}
	b, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(b))
	return nil
}

func printCompiled(out []byte) error {
	var res struct {
		Ruleset  string   `json:"ruleset"`
		Warnings []string `json:"warnings"`
	}
	if err := json.Unmarshal(out, &res); err != nil {
		return err
	}
	fmt.Print(res.Ruleset)
	for _, w := range res.Warnings {
		fmt.Fprintln(os.Stderr, "warning:", w)
	}
	return nil
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

func whoami() string {
	if s := os.Getenv("SUDO_USER"); s != "" {
		return s
	}
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return "unknown"
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
