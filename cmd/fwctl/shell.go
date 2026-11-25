package main

// The captive CLI. SJB-OS users get this instead of a Unix shell, over SSH
// and on the console: a fixed set of firewall commands, no sudo, no file
// transfer, no way out to bash. Each command maps onto an fwctl command or a
// fixed, argument-checked system tool; nothing typed here reaches a shell.

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/stevejboyle/sjb-os/internal/cliconf"
	"github.com/stevejboyle/sjb-os/internal/config"
	"github.com/stevejboyle/sjb-os/internal/lineedit"
	"github.com/stevejboyle/sjb-os/internal/logs"
	"github.com/stevejboyle/sjb-os/internal/nicaddr"
)

const shellHelp = `SJB-OS commands:

  show status                 running revision, uncommitted changes, pending confirm
  show version                SJB-OS version and upgrade history
  show running | candidate    the config, as YAML
  show diff                   running vs candidate
  show ruleset                nftables ruleset the candidate compiles to
  show revisions              commit history
  show revision N             the config committed as revision N
  show tags [TAG]             tag registrations
  show interfaces             interface addresses
  show arp [INTERFACE]        ARP table (IPv4 neighbours), all interfaces or one
  show routes [vrf NAME]      static routes from the config, then the routing
                              tables (forwarding, each VRF, management)
  show nat                    NAT entries: port forwards, static NAT, source NAT,
                              with connections translated so far
  show vrf                    VRFs: table, interfaces, whether they're up
  show bgp                    BGP neighbors in every VRF: state, uptime, prefixes
  show ospf                   OSPF neighbors in every VRF
  show rib [vrf NAME]         the routing table as FRR sees it, with protocols
  show app                    applications seen so far: connections, bytes
  show app catalog [TEXT]     identifiable applications (name or category)
  show app categories         application categories, as rules name them
                              (category:video) and how many apps each holds
  show dhcp                   DHCP servers: range, gateway, DNS, active leases
  show dhcp leases [INTERFACE]
                              addresses handed out, all interfaces or one
  show statistics [1h|24h|7d] traffic per interface (average and peak), top
                              applications and hosts, IPS matches and top
                              signatures (default: the last hour)
  show ips                    IPS: engine, signatures (version, count, last
                              update), rules inspected
  show decryption             TLS decryption: state, CA, rules, connections
  show decryption ca          the decryption CA's certificate (PEM) and
                              fingerprint, to install on clients
  show decryption learned     servers passed through because their clients
                              rejected the firewall's certificate (pinned)
  show management-certificate [pem]
                              the web UI and tag API certificate: subject,
                              names, expiry, fingerprint (pem: and the PEM)
  show api-keys               API keys for the tag API and Prometheus (name,
                              scopes, key)
  show metrics [TEXT]         the Prometheus metrics (what a scraper of
                              https://<mgmt>:8443/metrics gets); with TEXT,
                              only the lines containing it
  show snmp                   the SNMP agent: state, who may poll, trap
                              receivers, credentials (names only)
  show log traffic [N] [TEXT] data-plane log: connections matching rules with
                              logging on (newest first; default 50)
                              add columns LIST to choose what to show, e.g.
                              columns src,sport,dst,dport,app (? lists them);
                              end with where QUERY to filter, e.g.
                              where zone = inside and dst = 4.2.2.2
  show log threat [N] [TEXT]  IPS log: signature matches on rules with an
                              ips-profile, blocked or alerted (columns and
                              where work as for traffic)
  show log decryption [N] [TEXT]
                              decryption log: what tlsd did with each
                              connection (decrypted, excluded, passed...)
  show log system [N] [TEXT]  management log: commits, logins, tags, upgrades,
                              user and role changes

  show log-forwarding         log forwarding to syslog servers (a SIEM): state,
                              messages sent, queued and dropped, last error

  show whoami                 your user name, role and what it allows
  show ssh-keys               your SSH keys
  show users                  SJB-OS users: role, status, last login
  show user NAME              one user, with their SSH keys
  show roles                  roles and who has them
  show role NAME              what a role may view and change, by area

  load                        paste a whole config (YAML); finish with a line
                              containing only "end", or Ctrl-D
  revert                      discard uncommitted changes
  commit [-m "MESSAGE"] [-confirm 5m]
                              apply the candidate; with -confirm it rolls back
                              unless you run confirm in time
  confirm                     accept a pending commit
  rollback N                  commit revision N again

  tags register IP TAG... [-ttl 1h]
  tags unregister IP TAG...

  request ips update          download the latest IPS signatures now
  request decryption ca generate
                              make a new decryption CA (clients must then
                              trust its certificate: show decryption ca)
  request decryption ca import
                              paste your own CA certificate and key (PEM)
  request decryption learned clear
                              decrypt the learned (pinned) servers again
  request management-certificate import
                              paste the web UI and tag API certificate, its
                              intermediates and key (PEM), e.g. from your CA
  request management-certificate self-signed
                              back to a new self-signed certificate
  request log-forwarding test NAME
                              send a test message to a log server
  request snmp credential add NAME v3 [auth sha256|sha512] [priv aes|aes256]
                              an SNMPv3 user (asks for its passphrases;
                              superusers); default SHA-256 and AES
  request snmp credential add NAME v2c
                              a v2c community (asks for it; superusers)
  request snmp credential change NAME ...
                              new secrets for a credential, used at once
  request snmp credential delete NAME
  request api-key add NAME scopes SCOPE[,SCOPE]
                              a key for the tag API or Prometheus
                              (metrics:read, tags:read, tags:write;
                              superusers); shows the key
  request api-key delete NAME
  request backup export [accounts]
                              print a backup of the running config to copy
                              into a file; with accounts, also users, roles
                              and tag API keys (superusers; encrypted, asks
                              for a passphrase)
  request backup restore [config] [accounts]
                              paste a backup: its config becomes the
                              candidate (commit it as usual); accounts
                              restores users, roles and API keys at once
                              (superusers)
  request user add NAME role ROLE
                              add a user (asks for the password); roles:
                              superuser, admin, read-only or a custom one
  request user set NAME role ROLE | set NAME disabled yes|no
                              change a user's role, or stop their logins
  request user password NAME  set someone's password (ends their sessions)
  request user unlock NAME    unlock after 5 wrong passwords
  request user delete NAME    delete a user (admin can't be deleted)
  request user ssh-key add NAME | ssh-key delete NAME N
                              manage someone's SSH keys
  request role add NAME [description "TEXT"]
                              a custom role, with no permissions yet
  request role set NAME AREA view|change|none
                              what the role may do in an area (show whoami
                              lists the areas)
  request role delete NAME    delete a custom role nobody has
  ping HOST [COUNT]           ping through the forwarding table
  passwd                      change your password (SSH, console and web UI)
  ssh-key add | ssh-key delete N
                              add (paste) or delete your own SSH keys
  configure                   configuration mode: set, delete, move, rename
  sjb                         a word from the border guard
  help                        this list
  exit                        log out

Tab completes commands and names; ? shows what can come next.
Upgrades live in the web UI (https://<mgmt-ip>/).
`

const configHelp = `Configuration mode. Changes go to a working copy, are saved to the
candidate as soon as they form a valid config, and reach the firewall at
commit. Tab completes, ? shows what can come next.

  set OBJECT NAME [ATTR VALUE]...   create or change, e.g.
      set address web-srv cidr 10.10.1.80
      set rule allow-web from inside to outside source [ inside-net ] service web action allow
      set route lab-net destination 10.20.0.0/16 gateway 10.10.1.254
      set system hostname sjb-lab
  delete OBJECT NAME                delete it
  delete OBJECT NAME ATTR           clear an attribute (lists go back to any)
  delete OBJECT NAME ATTR VALUE     remove a list member ([ a b ] for several)
  move rule|nat NAME top|bottom|before OTHER|after OTHER
  rename OBJECT OLD NEW             references follow
  show [OBJECT [NAME]]              the working config as YAML
  commit [-m "MESSAGE"] [-confirm 5m]
  revert                            throw away changes since the last commit
  run COMMAND                       an operational command, e.g. run show routes
  exit                              back to operational mode

Objects: system, zone, interface, address, address-group, service, rule, nat, route,
decryption-rule, decryption-profile, decryption-exclusion (and the others Tab lists).
Lists (from, to, source, destination, service, application, static): set
adds members, "any" replaces the list.
`

// session is one CLI login: operational mode, or configuration mode with a
// working copy of the config.
type session struct {
	in      *bufio.Reader
	cfg     *cliconf.Model // non-nil in configuration mode
	invalid string         // why the working copy isn't saved yet
	warned  bool           // exit already warned about unsaved changes
}

func (s *session) prompt() string {
	host, _ := os.Hostname()
	if s.cfg != nil {
		return fmt.Sprintf("%s@%s# ", whoami(), host)
	}
	return fmt.Sprintf("%s@%s> ", whoami(), host)
}

// complete serves the line editor: candidates for the word being typed.
func (s *session) complete(head string) (string, []lineedit.Candidate) {
	if strings.Count(head, `"`)%2 == 1 {
		return "", nil // inside a quoted message
	}
	partial := head[strings.LastIndexAny(head, " \t")+1:]
	words, err := splitWords(head[:len(head)-len(partial)])
	if err != nil {
		return partial, nil
	}
	var cands []cliconf.Candidate
	if s.cfg != nil {
		cands = cliconf.ConfigCandidates(s.cfg, words)
	} else {
		cands = cliconf.OperationalCandidates(words)
	}
	var out []lineedit.Candidate
	for _, c := range cliconf.Filter(cands, partial) {
		if s.cfg == nil && !c.IsHint() && !allowedCommand(currentMe, strings.Join(append(slices.Clone(words), c.Word), " ")) {
			continue // the role can't use it
		}
		out = append(out, lineedit.Candidate{Word: c.Word, Help: c.Help})
	}
	return partial, out
}

// currentMe is who is logged in, as ngfwd sees them: help and Tab show
// only what their role can use (ngfwd enforces it regardless).
var currentMe *me

func shellCmd(args []string) error {
	s := &session{in: bufio.NewReader(os.Stdin)}
	currentMe, _ = fetchMe()
	if len(args) >= 2 && args[0] == "-c" {
		_, err := s.run(strings.Join(args[1:], " "))
		return err
	}
	// Ctrl-C and friends must not kill the CLI (that would end the session);
	// catching them, rather than ignoring, leaves them at default for ping.
	sig := make(chan os.Signal, 4)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTSTP)
	go func() {
		for range sig {
			fmt.Println()
		}
	}()

	tty := isTerminal()
	ed := lineedit.New(s.in, os.Stdout, s.complete)
	if tty {
		fmt.Println("SJB-OS CLI: Stops Junk at the Border. Tab completes, ? shows options, help lists commands.")
	}
	for {
		line, err := s.readLine(ed, tty)
		if err == lineedit.ErrInterrupt {
			continue
		}
		if err != nil {
			fmt.Println()
			return nil // Ctrl-D or end of input
		}
		quit, err := s.run(line)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
		}
		if quit {
			return nil
		}
	}
}

// readLine uses the line editor on a terminal and plain lines otherwise
// (scripts piped over SSH).
func (s *session) readLine(ed *lineedit.Editor, tty bool) (string, error) {
	if s.cfg != nil {
		fmt.Println("[edit]") // configuration mode
	}
	if tty {
		if restore, err := lineedit.Raw(); err == nil {
			defer restore()
			return ed.ReadLine(s.prompt())
		}
	}
	fmt.Print(s.prompt())
	line, err := s.in.ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// run executes one line in the current mode; quit ends the session.
func (s *session) run(line string) (quit bool, err error) {
	line = strings.TrimSpace(line)
	if s.cfg != nil {
		return false, s.runConfig(line)
	}
	switch line {
	case "exit", "quit", "logout":
		return true, nil
	case "configure", "conf", "config":
		return false, s.enterConfig()
	}
	return false, runShellLine(line, s.in)
}

func (s *session) enterConfig() error {
	if currentMe != nil && !currentMe.ConfigEdit {
		return fmt.Errorf("role %s can't change the config (show running shows it)", currentMe.Role)
	}
	out, err := call("GET", "/v1/config/candidate", nil)
	if err != nil {
		return err
	}
	m, err := cliconf.LoadYAML(out)
	if err != nil {
		return fmt.Errorf("the candidate config can't be edited here: %w", err)
	}
	s.cfg, s.invalid, s.warned = m, "", false
	fmt.Println("Entering configuration mode. Tab completes, ? shows options, help lists commands.")
	return nil
}

func (s *session) runConfig(line string) error {
	words, err := splitWords(line)
	if err != nil || len(words) == 0 {
		return err
	}
	cmd, rest := words[0], words[1:]
	switch cmd {
	case "help", "?":
		fmt.Print(configHelp)
	case "set", "delete", "move", "rename":
		edit := map[string]func([]string) error{"set": s.cfg.Set, "delete": s.cfg.Delete, "move": s.cfg.Move, "rename": s.cfg.Rename}[cmd]
		if err := edit(rest); err != nil {
			return err
		}
		s.warned = false
		return s.save()
	case "show":
		if len(rest) > 0 && cliconf.KindByName(rest[0]) == nil {
			return showCmd(rest) // show diff, show status... work here too
		}
		out, err := s.cfg.Show(rest)
		if err != nil {
			return err
		}
		fmt.Print(out)
	case "commit":
		if s.invalid != "" {
			return fmt.Errorf("the working config isn't valid yet, so nothing was committed:\n%s", s.invalid)
		}
		return dispatch("commit", rest)
	case "revert":
		if _, err := call("POST", "/v1/config/revert", nil); err != nil {
			return err
		}
		fmt.Println("changes discarded; the working config is the running config again")
		return s.enterConfigQuiet()
	case "run":
		if len(rest) == 0 {
			return fmt.Errorf("run what? e.g. run show routes")
		}
		if rest[0] == "configure" {
			return fmt.Errorf("already in configuration mode")
		}
		return runShellLine(strings.Join(quoteAll(rest), " "), s.in)
	case "exit", "quit", "end":
		if s.invalid != "" && !s.warned {
			s.warned = true
			return fmt.Errorf("the working config has changes that aren't valid yet, so they aren't saved:\n%s\nfix them, or exit again to throw them away", s.invalid)
		}
		s.cfg = nil
		if st, err := call("GET", "/v1/status", nil); err == nil && strings.Contains(string(st), `"uncommitted_changes": true`) {
			fmt.Println("Exiting configuration mode. The candidate has uncommitted changes: commit, or revert.")
		} else {
			fmt.Println("Exiting configuration mode.")
		}
	case "configure":
		fmt.Println("already in configuration mode")
	default:
		return fmt.Errorf("unknown configuration command %q (type help; run COMMAND for operational ones)", cmd)
	}
	return nil
}

func (s *session) enterConfigQuiet() error {
	out, err := call("GET", "/v1/config/candidate", nil)
	if err != nil {
		return err
	}
	m, err := cliconf.LoadYAML(out)
	if err != nil {
		return err
	}
	s.cfg, s.invalid, s.warned = m, "", false
	return nil
}

// save pushes the working copy to the candidate when it is valid. While it
// isn't (a new rule without an action yet), it stays local and the reason
// is shown once; commit refuses until it is fixed.
func (s *session) save() error {
	y, err := s.cfg.YAML()
	if err != nil {
		return err
	}
	if _, err := call("PUT", "/v1/config/candidate", y); err != nil {
		msg := strings.TrimPrefix(err.Error(), "invalid: ")
		first := s.invalid == ""
		s.invalid = msg
		if first {
			fmt.Println("note: not saved to the candidate yet, it isn't valid:")
			fmt.Println("  " + strings.ReplaceAll(msg, "\n", "\n  "))
		}
		return nil
	}
	if s.invalid != "" {
		fmt.Println("saved: the working config is valid again")
	}
	s.invalid = ""
	return nil
}

func quoteAll(words []string) []string {
	out := make([]string, len(words))
	for i, w := range words {
		if strings.ContainsAny(w, " \t") || w == "" {
			w = `"` + w + `"`
		}
		out[i] = w
	}
	return out
}

// runShellLine runs one CLI command. in supplies pasted input for load.
func runShellLine(line string, in io.Reader) error {
	words, err := splitWords(line)
	if err != nil {
		return err
	}
	if len(words) == 0 {
		return nil
	}
	cmd, rest := words[0], words[1:]
	switch cmd {
	case "help", "?":
		if m, err := fetchMe(); err == nil {
			currentMe = m
		}
		fmt.Print(roleHelp(currentMe, shellHelp))
		return nil
	case "exit", "quit", "logout":
		return nil
	case "show":
		return showCmd(rest)
	case "load":
		if len(rest) != 0 {
			return fmt.Errorf("load takes no arguments: paste the config after it")
		}
		return loadPasted(in)
	case "revert":
		return printJSON(call("POST", "/v1/config/revert", nil))
	case "commit", "confirm", "rollback", "tags", "sjb":
		return dispatch(cmd, rest)
	case "ssh-key":
		return sshKeyCmd(rest, in)
	case "request":
		if len(rest) > 0 && rest[0] == "user" {
			return requestUser(rest[1:], in)
		}
		if len(rest) > 0 && rest[0] == "role" {
			return requestRole(rest[1:])
		}
		if len(rest) > 0 && rest[0] == "backup" {
			return requestBackup(rest[1:], in)
		}
		if len(rest) > 0 && rest[0] == "management-certificate" {
			return requestMgmtCert(rest[1:], in)
		}
		if len(rest) > 0 && rest[0] == "snmp" {
			return requestSNMP(rest[1:], in)
		}
		if len(rest) > 0 && rest[0] == "api-key" {
			return requestAPIKey(rest[1:])
		}
		if len(rest) == 3 && rest[0] == "log-forwarding" && rest[1] == "test" {
			return requestLogForwardingTest(rest[2])
		}
		switch strings.Join(rest, " ") {
		case "ips update":
			return requestIPSUpdate()
		case "decryption ca generate":
			return requestDecryptionCAGenerate(in)
		case "decryption ca import":
			return requestDecryptionCAImport(in)
		case "decryption learned clear":
			return requestDecryptionLearnedClear()
		}
		return fmt.Errorf("request ips update | decryption ca generate | decryption ca import | decryption learned clear | management-certificate import|self-signed | log-forwarding test NAME | snmp credential ... | api-key add|delete ... | backup ... | user ... | role ...")
	case "ping":
		return pingCmd(rest)
	case "passwd":
		if len(rest) != 0 {
			return fmt.Errorf("passwd changes your own password and takes no arguments")
		}
		return passwdCmd(in)
	}
	return fmt.Errorf("unknown command %q (type help)", cmd)
}

func showCmd(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("show what? (type help)")
	}
	what, rest := args[0], args[1:]
	switch {
	case what == "status" && len(rest) == 0:
		return dispatch("status", nil)
	case what == "version" && len(rest) == 0:
		return upgradeCmd([]string{"status"})
	case (what == "running" || what == "candidate") && len(rest) == 0:
		return dispatch("show", []string{what})
	case what == "diff" && len(rest) == 0:
		return dispatch("diff", nil)
	case what == "ruleset" && len(rest) == 0:
		return dispatch("preview", nil)
	case what == "revisions" && len(rest) == 0:
		return dispatch("revisions", nil)
	case what == "revision" && len(rest) == 1:
		n, err := strconv.Atoi(rest[0])
		if err != nil || n < 1 {
			return fmt.Errorf("revision must be a positive number")
		}
		return printRaw(call("GET", "/v1/revisions/"+rest[0], nil))
	case what == "tags" && len(rest) <= 1:
		return dispatch("tags", rest)
	case what == "log" && len(rest) >= 1:
		return showLog(rest)
	case what == "log-forwarding" && len(rest) == 0:
		return showLogForwarding()
	case what == "snmp" && len(rest) == 0:
		return showSNMP()
	case what == "metrics" && len(rest) <= 1:
		return showMetrics(strings.Join(rest, ""))
	case what == "whoami" && len(rest) == 0:
		return showWhoami()
	case what == "ssh-keys" && len(rest) == 0:
		return showSSHKeys()
	case what == "users" && len(rest) == 0:
		return showUsers()
	case what == "user" && len(rest) == 1:
		return showUser(rest[0])
	case what == "roles" && len(rest) == 0:
		return showRoles()
	case what == "role" && len(rest) == 1:
		return showRole(rest[0])
	case what == "management-certificate" && (len(rest) == 0 || len(rest) == 1 && rest[0] == "pem"):
		return showMgmtCert(rest)
	case what == "api-keys" && len(rest) == 0:
		return printRaw(call("GET", "/v1/api-keys", nil))
	case what == "interfaces" && len(rest) == 0:
		return showInterfaces()
	case what == "arp" && len(rest) == 0:
		return runTool("ip", "-4", "neigh", "show")
	case what == "arp" && len(rest) == 1:
		if !ifaceNameRE.MatchString(rest[0]) {
			return fmt.Errorf("%q is not an interface name", rest[0])
		}
		return runTool("ip", "-4", "neigh", "show", "dev", rest[0])
	case what == "app" && len(rest) == 0:
		return showApps()
	case what == "app" && len(rest) == 1 && rest[0] == "categories":
		return showAppCategories()
	case what == "app" && len(rest) <= 2 && rest[0] == "catalog":
		q := ""
		if len(rest) == 2 {
			q = rest[1]
		}
		return showAppCatalog(q)
	case what == "ips" && len(rest) == 0:
		return showIPS()
	case what == "decryption" && len(rest) == 0:
		return showDecryption()
	case what == "decryption" && len(rest) == 1 && rest[0] == "ca":
		return showDecryptionCA()
	case what == "decryption" && len(rest) == 1 && rest[0] == "learned":
		return showDecryptionLearned()
	case what == "statistics" && len(rest) <= 1:
		w := "1h"
		if len(rest) == 1 {
			w = rest[0]
		}
		return showStatistics(w)
	case what == "dhcp" && len(rest) == 0:
		return showDHCP()
	case what == "dhcp" && len(rest) <= 2 && rest[0] == "leases":
		iface := ""
		if len(rest) == 2 {
			if !ifaceNameRE.MatchString(rest[1]) {
				return fmt.Errorf("%q is not an interface name", rest[1])
			}
			iface = rest[1]
		}
		return showDHCPLeases(iface)
	case what == "routes" && len(rest) == 2 && rest[0] == "vrf":
		if rest[1] == config.VRFDefault {
			return runTool("ip", "-4", "route")
		}
		if !vrfNameRE.MatchString(rest[1]) {
			return fmt.Errorf("%q is not a VRF name", rest[1])
		}
		return runTool("ip", "-4", "route", "show", "vrf", config.VRFDevice(rest[1]))
	case what == "routes" && len(rest) == 0:
		if err := printStaticRoutes(); err != nil {
			return err
		}
		fmt.Println("forwarding table (vrf default):")
		if err := runTool("ip", "-4", "route"); err != nil {
			return err
		}
		vrfs, _, _ := runningVRFs()
		for _, v := range vrfs {
			fmt.Printf("\nvrf %s:\n", v.Name)
			runTool("ip", "-4", "route", "show", "vrf", config.VRFDevice(v.Name))
		}
		fmt.Println("\nmanagement table (vrf mgmt):")
		return runTool("ip", "-4", "route", "show", "vrf", "vrf-mgmt")
	case what == "nat" && len(rest) == 0:
		return showNAT()
	case what == "vrf" && len(rest) == 0:
		return showVRF()
	case (what == "bgp" || what == "ospf") && len(rest) == 0:
		return showRouting(what, "")
	case what == "rib" && len(rest) == 0:
		return showRouting("routes", "")
	case what == "rib" && len(rest) == 2 && rest[0] == "vrf" && vrfNameRE.MatchString(rest[1]):
		return showRouting("routes", rest[1])
	}
	return fmt.Errorf("unknown show command (type help)")
}

func loadPasted(in io.Reader) error {
	tty := isTerminal()
	if tty {
		fmt.Println(`Paste the config, then a line with only "end" (or Ctrl-D):`)
	}
	var b strings.Builder
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 64*1024), 4<<20)
	for sc.Scan() {
		if strings.TrimSpace(sc.Text()) == "end" {
			break
		}
		b.WriteString(sc.Text())
		b.WriteByte('\n')
	}
	if err := sc.Err(); err != nil {
		return err
	}
	if strings.TrimSpace(b.String()) == "" {
		return fmt.Errorf("nothing pasted; candidate unchanged")
	}
	if _, err := call("PUT", "/v1/config/candidate", []byte(b.String())); err != nil {
		return err
	}
	fmt.Println("candidate updated; review with `show diff`, apply with `commit -confirm 5m`")
	return nil
}

var hostRE = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,62}\.)*[A-Za-z0-9-]{1,63}\.?$`)

func pingCmd(args []string) error {
	if len(args) < 1 || len(args) > 2 {
		return fmt.Errorf("usage: ping HOST [COUNT]")
	}
	host := args[0]
	if _, err := netip.ParseAddr(host); err != nil && !hostRE.MatchString(host) {
		return fmt.Errorf("%q is not an IP address or host name", host)
	}
	count := 4
	if len(args) == 2 {
		n, err := strconv.Atoi(args[1])
		if err != nil || n < 1 || n > 100 {
			return fmt.Errorf("count must be 1-100")
		}
		count = n
	}
	return runTool("ping", "-c", strconv.Itoa(count), "-W", "2", "--", host)
}

// runTool runs a fixed system program with checked arguments, attached to
// the terminal. No shell is involved.
func runTool(name string, args ...string) error {
	c := exec.Command(name, args...)
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	err := c.Run()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return nil // the tool already said what went wrong
	}
	return err
}

// splitWords splits a command line on spaces, honouring double quotes.
func splitWords(s string) ([]string, error) {
	var words []string
	var cur strings.Builder
	inQuote, have := false, false
	for _, r := range s {
		switch {
		case r == '"':
			inQuote = !inQuote
			have = true
		case (r == ' ' || r == '\t') && !inQuote:
			if have {
				words = append(words, cur.String())
				cur.Reset()
				have = false
			}
		default:
			cur.WriteRune(r)
			have = true
		}
	}
	if inQuote {
		return nil, fmt.Errorf("unterminated quote")
	}
	if have {
		words = append(words, cur.String())
	}
	return words, nil
}

// passwdCmd changes the caller's one password (SSH, console, web UI)
// through ngfwd, which can write both password stores. Reads three lines
// from in: current, new, new again (echo off on a terminal).
func passwdCmd(in io.Reader) error {
	br, ok := in.(*bufio.Reader)
	if !ok {
		br = bufio.NewReader(in)
	}
	ask := func(label string) (string, error) {
		tty := isTerminal()
		if tty {
			fmt.Fprint(os.Stderr, label)
			setEcho(false)
			defer func() { setEcho(true); fmt.Fprintln(os.Stderr) }()
		}
		line, err := br.ReadString('\n')
		if err != nil && line == "" {
			return "", fmt.Errorf("no input")
		}
		return strings.TrimRight(line, "\r\n"), nil
	}
	cur, err := ask("Current password: ")
	if err != nil {
		return err
	}
	a, err := ask("New password (10+ characters): ")
	if err != nil {
		return err
	}
	b, err := ask("Again: ")
	if err != nil {
		return err
	}
	if a != b {
		return fmt.Errorf("passwords do not match; nothing changed")
	}
	body := mustJSON(map[string]string{"user": whoami(), "current": cur, "new": a})
	if _, err := call("POST", "/v1/password", body); err != nil {
		return err
	}
	fmt.Println("Password changed for SSH, the console and the web UI. New key, same gate.")
	return nil
}

// printStaticRoutes lists the config's static routes and whether each is in
// the kernel. Routes are edited like any config (web UI, or load/commit).
func printStaticRoutes() error {
	out, err := call("GET", "/v1/routes", nil)
	if err != nil {
		return err
	}
	var rs []struct {
		Name      string `json:"name"`
		Dest      string `json:"destination"`
		Gateway   string `json:"gateway"`
		Dev       string `json:"interface"`
		Table     int    `json:"table"`
		VRF       string `json:"vrf"`
		Installed bool   `json:"installed"`
		Error     string `json:"error"`
	}
	if err := json.Unmarshal(out, &rs); err != nil {
		return err
	}
	fmt.Println("static routes (config):")
	if len(rs) == 0 {
		fmt.Println("  none (add them in the web UI's Network page, or under routes: in the config)")
		fmt.Println()
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "  NAME\tVRF\tDESTINATION\tNEXT HOP\tINTERFACE\tSTATE")
	for _, r := range rs {
		vrf, state, dev, hop := r.VRF, "installed", r.Dev, r.Gateway
		if vrf == "" {
			vrf = config.VRFDefault
		}
		if !r.Installed {
			state = "NOT INSTALLED: " + r.Error
		}
		if hop == "" && strings.HasPrefix(dev, "vrf-") {
			hop, dev = "vrf "+strings.TrimPrefix(dev, "vrf-"), ""
		}
		if dev == "" {
			dev = "-"
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\t%s\n", r.Name, vrf, r.Dest, hop, dev, state)
	}
	tw.Flush()
	fmt.Println()
	return nil
}

// showLog prints the traffic or system log as a table, newest first.
func showLog(args []string) error {
	kind := args[0]
	if kind != "traffic" && kind != "threat" && kind != "decryption" && kind != "system" {
		return fmt.Errorf("show log traffic, show log threat, show log decryption or show log system")
	}
	n, q := 50, ""
	cols := logs.DefaultTrafficColumns
	parseCols := logs.ParseColumns
	switch kind {
	case "threat":
		cols, parseCols = logs.DefaultThreatColumns, logs.ParseThreatColumns
	case "decryption":
		cols, parseCols = logs.DefaultDecryptionColumns, logs.ParseDecryptionColumns
	}
	rest := args[1:]
	for i := 0; i < len(rest); i++ {
		a := rest[i]
		switch v, err := strconv.Atoi(a); {
		case a == "where":
			// The rest of the line is the query; re-quote words that had
			// spaces inside quotes.
			var parts []string
			for _, w := range rest[i+1:] {
				if strings.ContainsAny(w, " \t") {
					w = `"` + w + `"`
				}
				parts = append(parts, w)
			}
			q = strings.Join(parts, " ")
			if q == "" {
				return fmt.Errorf("where needs a query, e.g. where zone = inside and dst = 4.2.2.2")
			}
			i = len(rest)
		case a == "columns" && kind != "system":
			if i+1 >= len(rest) {
				return fmt.Errorf("columns needs a list, e.g. columns src,sport,dst,dport,app")
			}
			c, err := parseCols(rest[i+1])
			if err != nil {
				return err
			}
			cols = c
			i++
		case err == nil && v > 0:
			n = v
		default:
			q = a
		}
	}
	path := fmt.Sprintf("/v1/logs/%s?n=%d&q=%s", kind, n, url.QueryEscape(q))
	out, err := call("GET", path, nil)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	defer tw.Flush()
	ts := func(t time.Time) string { return t.Local().Format("Jan 02 15:04:05") }
	table := func(n int, value func(i int, col string) string, when func(i int) time.Time) {
		head := make([]string, len(cols))
		for i, c := range cols {
			head[i] = strings.ToUpper(c)
		}
		fmt.Fprintln(tw, strings.Join(head, "\t"))
		for e := 0; e < n; e++ {
			row := make([]string, len(cols))
			for i, c := range cols {
				switch v := value(e, c); {
				case c == "time":
					row[i] = ts(when(e))
				case v == "":
					row[i] = "-"
				default:
					row[i] = v
				}
			}
			fmt.Fprintln(tw, strings.Join(row, "\t"))
		}
	}
	if kind == "decryption" {
		var es []logs.Decryption
		if err := json.Unmarshal(out, &es); err != nil {
			return err
		}
		if len(es) == 0 {
			fmt.Println("no decryption log entries (connections decryption rules cover write here)")
			return nil
		}
		table(len(es), func(i int, c string) string { return es[i].Value(c) }, func(i int) time.Time { return es[i].Time })
		return nil
	}
	if kind == "threat" {
		var es []logs.Threat
		if err := json.Unmarshal(out, &es); err != nil {
			return err
		}
		if len(es) == 0 {
			fmt.Println("no threats logged (rules with an ips-profile write here)")
			return nil
		}
		table(len(es), func(i int, c string) string { return es[i].Value(c) }, func(i int) time.Time { return es[i].Time })
		return nil
	}
	if kind == "traffic" {
		var es []logs.Traffic
		if err := json.Unmarshal(out, &es); err != nil {
			return err
		}
		if len(es) == 0 {
			fmt.Println("no traffic logged (only rules with log yes write here)")
			return nil
		}
		head := make([]string, len(cols))
		for i, c := range cols {
			head[i] = strings.ToUpper(c)
		}
		fmt.Fprintln(tw, strings.Join(head, "\t"))
		for _, e := range es {
			row := make([]string, len(cols))
			for i, c := range cols {
				switch v := e.Value(c); {
				case c == "time":
					row[i] = ts(e.Time)
				case v == "":
					row[i] = "-"
				default:
					row[i] = v
				}
			}
			fmt.Fprintln(tw, strings.Join(row, "\t"))
		}
		return nil
	}
	var es []struct {
		Time                           time.Time
		Source, Level, Message, Fields string
	}
	if err := json.Unmarshal(out, &es); err != nil {
		return err
	}
	if len(es) == 0 {
		fmt.Println("no system log entries")
		return nil
	}
	fmt.Fprintln(tw, "TIME\tSOURCE\tLEVEL\tMESSAGE")
	for _, e := range es {
		msg := e.Message
		if e.Fields != "" {
			msg += "  " + e.Fields
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", ts(e.Time), e.Source, e.Level, msg)
	}
	return nil
}

// showInterfaces prints the kernel's view, then the addresses the config
// sets on physical NICs and whether each is applied.
func showInterfaces() error {
	if err := runTool("ip", "-br", "addr"); err != nil {
		return err
	}
	out, err := call("GET", "/v1/nics", nil)
	if err != nil {
		return err
	}
	var states []struct {
		Name, Address, Error string
		Applied              bool
	}
	json.Unmarshal(out, &states)
	if len(states) == 0 {
		return nil
	}
	fmt.Println("\nconfigured addresses (config):")
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	defer tw.Flush()
	fmt.Fprintln(tw, "  INTERFACE\tADDRESS\tSTATE")
	for _, s := range states {
		st := "applied"
		if !s.Applied {
			st = "NOT APPLIED: " + s.Error
		}
		addr := s.Address
		if addr == nicaddr.TrunkOnly {
			addr = "none (trunk: VLANs only, untagged dropped)"
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s\n", s.Name, addr, st)
	}
	return nil
}

var ifaceNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$`)

var vrfNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$`)

// runningVRFs reads the VRFs of the running config (and the config).
func runningVRFs() ([]config.VRF, *config.Config, error) {
	out, err := call("GET", "/v1/config/running", nil)
	if err != nil {
		return nil, nil, err
	}
	if len(strings.TrimSpace(string(out))) == 0 {
		return nil, &config.Config{}, nil
	}
	cfg, err := config.Parse(out)
	if err != nil {
		return nil, nil, err
	}
	return cfg.VRFs, cfg, nil
}

func showVRF() error {
	vrfs, cfg, err := runningVRFs()
	if err != nil {
		return err
	}
	out, err := call("GET", "/v1/netdev", nil)
	if err != nil {
		return err
	}
	var states []struct {
		Name, Kind, Error string
		OK                bool
	}
	json.Unmarshal(out, &states)
	state := map[string]string{}
	for _, s := range states {
		if s.OK {
			state[s.Name] = "up"
		} else {
			state[s.Name] = "NOT UP: " + s.Error
		}
	}
	tables := cfg.VRFTables()
	members := map[string][]string{}
	for _, in := range cfg.Interfaces {
		if in.Name == cfg.System.MgmtInterface {
			continue
		}
		members[in.VRFOf()] = append(members[in.VRFOf()], in.Name)
	}
	if m := cfg.System.MgmtInterface; m != "" {
		members[config.VRFMgmt] = []string{m}
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	defer tw.Flush()
	fmt.Fprintln(tw, "VRF\tTABLE\tINTERFACES\tSTATE")
	row := func(name, table, st string) {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", name, table, strings.Join(members[name], " "), st)
	}
	row(config.VRFDefault, "main", "built in")
	row(config.VRFMgmt, "100", "built in (first boot)")
	for _, v := range vrfs {
		st := state[config.VRFDevice(v.Name)]
		if st == "" {
			st = "pending"
		}
		row(v.Name, strconv.Itoa(tables[v.Name]), st)
	}
	return nil
}

// showRouting prints BGP neighbors, OSPF neighbors or FRR's routes.
func showRouting(what, vrf string) error {
	out, err := call("GET", "/v1/routing/"+what+"?vrf="+url.QueryEscape(vrf), nil)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	defer tw.Flush()
	switch what {
	case "bgp":
		var ps []struct {
			VRF, Address, State, Uptime, Description string
			RemoteAS                                 uint32 `json:"remote_as"`
			Received                                 int    `json:"prefixes_received"`
			Sent                                     int    `json:"prefixes_sent"`
		}
		if err := json.Unmarshal(out, &ps); err != nil {
			return err
		}
		if len(ps) == 0 {
			fmt.Println("no BGP neighbors (or BGP isn't configured)")
			return nil
		}
		fmt.Fprintln(tw, "VRF\tNEIGHBOR\tREMOTE AS\tSTATE\tUP/DOWN\tRECEIVED\tSENT\tDESCRIPTION")
		for _, p := range ps {
			fmt.Fprintf(tw, "%s\t%s\t%d\t%s\t%s\t%d\t%d\t%s\n", p.VRF, p.Address, p.RemoteAS, p.State, p.Uptime, p.Received, p.Sent, p.Description)
		}
	case "ospf":
		var ns []struct {
			VRF, State, Address, Interface string
			RouterID                       string `json:"router_id"`
		}
		if err := json.Unmarshal(out, &ns); err != nil {
			return err
		}
		if len(ns) == 0 {
			fmt.Println("no OSPF neighbors (or OSPF isn't configured)")
			return nil
		}
		fmt.Fprintln(tw, "VRF\tNEIGHBOR ID\tSTATE\tADDRESS\tINTERFACE")
		for _, n := range ns {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", n.VRF, n.RouterID, n.State, n.Address, n.Interface)
		}
	case "routes":
		var rs []struct {
			VRF, Prefix, Protocol, Interface string
			NextHop                          string `json:"next_hop"`
			Selected                         bool
		}
		if err := json.Unmarshal(out, &rs); err != nil {
			return err
		}
		fmt.Fprintln(tw, "VRF\tPREFIX\tPROTOCOL\tNEXT HOP\tINTERFACE\tBEST")
		for _, r := range rs {
			best := ""
			if r.Selected {
				best = "*"
			}
			hop := r.NextHop
			if hop == "" {
				hop = "directly connected"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", r.VRF, r.Prefix, r.Protocol, hop, r.Interface, best)
		}
	}
	return nil
}

// showDHCP prints the configured DHCP servers as clients see them.
func showDHCP() error {
	out, err := call("GET", "/v1/dhcp", nil)
	if err != nil {
		return err
	}
	var st struct {
		Installed, Running bool
		Error              string
		Servers            []struct {
			Interface, Network, Range, Gateway, Domain string
			DNS                                        []string
			DNSDefault                                 bool `json:"dns_default"`
			LeaseTime                                  int  `json:"lease_time"`
			Reservations, Leases                       int
		}
	}
	if err := json.Unmarshal(out, &st); err != nil {
		return err
	}
	if len(st.Servers) == 0 {
		fmt.Println("no DHCP servers configured (configure: set dhcp-server INTERFACE range FIRST-LAST)")
		return nil
	}
	switch {
	case !st.Installed:
		fmt.Println("DHCP server (Kea): not installed yet; an upgrade installs it in the background")
	case !st.Running:
		fmt.Println("DHCP server (Kea): NOT RUNNING (root: journalctl -u kea-dhcp4-server)")
	default:
		fmt.Println("DHCP server (Kea): running")
	}
	if st.Error != "" {
		fmt.Println("leases unavailable:", st.Error)
	}
	fmt.Println()
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "INTERFACE\tNETWORK\tRANGE\tGATEWAY\tDNS\tLEASE\tRESERVED\tACTIVE LEASES")
	for _, s := range st.Servers {
		dns := strings.Join(s.DNS, ",")
		if s.DNSDefault {
			dns += " (firewall's)"
		}
		if len(s.DNS) == 0 {
			dns = "none"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%d\t%d\n", s.Interface, s.Network, s.Range, s.Gateway, dns,
			(time.Duration(s.LeaseTime) * time.Second).String(), s.Reservations, s.Leases)
	}
	return tw.Flush()
}

// showDHCPLeases prints the leases Kea holds.
func showDHCPLeases(iface string) error {
	out, err := call("GET", "/v1/dhcp/leases?interface="+url.QueryEscape(iface), nil)
	if err != nil {
		return err
	}
	var ls []struct {
		Interface, Address, MAC, Hostname, State, Reserved string
		Expires                                            time.Time
	}
	if err := json.Unmarshal(out, &ls); err != nil {
		return err
	}
	if len(ls) == 0 {
		fmt.Println("no leases")
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "INTERFACE\tADDRESS\tMAC\tHOSTNAME\tSTATE\tEXPIRES\tRESERVATION")
	for _, l := range ls {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", l.Interface, l.Address, l.MAC, l.Hostname, l.State,
			l.Expires.Local().Format("2006-01-02 15:04:05"), l.Reserved)
	}
	return tw.Flush()
}

// showApps prints the applications App Identification has seen, by bytes.
func showApps() error {
	out, err := call("GET", "/v1/apps", nil)
	if err != nil {
		return err
	}
	var st struct {
		Enabled, Running bool
		ActiveFlows      int `json:"active_flows"`
		Note             string
		State            string
		Detail           string `json:"state_detail"`
		Apps             []struct {
			Name, Category string
			Flows, Bytes   int64
			LastSeen       time.Time `json:"last_seen"`
		}
	}
	if err := json.Unmarshal(out, &st); err != nil {
		return err
	}
	switch {
	case !st.Enabled:
		fmt.Println("App Identification: off")
	case st.Running:
		fmt.Printf("App Identification: running, %d connections being identified\n", st.ActiveFlows)
	default:
		fmt.Println("App Identification: NOT RUNNING")
	}
	if st.State != "" {
		fmt.Printf("Traffic: %s: %s\n", strings.ToUpper(st.State), st.Detail)
	}
	if st.Note != "" {
		fmt.Println(st.Note)
	}
	if len(st.Apps) == 0 {
		return nil
	}
	fmt.Println()
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "APPLICATION\tCATEGORY\tCONNECTIONS\tBYTES\tLAST SEEN")
	for _, a := range st.Apps {
		fmt.Fprintf(tw, "%s\t%s\t%d\t%s\t%s\n", a.Name, a.Category, a.Flows, humanBytes(a.Bytes), a.LastSeen.Local().Format("Jan 02 15:04:05"))
	}
	return tw.Flush()
}

// showAppCatalog lists the applications App Identification can identify.
func showAppCatalog(q string) error {
	out, err := call("GET", "/v1/apps/catalog?q="+url.QueryEscape(q), nil)
	if err != nil {
		return err
	}
	var apps []struct{ Name, Category string }
	if err := json.Unmarshal(out, &apps); err != nil {
		return err
	}
	if len(apps) == 0 {
		fmt.Println("no application matches")
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "APPLICATION\tCATEGORY")
	for _, a := range apps {
		fmt.Fprintf(tw, "%s\t%s\n", a.Name, a.Category)
	}
	tw.Flush()
	fmt.Printf("%d applications\n", len(apps))
	return nil
}

// humanBytes writes n as B, KB, MB, GB (powers of 1024).
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}

// showAppCategories lists App Identification's categories as rules name them.
func showAppCategories() error {
	out, err := call("GET", "/v1/apps/categories", nil)
	if err != nil {
		return err
	}
	var cats []struct {
		Name, Ref string
		Apps      int
	}
	if err := json.Unmarshal(out, &cats); err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "CATEGORY\tIN RULES\tAPPLICATIONS")
	for _, c := range cats {
		fmt.Fprintf(tw, "%s\t%s\t%d\n", c.Name, c.Ref, c.Apps)
	}
	return tw.Flush()
}

func showIPS() error {
	out, err := call("GET", "/v1/ips", nil)
	if err != nil {
		return err
	}
	var st struct {
		Enabled, InUse, Installed, Running, Loading bool
		Loaded                                      int
		State                                       string
		Detail                                      string `json:"state_detail"`
		MemTotal                                    uint64 `json:"mem_total"`
		Rules                                       []string
		Exceptions                                  []struct {
			Name, SID, Action          string
			Rules, Source, Destination []string
			Hits                       *uint64
			Inactive                   bool
		}
		Signatures struct {
			Source, Version string
			Updated, Built  time.Time
			LastAttempt     time.Time `json:"last_attempt"`
			LastError       string    `json:"last_error"`
			Signatures      int
			Counts          map[string]int
			Disabled        int
		}
	}
	if err := json.Unmarshal(out, &st); err != nil {
		return err
	}
	onoff := map[bool]string{true: "on", false: "off"}
	engine := "stopped"
	switch {
	case st.Running && st.Loading && st.Loaded > 0:
		engine = fmt.Sprintf("running, loading signatures (%d active until the new set is ready)", st.Loaded)
	case st.Running && st.Loading:
		engine = "starting (loading signatures)"
	case st.Running:
		engine = fmt.Sprintf("running, %d signatures loaded", st.Loaded)
	case !st.Installed:
		engine = "not installed yet (an upgrade installs Suricata in the background)"
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintf(tw, "IPS\t%s (system ips)\n", onoff[st.Enabled])
	fmt.Fprintf(tw, "engine\tSuricata, %s\n", engine)
	fmt.Fprintf(tw, "inspection\t%s: %s\n", strings.ToUpper(st.State), st.Detail)
	if st.MemTotal > 0 {
		fmt.Fprintf(tw, "memory\t%.1f GB (4 GB recommended)\n", float64(st.MemTotal)/(1<<30))
	}
	sig := st.Signatures
	if sig.Source == "" {
		sig.Source = "none yet"
	}
	src := sig.Source
	if sig.Version != "" {
		src += ", version " + sig.Version
	}
	fmt.Fprintf(tw, "signatures\t%d (%s)\n", sig.Signatures, src)
	if sig.Signatures > 0 {
		fmt.Fprintf(tw, "\tcritical %d, major %d, minor %d, informational %d; %d disabled\n",
			sig.Counts["critical"], sig.Counts["major"], sig.Counts["minor"], sig.Counts["informational"], sig.Disabled)
	}
	ts := func(t time.Time) string {
		if t.IsZero() {
			return "never"
		}
		return t.Local().Format("2006-01-02 15:04")
	}
	fmt.Fprintf(tw, "last update\t%s (checked daily; request ips update for now)\n", ts(sig.Updated))
	if sig.LastError != "" {
		fmt.Fprintf(tw, "last attempt\t%s failed: %s\n", ts(sig.LastAttempt), sig.LastError)
	}
	if len(st.Rules) == 0 {
		fmt.Fprintf(tw, "rules\tnone (set rule NAME ips-profile default)\n")
	} else {
		fmt.Fprintf(tw, "rules\t%s\n", strings.Join(st.Rules, ", "))
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if len(st.Exceptions) > 0 {
		fmt.Println()
		tw = tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "EXCEPTION\tSID\tRULES\tSOURCE\tDESTINATION\tACTION\tPACKETS")
		for _, e := range st.Exceptions {
			action := e.Action
			if e.Inactive {
				action += " (inactive: no free code yet; commit again once the rules are loaded)"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", e.Name, e.SID, anyList(e.Rules), anyList(e.Source), anyList(e.Destination), action, count(e.Hits))
		}
		return tw.Flush()
	}
	return nil
}

// anyList shows an exception's scope list ("any" when empty).
func anyList(xs []string) string {
	if len(xs) == 0 {
		return "any"
	}
	return strings.Join(xs, ",")
}

func requestIPSUpdate() error {
	fmt.Println("downloading ET Open signatures...")
	out, err := call("POST", "/v1/ips/update", nil)
	if err != nil {
		return err
	}
	var st struct {
		Version    string
		Signatures int
	}
	json.Unmarshal(out, &st)
	fmt.Printf("IPS signatures updated: %d (version %s); the engine reloads them in the background\n", st.Signatures, st.Version)
	return nil
}

func showStatistics(window string) error {
	if window != "1h" && window != "24h" && window != "7d" {
		return fmt.Errorf("show statistics 1h, 24h or 7d")
	}
	out, err := call("GET", "/v1/stats?window="+window, nil)
	if err != nil {
		return err
	}
	var v struct {
		Window     string
		Step       int
		Samples    int
		AppID      bool `json:"app_id"`
		IPS        bool
		Interfaces []struct {
			Name     string
			InBytes  int64   `json:"in_bytes"`
			OutBytes int64   `json:"out_bytes"`
			PeakBps  float64 `json:"peak_bps"`
		}
		Apps, Hosts []struct {
			Name    string
			Bytes   int64
			Flows   int64 `json:"connections"`
			Threats int
		}
		Threats struct {
			Blocked, Alerted int
			Series           map[string][]int
			Top              []struct {
				SID                 int
				Signature, Severity string
				Count               int
			}
		}
	}
	if err := json.Unmarshal(out, &v); err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	defer tw.Flush()
	span := map[string]float64{"1h": 3600, "24h": 86400, "7d": 604800}[window]
	bps := func(b float64) string {
		units := []string{"b/s", "Kb/s", "Mb/s", "Gb/s"}
		i := 0
		for b >= 1000 && i < len(units)-1 {
			b /= 1000
			i++
		}
		return fmt.Sprintf("%.1f %s", b, units[i])
	}
	if v.Samples == 0 {
		fmt.Fprintln(tw, "No statistics for this period yet: a sample is taken every minute.")
		return nil
	}
	fmt.Fprintf(tw, "Last %s (%d minute samples)\n\n", window, v.Samples)
	fmt.Fprintln(tw, "INTERFACE\tIN\tOUT\tAVERAGE\tPEAK")
	for _, f := range v.Interfaces {
		in, outb := f.InBytes, f.OutBytes
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", f.Name, humanBytes(in), humanBytes(outb), bps(float64(in+outb)*8/span), bps(f.PeakBps))
	}
	fmt.Fprintln(tw)
	if !v.AppID {
		fmt.Fprintln(tw, "Applications and hosts: App Identification is off (set system app-identification on)")
	} else {
		fmt.Fprintln(tw, "APPLICATION\tBYTES\tCONNECTIONS")
		for _, a := range v.Apps {
			fmt.Fprintf(tw, "%s\t%s\t%d\n", a.Name, humanBytes(a.Bytes), a.Flows)
		}
		fmt.Fprintln(tw)
		fmt.Fprintln(tw, "HOST\tBYTES\tCONNECTIONS\tTHREATS")
		for _, h := range v.Hosts {
			fmt.Fprintf(tw, "%s\t%s\t%d\t%d\n", h.Name, humanBytes(h.Bytes), h.Flows, h.Threats)
		}
	}
	fmt.Fprintln(tw)
	sum := func(xs []int) (n int) {
		for _, x := range xs {
			n += x
		}
		return
	}
	fmt.Fprintf(tw, "Threats: %d blocked, %d alerted (critical %d, major %d, minor %d, informational %d)\n",
		v.Threats.Blocked, v.Threats.Alerted, sum(v.Threats.Series["critical"]), sum(v.Threats.Series["major"]),
		sum(v.Threats.Series["minor"]), sum(v.Threats.Series["informational"]))
	if len(v.Threats.Top) > 0 {
		fmt.Fprintln(tw, "SID\tSEVERITY\tMATCHES\tSIGNATURE")
		for _, s := range v.Threats.Top {
			fmt.Fprintf(tw, "%d\t%s\t%d\t%s\n", s.SID, s.Severity, s.Count, s.Signature)
		}
	}
	return nil
}
