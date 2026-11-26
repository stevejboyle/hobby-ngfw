package ips

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/stevejboyle/sjb-os/internal/compiler"
	"github.com/stevejboyle/sjb-os/internal/sysd"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Runner is what ngfwd needs from the appliance to run the IPS. Tests and
// development builds use Noop.
type Runner interface {
	// Available reports whether Suricata is installed.
	Available() bool
	// Start enables and starts the engine; Stop stops and disables it.
	// Neither blocks on systemd.
	Start() error
	Stop() error
	Running() bool
	// ReloadRules has the running engine load the rules file again and
	// returns only once it has: nil means Suricata finished loading a
	// rules file at least as new as the one on disk when it was called.
	// It blocks for as long as the load takes (seconds to minutes).
	ReloadRules() error
	// MemTotal is the appliance's RAM in bytes (0 if unknown).
	MemTotal() uint64
	// ConnMark is the ct mark of the connection a packet with this
	// 5-tuple belongs to, in either direction. decrypted: it is TLS
	// decryption's cleartext loop leg (conntrack zone LoopZone), which
	// carries the rule; the client's own connection, with the same tuple in
	// the default zone, doesn't.
	ConnMark(proto, src string, sport int, dst string, dport int) (mark uint32, decrypted, ok bool)
	// LoadedRules is how many signatures the running engine has active
	// (false when it can't tell: not running, or still starting).
	LoadedRules() (int, bool)
}

// Noop runs nothing.
type Noop struct{}

func (Noop) Available() bool                                                { return false }
func (Noop) Start() error                                                   { return nil }
func (Noop) Stop() error                                                    { return nil }
func (Noop) Running() bool                                                  { return false }
func (Noop) ReloadRules() error                                             { return errors.New("no IPS engine") }
func (Noop) MemTotal() uint64                                               { return 0 }
func (Noop) ConnMark(string, string, int, string, int) (uint32, bool, bool) { return 0, false, false }
func (Noop) LoadedRules() (int, bool)                                       { return 0, false }

// CommandSocket is Suricata's unix-command socket (suricata.yaml).
const CommandSocket = "/run/sjb-ips/suricata-command.socket"

// Exec runs Suricata under systemd.
type Exec struct {
	Suricata  string // default /usr/bin/suricata
	Conntrack string // default conntrack
	Socket    string // default CommandSocket
}

// LoadedRules asks the engine over its command socket (ruleset-stats).
func (e Exec) LoadedRules() (int, bool) {
	path := e.Socket
	if path == "" {
		path = CommandSocket
	}
	c, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		return 0, false
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	dec := json.NewDecoder(c)
	var hello struct{ Return string }
	if _, err := c.Write([]byte(`{"version": "0.2"}` + "\n")); err != nil || dec.Decode(&hello) != nil || hello.Return != "OK" {
		return 0, false
	}
	var resp struct {
		Return  string
		Message []struct {
			Loaded int `json:"rules_loaded"`
		}
	}
	if _, err := c.Write([]byte(`{"command": "ruleset-stats"}` + "\n")); err != nil || dec.Decode(&resp) != nil || resp.Return != "OK" || len(resp.Message) == 0 {
		return 0, false
	}
	return resp.Message[0].Loaded, true
}

func (e Exec) Available() bool {
	p := e.Suricata
	if p == "" {
		p = "/usr/bin/suricata"
	}
	_, err := os.Stat(p)
	return err == nil
}

func systemctl(args ...string) error {
	out, err := exec.Command("systemctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (Exec) Start() error {
	return systemctl("enable", "--now", "--no-block", Unit)
}

func (Exec) Stop() error {
	return systemctl("disable", "--now", "--no-block", Unit)
}

func (Exec) Running() bool {
	return sysd.Active(Unit)
}

// ReloadRules asks Suricata over its command socket to reload the rules
// file and waits for its answer. Suricata handles socket commands one at a
// time, and its blocking reload reads the rules file after the command
// arrives and answers "done" only once the new rules are in use (checked
// against Suricata 7.0: a file replaced during an earlier reload was
// picked up by the next request). Anything but OK is an error.
func (e Exec) ReloadRules() error {
	path := e.Socket
	if path == "" {
		path = CommandSocket
	}
	c, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		return fmt.Errorf("Suricata's command socket: %w", err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Minute))
	dec := json.NewDecoder(c)
	var hello struct{ Return string }
	if _, err := c.Write([]byte(`{"version": "0.2"}` + "\n")); err != nil || dec.Decode(&hello) != nil || hello.Return != "OK" {
		return errors.New("Suricata's command socket didn't answer")
	}
	var resp struct {
		Return  string
		Message any
	}
	if _, err := c.Write([]byte(`{"command": "reload-rules"}` + "\n")); err != nil {
		return err
	}
	if err := dec.Decode(&resp); err != nil {
		return fmt.Errorf("reload-rules: %w", err)
	}
	if resp.Return != "OK" {
		return fmt.Errorf("reload-rules: %v", resp.Message)
	}
	return nil
}

func (Exec) MemTotal() uint64 {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "MemTotal:"); ok {
			kb, _ := strconv.ParseUint(strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(v), "kB")), 10, 64)
			return kb * 1024
		}
	}
	return 0
}

var markRE = regexp.MustCompile(`\bmark=(\d+)`)

// LoopZone is TLS decryption's conntrack zone.
const LoopZone = compiler.LoopCTZone

func (e Exec) ConnMark(proto, src string, sport int, dst string, dport int) (uint32, bool, bool) {
	// Decrypted traffic has two entries with this tuple: the client's own
	// connection (default zone, no rule) and the loop leg the rules judged.
	m, ok := e.connMark(0, proto, src, sport, dst, dport)
	if !ok || m>>16 == 0 {
		if lm, lok := e.connMark(LoopZone, proto, src, sport, dst, dport); lok {
			return lm, true, true
		}
	}
	return m, false, ok
}

func (e Exec) connMark(zone int, proto, src string, sport int, dst string, dport int) (uint32, bool) {
	path := e.Conntrack
	if path == "" {
		path = "conntrack"
	}
	try := func(s string, sp int, d string, dp int) (uint32, bool) {
		// conntrack -G takes no zone (conntrack-tools 1.4.8): list the zone,
		// filtered to the original-direction tuple, instead.
		args := []string{"-G", "-p", proto, "-s", s, "-d", d}
		if zone != 0 {
			args = []string{"-L", "-w", strconv.Itoa(zone), "-p", proto, "-s", s, "-d", d}
		}
		if proto == "tcp" || proto == "udp" {
			args = append(args, "--sport", strconv.Itoa(sp), "--dport", strconv.Itoa(dp))
		}
		out, err := exec.Command(path, args...).Output()
		if err != nil {
			return 0, false
		}
		m := markRE.FindSubmatch(bytes.TrimSpace(out))
		if m == nil {
			return 0, false
		}
		n, err := strconv.ParseUint(string(m[1]), 10, 32)
		return uint32(n), err == nil
	}
	if m, ok := try(src, sport, dst, dport); ok {
		return m, true
	}
	return try(dst, dport, src, sport) // a reply-direction packet
}
