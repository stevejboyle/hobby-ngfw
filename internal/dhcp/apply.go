package dhcp

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Runner applies Kea configuration and reads leases.
type Runner interface {
	// Available reports whether Kea is installed.
	Available() bool
	// Options returns the appliance facts Compile needs.
	Options() Options
	// Check validates a config without applying it (kea-dhcp4 -t).
	Check(conf string) error
	// Apply writes the config and starts, restarts or stops Kea as needed.
	// It never blocks on systemd (ngfwd starts before networking).
	Apply(r *Result) error
	// Running reports whether Kea is running.
	Running() bool
	// Leases returns Kea's leases.
	Leases() ([]RawLease, error)
}

// RawLease is a lease as Kea reports it.
type RawLease struct {
	Address  string `json:"ip-address"`
	MAC      string `json:"hw-address"`
	Hostname string `json:"hostname"`
	SubnetID int    `json:"subnet-id"`
	CLTT     int64  `json:"cltt"`      // last client contact, Unix time
	Valid    int64  `json:"valid-lft"` // seconds from CLTT
	State    int    `json:"state"`     // 0 active, 1 declined, 2 expired-reclaimed
}

// Noop is used where Kea isn't managed (development machines).
type Noop struct{}

func (Noop) Available() bool     { return false }
func (Noop) Options() Options    { return Options{} }
func (Noop) Check(string) error  { return nil }
func (Noop) Apply(*Result) error { return fmt.Errorf("Kea is not managed on this system") }
func (Noop) Running() bool       { return false }
func (Noop) Leases() ([]RawLease, error) {
	return nil, fmt.Errorf("Kea is not managed on this system")
}

// Exec drives the installed Kea.
type Exec struct {
	Binary   string // default /usr/sbin/kea-dhcp4
	Conf     string // default ConfPath
	Socket   string // default SocketPath
	NetifDir string // networkd's link state, default /run/systemd/netif/links
	Systemd  func(args ...string) error
	// Passwd is the account file to find Kea's user in (default
	// /etc/passwd); tests point it elsewhere.
	Passwd string
}

// keaIDs is Kea's user and group.
type keaIDs struct{ uid, gid int }

// keaIDs reads Kea's account (_kea) from the passwd file.
func (e Exec) keaIDs() (keaIDs, error) {
	body, err := os.ReadFile(or(e.Passwd, "/etc/passwd"))
	if err != nil {
		return keaIDs{}, err
	}
	for _, line := range strings.Split(string(body), "\n") {
		f := strings.Split(line, ":")
		if len(f) >= 4 && f[0] == "_kea" {
			uid, err1 := strconv.Atoi(f[2])
			gid, err2 := strconv.Atoi(f[3])
			if err1 == nil && err2 == nil {
				return keaIDs{uid, gid}, nil
			}
		}
	}
	return keaIDs{}, fmt.Errorf("Kea's user _kea isn't on this system (is kea-dhcp4-server installed?)")
}

const unit = "kea-dhcp4-server"

func (e Exec) binary() string { return or(e.Binary, "/usr/sbin/kea-dhcp4") }
func (e Exec) conf() string   { return or(e.Conf, ConfPath) }
func (e Exec) socket() string { return or(e.Socket, SocketPath) }

func or(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func (e Exec) systemctl(args ...string) error {
	if e.Systemd != nil {
		return e.Systemd(args...)
	}
	out, err := exec.Command("systemctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Available reports whether kea-dhcp4 is installed.
func (e Exec) Available() bool {
	_, err := os.Stat(e.binary())
	return err == nil
}

// Options finds the hooks directory and the firewall's upstream DNS.
func (e Exec) Options() Options {
	o := Options{DNS: e.upstreamDNS()}
	if m, _ := filepath.Glob("/usr/lib/*/kea/hooks/" + LeaseHook); len(m) > 0 {
		o.HooksDir = filepath.Dir(m[0])
	}
	return o
}

// upstreamDNS returns the DNS servers networkd has for outside (static or
// learned by DHCP), else for mgmt, else /etc/resolv.conf's.
func (e Exec) upstreamDNS() []string {
	dir := or(e.NetifDir, "/run/systemd/netif/links")
	byIface := map[string][]string{}
	files, _ := os.ReadDir(dir)
	for _, f := range files {
		idx, err := strconv.Atoi(f.Name())
		if err != nil {
			continue
		}
		ifi, err := net.InterfaceByIndex(idx)
		if err != nil {
			continue
		}
		body, _ := os.ReadFile(filepath.Join(dir, f.Name()))
		for _, line := range strings.Split(string(body), "\n") {
			if v, ok := strings.CutPrefix(line, "DNS="); ok {
				byIface[ifi.Name] = append(byIface[ifi.Name], strings.Fields(v)...)
			}
		}
	}
	for _, nic := range []string{"outside", "mgmt"} {
		if d := ipv4Only(byIface[nic]); len(d) > 0 {
			return d
		}
	}
	var out []string
	body, _ := os.ReadFile("/etc/resolv.conf")
	sc := bufio.NewScanner(bytes.NewReader(body))
	for sc.Scan() {
		if f := strings.Fields(sc.Text()); len(f) == 2 && f[0] == "nameserver" {
			out = append(out, f[1])
		}
	}
	return ipv4Only(out)
}

// Check runs kea-dhcp4 -t on the config, as Kea's own user.
//
// Debian's AppArmor profile lets kea-dhcp4 read only /etc/kea, and denies it
// root's permission overrides, while /etc/kea belongs to _kea (mode 0750):
// run as root, kea-dhcp4 can't even enter it. So the check file goes in
// /etc/kea, owned by _kea, and the check runs as _kea.
func (e Exec) Check(conf string) error {
	ids, err := e.keaIDs()
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(e.conf()), ".sjb-check-*.conf")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	f.WriteString(conf)
	f.Chown(ids.uid, ids.gid)
	f.Close()
	cmd := exec.Command(e.binary(), "-t", f.Name())
	if ids.uid != os.Getuid() {
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(ids.uid), Gid: uint32(ids.gid)}}
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", checkError(string(out), f.Name(), err))
	}
	return nil
}

// Apply writes the config if it changed and has systemd run Kea only while
// something is served.
func (e Exec) Apply(r *Result) error {
	ids, err := e.keaIDs()
	if err != nil {
		return err
	}
	cur, _ := os.ReadFile(e.conf())
	changed := string(cur) != r.Conf
	if !changed {
		// Right content but not Kea's to read (Debian ships it root:root).
		if st, err := os.Stat(e.conf()); err == nil {
			if sys, ok := st.Sys().(*syscall.Stat_t); ok && (int(sys.Uid) != ids.uid || int(sys.Gid) != ids.gid) {
				changed = true
			}
		}
	}
	if changed {
		if err := writeConf(e.conf(), r.Conf, ids); err != nil {
			return err
		}
	}
	active := e.systemctl("is-active", "--quiet", unit) == nil
	switch {
	case r.Enabled():
		if err := e.systemctl("enable", "--quiet", unit); err != nil {
			return err
		}
		if changed || !active {
			return e.systemctl("--no-block", "restart", unit)
		}
	case active || e.systemctl("is-enabled", "--quiet", unit) == nil:
		return e.systemctl("--no-block", "disable", "--now", "--quiet", unit)
	}
	return nil
}

// Running reports whether systemd has Kea running.
func (e Exec) Running() bool { return e.systemctl("is-active", "--quiet", unit) == nil }

// Leases asks Kea for every lease over its control socket.
func (e Exec) Leases() ([]RawLease, error) {
	var resp struct {
		Result    int    `json:"result"`
		Text      string `json:"text"`
		Arguments struct {
			Leases []RawLease `json:"leases"`
		} `json:"arguments"`
	}
	if err := command(e.socket(), "lease4-get-all", &resp); err != nil {
		return nil, err
	}
	switch resp.Result {
	case 0:
		return resp.Arguments.Leases, nil
	case 3: // empty
		return []RawLease{}, nil
	}
	return nil, fmt.Errorf("Kea: %s", resp.Text)
}

// command sends one command to Kea's control socket and decodes the reply.
func command(path, cmd string, out any) error {
	c, err := net.DialTimeout("unix", path, 2*time.Second)
	if err != nil {
		return fmt.Errorf("Kea isn't answering (is it running?): %v", err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := fmt.Fprintf(c, `{"command": %q}`, cmd); err != nil {
		return err
	}
	// Kea answers with one JSON document and closes the connection.
	body, err := io.ReadAll(c)
	if err != nil && len(body) == 0 {
		return err
	}
	return json.Unmarshal(body, out)
}

// writeConf replaces Kea's config, owned by Kea's user.
func writeConf(path, data string, ids keaIDs) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".sjb-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o640); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chown(ids.uid, ids.gid); err != nil {
		tmp.Close()
		return fmt.Errorf("making %s Kea's: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// checkError picks Kea's reason out of kea-dhcp4 -t output: its "Error
// encountered" line, else its last ERROR log message, else the last line.
func checkError(out, file string, err error) string {
	clean := func(m string) string { return strings.TrimSpace(strings.ReplaceAll(m, file, "dhcp config")) }
	var lastErr, last string
	for _, line := range strings.Split(out, "\n") {
		if msg, ok := strings.CutPrefix(line, "Error encountered: "); ok {
			return clean(msg)
		}
		if i := strings.Index(line, " ERROR "); i >= 0 {
			msg := line[i+7:]
			if j := strings.Index(msg, "] "); j >= 0 {
				msg = msg[j+2:]
			}
			lastErr = msg
		}
		if strings.TrimSpace(line) != "" {
			last = line
		}
	}
	switch {
	case lastErr != "":
		return clean(lastErr)
	case last != "":
		return clean(last)
	}
	return fmt.Sprintf("kea-dhcp4 -t: %v", err)
}
