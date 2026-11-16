package decrypt

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"time"
)

// Status is what tlsd reports on its socket (GET /v1/status).
type Status struct {
	Mode       string           `json:"mode"`
	Started    time.Time        `json:"started"`
	CA         CAInfo           `json:"ca"`
	Rules      int              `json:"rules"`
	Exclusions int              `json:"exclusion_names"`
	Builtin    bool             `json:"builtin_exclusions"`
	Counts     map[string]int64 `json:"counts"`
	Active     int64            `json:"active"`
	Learned    int              `json:"learned"`
	LoadError  string           `json:"load_error,omitempty"`
}

// Runner is how ngfwd runs tlsd. Tests fake it.
type Runner interface {
	// Available: tlsd is installed (a bundle shipped it).
	Available() bool
	Start() error
	Stop() error
	Running() bool
	// Status asks the running tlsd; an error means it isn't answering.
	Status() (Status, error)
	// Reload has tlsd re-read its policy and CA.
	Reload() error
	Learned() ([]LearnedEntry, error)
	ClearLearned() (int, error)
	// Owner is who the CA files belong to (tlsd's user).
	Owner() Owner
}

// Unit is tlsd's systemd unit.
const Unit = "sjb-tlsd.service"

// User is the account tlsd runs as (created by sjb-migrate).
const User = "sjb-tls"

// Exec runs tlsd with systemd and talks to it on its socket.
type Exec struct {
	Binary string // default /usr/local/sbin/tlsd
	Socket string // default /run/sjb-tlsd/tlsd.sock
}

func (e Exec) binary() string {
	if e.Binary == "" {
		return "/usr/local/sbin/tlsd"
	}
	return e.Binary
}

func (e Exec) socket() string {
	if e.Socket == "" {
		return "/run/sjb-tlsd/tlsd.sock"
	}
	return e.Socket
}

func (e Exec) Available() bool {
	if _, err := os.Stat(e.binary()); err != nil {
		return false
	}
	_, err := user.Lookup(User)
	return err == nil
}

func systemctl(args ...string) error {
	out, err := exec.Command("systemctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (Exec) Start() error { return systemctl("enable", "--now", "--no-block", Unit) }
func (Exec) Stop() error  { return systemctl("disable", "--now", "--no-block", Unit) }
func (Exec) Running() bool {
	return exec.Command("systemctl", "is-active", "--quiet", Unit).Run() == nil
}

func (e Exec) client() *http.Client {
	return &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", e.socket())
		}}}
}

func (e Exec) call(method, path string, v any) error {
	req, err := http.NewRequest(method, "http://tlsd"+path, nil)
	if err != nil {
		return err
	}
	resp, err := e.client().Do(req)
	if err != nil {
		return fmt.Errorf("tlsd isn't answering: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("tlsd: %s: %s", resp.Status, strings.TrimSpace(string(data)))
	}
	if v == nil {
		return nil
	}
	return json.Unmarshal(data, v)
}

func (e Exec) Status() (Status, error) {
	var s Status
	err := e.call("GET", "/v1/status", &s)
	return s, err
}

func (e Exec) Reload() error { return e.call("POST", "/v1/reload", nil) }

func (e Exec) Learned() ([]LearnedEntry, error) {
	var l []LearnedEntry
	err := e.call("GET", "/v1/learned", &l)
	return l, err
}

func (e Exec) ClearLearned() (int, error) {
	var r struct{ Cleared int }
	err := e.call("POST", "/v1/learned/clear", &r)
	return r.Cleared, err
}

func (Exec) Owner() Owner {
	u, err := user.Lookup(User)
	if err != nil {
		return NoOwner
	}
	uid, err1 := strconv.Atoi(u.Uid)
	gid, err2 := strconv.Atoi(u.Gid)
	if err1 != nil || err2 != nil {
		return NoOwner
	}
	return Owner{UID: uid, GID: gid}
}
