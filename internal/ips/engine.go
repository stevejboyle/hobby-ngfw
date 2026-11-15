package ips

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Paths under Engine.Dir.
const (
	RulesFile  = "rules/sjb.rules"
	ClassFile  = "rules/classification.config"
	CacheFile  = "cache/emerging.rules.tar.gz"
	StatusFile = "status.json"
)

// Unit is the systemd unit running Suricata.
const Unit = "sjb-ips.service"

// Status is what `show ips` and the web UI report about the signatures.
type Status struct {
	// Source is "ET Open" once downloaded; "test signatures only" before.
	Source      string    `json:"source"`
	Version     string    `json:"version,omitempty"` // ET Open's rule set version
	Updated     time.Time `json:"updated,omitempty"` // last successful download
	Built       time.Time `json:"built,omitempty"`   // rules file last written
	Signatures  int       `json:"signatures"`
	Counts      Counts    `json:"counts"`
	Disabled    int       `json:"disabled"` // signatures left out by config
	LastAttempt time.Time `json:"last_attempt,omitempty"`
	LastError   string    `json:"last_error,omitempty"`
}

// Engine manages the signatures on disk and asks Suricata to reload them.
type Engine struct {
	Dir    string // /var/lib/sjb-os/ips
	URL    string // default ETOpenURL
	Client *http.Client
	// Reload makes a running Suricata load the new rules (nil: nothing).
	Reload func() error
	Now    func() time.Time

	mu sync.Mutex // serialises builds and updates
}

func (e *Engine) path(rel string) string { return filepath.Join(e.Dir, filepath.FromSlash(rel)) }

func (e *Engine) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

// Status reads the recorded status (zero before anything was built).
func (e *Engine) Status() Status {
	var st Status
	if b, err := os.ReadFile(e.path(StatusFile)); err == nil {
		json.Unmarshal(b, &st)
	}
	if st.Counts == nil {
		st.Counts = Counts{}
	}
	return st
}

func (e *Engine) saveStatus(st Status) error {
	b, _ := json.MarshalIndent(st, "", "  ")
	return writeFile(e.path(StatusFile), append(b, '\n'), 0o644)
}

// Installed reports whether a rules file exists for Suricata to load.
func (e *Engine) Installed() bool {
	_, err := os.Stat(e.path(RulesFile))
	return err == nil
}

// Update downloads the rule set, keeps it, and rebuilds the rules file.
// On a failed download the rules in place stay, and the status says why.
func (e *Engine) Update(ctx context.Context, disabled map[int]bool) (Status, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	st := e.Status()
	st.LastAttempt = e.now().UTC()
	url := e.URL
	if url == "" {
		url = ETOpenURL
	}
	client := e.Client
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Minute}
	}
	tgz, err := Download(ctx, client, url)
	if err == nil {
		_, err = Unpack(tgz)
	}
	if err != nil {
		st.LastError = err.Error()
		e.saveStatus(st)
		return st, fmt.Errorf("downloading signatures: %w", err)
	}
	if err := writeFile(e.path(CacheFile), tgz, 0o644); err != nil {
		return st, err
	}
	st.Updated = st.LastAttempt
	st.LastError = ""
	st.Version = versionOf(ctx, client, url)
	if err := e.saveStatus(st); err != nil {
		return st, err
	}
	return e.build(disabled)
}

// versionOf reads the rule set's version.txt beside the tarball ("" if
// unavailable).
func versionOf(ctx context.Context, client *http.Client, url string) string {
	u := url[:strings.LastIndex(url, "/")+1] + "version.txt"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return ""
	}
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	var b [64]byte
	n, _ := resp.Body.Read(b[:])
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	return strings.TrimSpace(string(b[:n]))
}

// Build rewrites the rules file from the kept download (or the test
// signatures alone when nothing has been downloaded), leaving out the
// disabled signatures, and reloads Suricata.
func (e *Engine) Build(disabled map[int]bool) (Status, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.build(disabled)
}

func (e *Engine) build(disabled map[int]bool) (Status, error) {
	st := e.Status()
	files := map[string][]byte{}
	if tgz, err := os.ReadFile(e.path(CacheFile)); err == nil {
		if files, err = Unpack(tgz); err != nil {
			return st, fmt.Errorf("the kept rule set is unreadable (run an update): %w", err)
		}
		st.Source = "ET Open"
	} else if errors.Is(err, os.ErrNotExist) {
		st.Source = "test signatures only"
	} else {
		return st, err
	}
	rules, counts := Process(files, disabled)
	class := files["classification.config"]
	if class == nil {
		class = []byte("config classification: misc-activity,Misc activity,3\n")
	}
	st.Counts = counts
	st.Signatures = counts.Total()
	st.Disabled = len(disabled)
	// Unchanged rules (a daily check with nothing new, a restart): no
	// rewrite, no reload. Loading the full set takes Suricata a while.
	if old, err := os.ReadFile(e.path(RulesFile)); err == nil && bytes.Equal(old, rules) {
		return st, e.saveStatus(st)
	}
	if err := writeFile(e.path(ClassFile), class, 0o644); err != nil {
		return st, err
	}
	if err := writeFile(e.path(RulesFile), rules, 0o644); err != nil {
		return st, err
	}
	os.Remove(e.path("rules/groot.rules")) // its name before 0.8.0
	st.Built = e.now().UTC()
	if err := e.saveStatus(st); err != nil {
		return st, err
	}
	if e.Reload != nil {
		if err := e.Reload(); err != nil {
			return st, fmt.Errorf("reloading Suricata: %w", err)
		}
	}
	return st, nil
}

func writeFile(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
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
