// Package nft applies rulesets and set changes through the nft binary.
// Every call is one `nft -f -` transaction: all of it applies or none does.
package nft

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
	"sync"
)

// Runner applies nftables scripts.
type Runner interface {
	// Check parses and validates a script without applying it.
	Check(script string) error
	// Apply runs a script as one atomic transaction.
	Apply(script string) error
}

// Exec runs the real nft binary.
type Exec struct{ Path string }

func (e Exec) run(script string, args ...string) error {
	path := e.Path
	if path == "" {
		path = "nft"
	}
	cmd := exec.Command(path, append(args, "-f", "-")...)
	cmd.Stdin = strings.NewReader(script)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nft: %v: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// Check implements Runner.
func (e Exec) Check(script string) error { return e.run(script, "-c") }

// Apply implements Runner.
func (e Exec) Apply(script string) error { return e.run(script) }

// Fake records scripts instead of running them. For tests.
type Fake struct {
	mu      sync.Mutex
	Applied []string
	// FailOn makes Check and Apply fail when the script contains it.
	FailOn string
	// ApplyErr, when set, is called by Apply (after Check passes) and fails
	// it when it returns an error: a ruleset that checks but won't load.
	ApplyErr func(script string) error
}

// Check implements Runner.
func (f *Fake) Check(script string) error {
	if f.FailOn != "" && strings.Contains(script, f.FailOn) {
		return fmt.Errorf("fake nft: rejected script")
	}
	return nil
}

// Apply implements Runner.
func (f *Fake) Apply(script string) error {
	if err := f.Check(script); err != nil {
		return err
	}
	if f.ApplyErr != nil {
		if err := f.ApplyErr(script); err != nil {
			return err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Applied = append(f.Applied, script)
	return nil
}

// Last returns the most recently applied script.
func (f *Fake) Last() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.Applied) == 0 {
		return ""
	}
	return f.Applied[len(f.Applied)-1]
}
