// Package nicaddr applies the config's addresses on the appliance's physical
// data-plane NICs (inside, outside).
//
// First boot gives each NIC a systemd-networkd file, 20-<nic>.network, from
// the deployment settings (a static address, or DHCP). When the config sets
// an address for the NIC, ngfwd writes 10-<nic>-sjb.network beside it.
// networkd uses only the first matching .network file in lexical order, so
// ngfwd's file takes over completely: the configured address, no DHCP, and
// the deployment file's DNS settings. Removing the address removes the file,
// and networkd goes back to the deployment settings.
//
// The management NIC is never touched, so a commit can't cut off management.
package nicaddr

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// State reports one NIC whose address the config sets.
type State struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	Applied bool   `json:"applied"`
	Error   string `json:"error,omitempty"`
}

// Mode says how far Sync goes in applying changed overrides.
type Mode int

const (
	// Deferred writes the files only; networkctl runs on a later pass.
	// ngfwd starts before networkd, and systemd waits for ngfwd's socket,
	// so starting must not call networkctl or wait for addresses.
	Deferred Mode = iota
	// Background has networkd apply pending changes without waiting for
	// the addresses (ngfwd's periodic pass).
	Background
	// Commit applies changes and waits briefly for the addresses, so routes
	// via the new networks can go in at the same commit.
	Commit
)

// Syncer makes the NICs' networkd overrides match want (NIC name -> CIDR).
// NICs it manages but that are missing from want go back to the deployment
// settings.
type Syncer interface {
	Sync(want map[string]string, mode Mode) ([]State, error)
}

// Noop never touches the system and reports nothing (development, where the
// NICs' addresses are informational).
type Noop struct{}

// Sync does nothing.
func (Noop) Sync(map[string]string, Mode) ([]State, error) { return nil, nil }

// Networkd writes networkd override files and reconfigures the NICs.
type Networkd struct {
	Dir  string   // /etc/systemd/network
	NICs []string // NICs ngfwd may manage, e.g. inside, outside
	// Networkctl runs networkctl with args; tests replace it.
	Networkctl func(args ...string) error
	// HasAddr reports whether the kernel shows addr on nic; in Commit mode
	// Sync waits briefly for it after a reconfigure. Nil: assume applied.
	HasAddr func(nic, addr string) bool
	// Wait is how long to wait for HasAddr (default 10 s: conflict
	// detection takes several seconds before the address is configured).
	Wait time.Duration

	pending map[string]bool // NICs networkd hasn't applied yet (deferred or failed)
}

// FileName is the override file for nic.
func FileName(nic string) string { return "10-" + nic + "-sjb.network" }

// HasOverride reports whether dir holds an override file for nic.
func HasOverride(dir, nic string) bool {
	_, err := os.Stat(filepath.Join(dir, FileName(nic)))
	return err == nil
}

// sameIgnoringComments compares two networkd files without their comment
// lines, so a reworded header doesn't count as a change (a change makes
// networkd reconfigure the link).
func sameIgnoringComments(a, b []byte) bool {
	strip := func(x []byte) string {
		var out []string
		for _, l := range strings.Split(string(x), "\n") {
			if !strings.HasPrefix(strings.TrimSpace(l), "#") {
				out = append(out, l)
			}
		}
		return strings.Join(out, "\n")
	}
	return strip(a) == strip(b)
}

// Render returns the override file for nic with addr, keeping the DNS
// settings of the deployment's file (deployment).
func Render(nic, addr string, deployment []byte) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "# Written by ngfwd from the SJB-OS config (interfaces: %s address).\n", nic)
	b.WriteString("# Takes over from the deployment settings in 20-" + nic + ".network while\n")
	b.WriteString("# the config sets an address; removed when it doesn't. Do not edit.\n")
	fmt.Fprintf(&b, "[Match]\nName=%s\n\n[Network]\nDHCP=no\nConfigureWithoutCarrier=yes\n", nic)
	sc := bufio.NewScanner(bytes.NewReader(deployment))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "DNS=") || strings.HasPrefix(line, "Domains=") {
			b.WriteString(line + "\n")
		}
	}
	// Address conflict detection (RFC 5227): networkd probes that nobody
	// else has the address, then announces it with gratuitous ARPs, so
	// neighbours with a stale entry (a router that saw the address on
	// another device) switch to this NIC at once. On a conflict the address
	// is not applied, and Sync reports it.
	fmt.Fprintf(&b, "\n[Address]\nAddress=%s\nDuplicateAddressDetection=ipv4\n", addr)
	return b.Bytes()
}

// Sync writes or removes each managed NIC's override, then (unless mode is
// Deferred) has networkd apply the ones that changed or are still pending.
func (n *Networkd) Sync(want map[string]string, mode Mode) ([]State, error) {
	managed := map[string]bool{}
	for _, nic := range n.NICs {
		managed[nic] = true
	}
	states := map[string]*State{}
	for _, nic := range sortedKeys(want) {
		st := &State{Name: nic, Address: want[nic]}
		if !managed[nic] {
			st.Error = "ngfwd doesn't manage this interface's address"
		}
		states[nic] = st
	}

	var changed []string
	for _, nic := range n.NICs {
		path := filepath.Join(n.Dir, FileName(nic))
		have, err := os.ReadFile(path)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		exists := err == nil
		addr := want[nic]
		dep, _ := os.ReadFile(filepath.Join(n.Dir, "20-"+nic+".network"))
		if addr == "" || deploymentHas(dep, addr) {
			// Nothing configured, or the deployment already gives the NIC
			// exactly this address (inside's usual case): no override.
			if exists {
				if err := os.Remove(path); err != nil {
					return nil, err
				}
				changed = append(changed, nic)
			}
			continue
		}
		body := Render(nic, addr, dep)
		if exists && sameIgnoringComments(have, body) {
			if !bytes.Equal(have, body) {
				os.WriteFile(path, body, 0o644) // header only: networkd needn't know
			}
			continue
		}
		tmp := path + ".tmp"
		if err := os.WriteFile(tmp, body, 0o644); err != nil {
			return nil, err
		}
		if err := os.Rename(tmp, path); err != nil {
			return nil, err
		}
		changed = append(changed, nic)
	}

	// Apply changed files, and NICs still pending from an earlier pass.
	// Nothing else calls networkctl: at boot ngfwd starts before networkd.
	if n.pending == nil {
		n.pending = map[string]bool{}
	}
	var redo []string
	for _, nic := range n.NICs {
		if slices.Contains(changed, nic) || n.pending[nic] {
			redo = append(redo, nic)
		}
	}
	failed := map[string]string{}
	if mode == Deferred {
		for _, nic := range redo {
			n.pending[nic] = true
		}
		redo = nil
	} else if len(redo) > 0 {
		if err := n.networkctl("reload"); err != nil {
			for _, nic := range redo {
				failed[nic] = err.Error()
			}
		} else {
			for _, nic := range redo {
				if err := n.networkctl("reconfigure", nic); err != nil {
					failed[nic] = err.Error()
				}
			}
		}
	}
	for _, nic := range redo {
		delete(n.pending, nic)
	}
	for nic := range failed {
		n.pending[nic] = true
	}

	for _, nic := range n.NICs {
		st := states[nic]
		if st == nil {
			continue
		}
		switch {
		case failed[nic] != "":
			st.Error = failed[nic] + "; ngfwd keeps trying"
		case n.HasAddr == nil:
			st.Applied = !n.pending[nic]
			if !st.Applied {
				st.Error = "being applied"
			}
		default:
			st.Applied = n.waitAddr(nic, st.Address, mode == Commit && slices.Contains(redo, nic))
			if !st.Applied && n.pending[nic] {
				st.Error = "being applied (networkd reconfigures it within seconds)"
			} else if !st.Applied {
				st.Error = "networkd hasn't put the address on the interface yet; if it persists, another device may be using it (see journalctl -u systemd-networkd)"
			}
		}
	}

	out := make([]State, 0, len(states))
	for _, nic := range sortedKeys(want) {
		out = append(out, *states[nic])
	}
	return out, nil
}

// deploymentHas reports whether the deployment's file sets addr statically
// (with DHCP off).
func deploymentHas(dep []byte, addr string) bool {
	has := false
	for _, line := range strings.Split(string(dep), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "Address="+addr:
			has = true
		case strings.HasPrefix(line, "DHCP=") && line != "DHCP=no":
			return false
		}
	}
	return has
}

func (n *Networkd) waitAddr(nic, addr string, wait bool) bool {
	if n.HasAddr(nic, addr) {
		return true
	}
	if !wait {
		return false
	}
	d := n.Wait
	if d == 0 {
		d = 10 * time.Second
	}
	for end := time.Now().Add(d); time.Now().Before(end); {
		time.Sleep(200 * time.Millisecond)
		if n.HasAddr(nic, addr) {
			return true
		}
	}
	return false
}

func (n *Networkd) networkctl(args ...string) error {
	if n.Networkctl != nil {
		return n.Networkctl(args...)
	}
	out, err := exec.Command("networkctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("networkctl %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// IPHasAddr reports whether `ip` shows addr (CIDR) on nic.
func IPHasAddr(ipPath string) func(nic, addr string) bool {
	return func(nic, addr string) bool {
		out, err := exec.Command(ipPath, "-4", "-o", "addr", "show", "dev", nic).Output()
		if err != nil {
			return false
		}
		for _, f := range strings.Fields(string(out)) {
			if f == addr {
				return true
			}
		}
		return false
	}
}

func sortedKeys(m map[string]string) []string {
	return slices.Sorted(maps.Keys(m))
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
