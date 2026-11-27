package ospkg

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// ExecDpkg runs the real dpkg tools.
type ExecDpkg struct{}

// dpkgTimeout bounds one dpkg run: a kernel install builds an initramfs,
// which is slow on small appliances.
const dpkgTimeout = 30 * time.Minute

func run(timeout time.Duration, env []string, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), env...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		err = fmt.Errorf("%s timed out after %s", name, timeout)
	}
	return out.Bytes(), err
}

func (ExecDpkg) Fields(deb string) (string, string, string, int64, error) {
	out, err := run(time.Minute, nil, "dpkg-deb", "-f", deb, "Package", "Version", "Architecture", "Installed-Size")
	if err != nil {
		return "", "", "", 0, fmt.Errorf("dpkg-deb: %v: %s", err, strings.TrimSpace(string(out)))
	}
	f := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		if k, v, ok := strings.Cut(line, ":"); ok {
			f[k] = strings.TrimSpace(v)
		}
	}
	kb, _ := strconv.ParseInt(f["Installed-Size"], 10, 64)
	if f["Package"] == "" || f["Version"] == "" {
		return "", "", "", 0, fmt.Errorf("no Package or Version in %s", deb)
	}
	return f["Package"], f["Version"], f["Architecture"], kb, nil
}

// policyRC keeps package scripts from starting Debian's own suricata.service
// (SJB-OS runs Suricata as sjb-ips); exit 101 means "not allowed".
const policyRC = "/usr/sbin/policy-rc.d"

func withPolicy(f func() ([]byte, error)) ([]byte, error) {
	if _, err := os.Lstat(policyRC); os.IsNotExist(err) {
		script := "#!/bin/sh\ncase \"$1\" in suricata|suricata.service) exit 101 ;; esac\nexit 0\n"
		if err := os.WriteFile(policyRC, []byte(script), 0o755); err == nil {
			defer os.Remove(policyRC)
		}
	}
	return f()
}

var dpkgEnv = []string{"DEBIAN_FRONTEND=noninteractive"}

func (ExecDpkg) Install(debs []string, downgrade bool) ([]byte, error) {
	args := []string{"--force-confold"}
	if downgrade {
		args = append(args, "--force-downgrade")
	}
	args = append(args, "-i")
	args = append(args, debs...)
	return withPolicy(func() ([]byte, error) { return run(dpkgTimeout, dpkgEnv, "dpkg", args...) })
}

func (ExecDpkg) Remove(pkgs []string, purge bool) ([]byte, error) {
	op := "--remove"
	if purge {
		op = "--purge"
	}
	return withPolicy(func() ([]byte, error) {
		return run(dpkgTimeout, dpkgEnv, "dpkg", append([]string{op}, pkgs...)...)
	})
}

func (ExecDpkg) Configure() ([]byte, error) {
	return run(dpkgTimeout, dpkgEnv, "dpkg", "--configure", "-a")
}

// AllowRunningKernelRemoval answers Debian's "abort removing the running
// kernel?" question with no, so a rollback can remove the kernel it
// installed even after booting it.
func (ExecDpkg) AllowRunningKernelRemoval() error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "debconf-set-selections")
	cmd.Stdin = strings.NewReader("linux-base linux-base/removing-running-kernel boolean false\n")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("debconf-set-selections: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// LiveHost is the running system.
type LiveHost struct{}

func (LiveHost) RunningKernel() string {
	b, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func (LiveHost) BootTime() time.Time {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return time.Time{}
	}
	for _, line := range strings.Split(string(data), "\n") {
		if f := strings.Fields(line); len(f) == 2 && f[0] == "btime" {
			if n, err := strconv.ParseInt(f[1], 10, 64); err == nil {
				return time.Unix(n, 0)
			}
		}
	}
	return time.Time{}
}

func (LiveHost) FreeBytes(path string) (uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, err
	}
	return uint64(st.Bavail) * uint64(st.Bsize), nil
}
