package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/stevejboyle/sjb-os/internal/ospkg"
)

func packageManager() *ospkg.Manager {
	return &ospkg.Manager{
		Root: envOr("NGFW_ROOT", "/"),
		Dpkg: ospkg.ExecDpkg{},
		Host: ospkg.LiveHost{},
		Log:  func(s string) { fmt.Println(s) },
	}
}

// packagesCmd: `fwctl packages install` (what sjb-packages runs after an
// upgrade) and `fwctl packages status [-json]`.
func packagesCmd(args []string) error {
	if len(args) == 0 {
		args = []string{"status"}
	}
	m := packageManager()
	switch args[0] {
	case "install":
		_, err := m.Install()
		return err
	case "status":
		st := m.Report()
		if len(args) > 1 && args[1] == "-json" {
			b, _ := json.MarshalIndent(st, "", "  ")
			fmt.Println(string(b))
			return nil
		}
		printPackages(st, true)
		return nil
	}
	return fmt.Errorf("usage: packages install|status [-json]")
}

// printPackages prints the OS package lines of `upgrade status` and
// `show version`; with detail, every package changed.
func printPackages(st ospkg.Status, detail bool) {
	switch st.State {
	case ospkg.StateOK:
		fmt.Printf("OS packages: %d updated (%d security) at %s\n", st.Updated(), st.Security(), st.Time.Local().Format("2006-01-02 15:04"))
	case ospkg.StateInstalling:
		fmt.Printf("OS packages: installing %d package(s), started %s\n", st.Updated(), st.Time.Local().Format("2006-01-02 15:04"))
	case ospkg.StateFailed:
		fmt.Printf("OS packages: install FAILED at %s: %s\n", st.Time.Local().Format("2006-01-02 15:04"), st.Error)
	default:
		fmt.Println("OS packages: as shipped (no updates installed by an upgrade)")
	}
	if st.Pending > 0 && st.State != ospkg.StateInstalling {
		fmt.Printf("OS packages: %d bundled package(s) not installed yet; they install when ngfwd starts\n", st.Pending)
	}
	if st.RunningKernel != "" {
		fmt.Printf("kernel:      %s\n", st.RunningKernel)
	}
	switch {
	case st.RebootRequired:
		fmt.Printf("REBOOT REQUIRED: %s\n", strings.Join(st.RebootReasons, "; "))
	case st.RebootRecommended:
		fmt.Printf("reboot recommended: %s\n", strings.Join(st.RebootReasons, "; "))
	}
	if detail {
		for _, c := range st.Changes {
			kind := ""
			if c.Security {
				kind = "  (security)"
			}
			fmt.Printf("  %-36s %s -> %s%s\n", c.Package, c.From, c.To, kind)
		}
	}
}

// restorePackages is the rollback hook: put back the saved package
// versions and say what happened.
func restorePackages(bdir string) (string, error) {
	m := packageManager()
	m.Log = func(s string) { fmt.Println(s) }
	res, err := m.Restore(bdir)
	if err != nil {
		return "", err
	}
	if res.Skipped {
		return "OS packages: none were saved by this upgrade (made before 0.9.14), so they are left as they are", nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "OS packages: %d put back to their earlier versions", len(res.Downgraded))
	if len(res.Removed) > 0 {
		fmt.Fprintf(&b, "; removed %s", strings.Join(res.Removed, " "))
	}
	if len(res.Kept) > 0 {
		fmt.Fprintf(&b, "; kept %s (still needed by other packages)", strings.Join(res.Kept, " "))
	}
	if res.RunningKernel {
		b.WriteString("\nREBOOT REQUIRED: the running kernel was removed; until the reboot, kernel modules not already loaded can't be loaded")
	}
	return b.String(), nil
}

// requestReboot: `request system reboot` in the CLI.
func requestReboot(in io.Reader) error {
	if !confirmLine(in, "Reboot the appliance now? Traffic stops until it is back (about a minute).") {
		fmt.Println("not rebooted")
		return nil
	}
	if _, err := call("POST", "/v1/reboot", mustJSON(map[string]any{})); err != nil {
		return err
	}
	fmt.Println("rebooting; reconnect in about a minute")
	return nil
}
