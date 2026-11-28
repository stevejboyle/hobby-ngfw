package main

import (
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// updatesStatus mirrors daemon.UpdatesStatus.
type updatesStatus struct {
	Available bool   `json:"available"`
	Enabled   bool   `json:"enabled"`
	Server    string `json:"server"`
	Installed string `json:"installed"`
	Checking  bool   `json:"checking"`
	LastCheck struct {
		Time   time.Time `json:"time"`
		OK     bool      `json:"ok"`
		Result string    `json:"result"`
		Latest *struct {
			Version string `json:"version"`
			Notes   string `json:"notes"`
		} `json:"latest"`
	} `json:"last_check"`
	Staged *struct {
		Version    string    `json:"version"`
		Size       int64     `json:"size"`
		Notes      string    `json:"notes"`
		Downloaded time.Time `json:"downloaded"`
	} `json:"staged"`
	UpdateReady bool `json:"update_ready"`
}

func getUpdates() (updatesStatus, error) {
	var st updatesStatus
	out, err := call("GET", "/v1/updates", nil)
	if err != nil {
		return st, err
	}
	return st, json.Unmarshal(out, &st)
}

func showUpdates() error {
	st, err := getUpdates()
	if err != nil {
		return err
	}
	printUpdates(st)
	return nil
}

func printUpdates(st updatesStatus) {
	if !st.Available {
		fmt.Println("online updates: not available on this system")
		return
	}
	check := "on; checked daily over the outside link"
	if !st.Enabled {
		check = "off (set system update-check on); request system upgrade check still works"
	}
	fmt.Printf("update server: %s\n", st.Server)
	fmt.Printf("daily check:   %s\n", check)
	fmt.Printf("installed:     SJB-OS %s\n", st.Installed)
	if st.Checking {
		fmt.Println("checking:      a check is running now (show system updates again in a minute)")
	}
	if lc := st.LastCheck; !lc.Time.IsZero() {
		res := lc.Result
		if !lc.OK {
			res = "FAILED: " + res
		}
		fmt.Printf("last check:    %s, %s\n", lc.Time.Local().Format("2006-01-02 15:04"), res)
		if lc.Latest != nil {
			fmt.Printf("latest:        SJB-OS %s", lc.Latest.Version)
			if lc.Latest.Notes != "" {
				fmt.Printf("  (%s)", lc.Latest.Notes)
			}
			fmt.Println()
		}
	} else if !st.Checking {
		fmt.Println("last check:    never")
	}
	if s := st.Staged; s != nil && st.UpdateReady {
		fmt.Printf("downloaded:    SJB-OS %s (%s, %s), ready: request system upgrade install\n",
			s.Version, sizeText(s.Size), s.Downloaded.Local().Format("2006-01-02 15:04"))
	}
}

// printUpdateLine adds the staged update, if any, to show version.
func printUpdateLine() {
	st, err := getUpdates()
	if err != nil || !st.UpdateReady || st.Staged == nil {
		return
	}
	fmt.Printf("update:    SJB-OS %s is downloaded; request system upgrade install installs it\n", st.Staged.Version)
}

func requestUpgradeCheck() error {
	out, err := call("POST", "/v1/updates/check", mustJSON(map[string]any{}))
	if err != nil {
		return err
	}
	var st updatesStatus
	if err := json.Unmarshal(out, &st); err != nil {
		return err
	}
	printUpdates(st)
	return nil
}

func requestUpgradeInstall(in io.Reader) error {
	st, err := getUpdates()
	if err != nil {
		return err
	}
	if !st.UpdateReady || st.Staged == nil {
		printUpdates(st)
		return fmt.Errorf("no update is downloaded; run request system upgrade check")
	}
	q := fmt.Sprintf("Install SJB-OS %s over %s now? ngfwd restarts (traffic keeps flowing); the session reconnects when it is back.", st.Staged.Version, st.Installed)
	if !confirmLine(in, q) {
		fmt.Println("not installed")
		return nil
	}
	if _, err := call("POST", "/v1/updates/install", mustJSON(map[string]any{})); err != nil {
		return err
	}
	fmt.Printf("installing SJB-OS %s; show version shows the result once ngfwd is back\n", st.Staged.Version)
	return nil
}

// sizeText is a byte count in MB, or KB below 1 MB.
func sizeText(n int64) string {
	if n >= 1<<20 {
		return fmt.Sprintf("%d MB", (n+(1<<19))>>20)
	}
	return fmt.Sprintf("%d KB", max(1, (n+512)>>10))
}
