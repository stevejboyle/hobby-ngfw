package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/stevejboyle/sjb-os/internal/logfwd"
)

// showLogForwarding prints the log forwarder's state and each server.
func showLogForwarding() error {
	out, err := call("GET", "/v1/logforwarding", nil)
	if err != nil {
		return err
	}
	var st logfwd.Status
	if err := json.Unmarshal(out, &st); err != nil {
		return err
	}
	if len(st.Servers) == 0 {
		fmt.Println("no log servers (add one in configure mode: set log-server NAME address IP, or on the web UI's Log forwarding page)")
		return nil
	}
	reader := "following the journal"
	if !st.Following {
		reader = "NOT READING the journal"
		if st.FollowError != "" {
			reader += ": " + st.FollowError
		}
	}
	fmt.Println("Log forwarding:", reader)
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "SERVER\tADDRESS\tTRANSPORT\tFORMAT\tVRF\tLOGS\tSTATE\tSENT\tQUEUED\tDROPPED")
	for _, s := range st.Servers {
		state := s.State
		if s.Since != nil && s.State == logfwd.StateConnected {
			state += " " + ago(*s.Since)
		}
		fmt.Fprintf(tw, "%s\t%s:%d\t%s\t%s\t%s\t%s\t%s\t%d\t%d\t%d\n", s.Name, s.Address, s.Port, s.Transport, s.Format, s.VRF,
			strings.Join(s.Types, ","), state, s.Sent, s.Queued, s.Dropped)
	}
	tw.Flush()
	for _, s := range st.Servers {
		if s.LastError != "" {
			when := ""
			if s.LastErrorAt != nil {
				when = " (" + ago(*s.LastErrorAt) + ")"
			}
			fmt.Printf("%s: last error%s: %s\n", s.Name, when, s.LastError)
		}
	}
	return nil
}

func ago(t time.Time) string {
	d := time.Since(t).Round(time.Second)
	if d < 0 {
		d = 0
	}
	return "for " + d.String()
}

// requestLogForwardingTest sends a test message to one log server.
func requestLogForwardingTest(name string) error {
	body, _ := json.Marshal(map[string]string{"name": name})
	if _, err := call("POST", "/v1/logforwarding/test", body); err != nil {
		return err
	}
	fmt.Printf("test message queued for %s (show log-forwarding shows whether it was sent)\n", name)
	return nil
}
