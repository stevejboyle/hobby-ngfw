package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/stevejboyle/sjb-os/internal/config"
	"github.com/stevejboyle/sjb-os/internal/snmp"
)

// showSNMP prints the SNMP agent's state, access and trap receivers.
func showSNMP() error {
	out, err := call("GET", "/v1/snmp", nil)
	if err != nil {
		return err
	}
	var st struct {
		Enabled       bool                      `json:"enabled"`
		Installed     bool                      `json:"installed"`
		Running       bool                      `json:"running"`
		State         string                    `json:"state"`
		ConfigCurrent bool                      `json:"config_current"`
		VerifiedAt    *time.Time                `json:"verified_at"`
		Attempts      int                       `json:"attempts"`
		NextRetry     *time.Time                `json:"next_retry"`
		CredsError    string                    `json:"credentials_error"`
		Error         string                    `json:"error"`
		Location      string                    `json:"location"`
		Contact       string                    `json:"contact"`
		V3Users       []string                  `json:"v3_users"`
		Communities   []string                  `json:"v2c_communities"`
		Managers      []string                  `json:"managers"`
		Receivers     []config.SNMPTrapReceiver `json:"trap_receivers"`
		Credentials   []snmp.Info               `json:"credentials"`
		MIBBase       string                    `json:"mib_base"`
	}
	if err := json.Unmarshal(out, &st); err != nil {
		return err
	}
	state := "off"
	if st.Enabled {
		switch st.State {
		case "running":
			state = "on, running"
			if st.VerifiedAt != nil {
				state += " (verified " + ago(*st.VerifiedAt) + ")"
			}
		case "starting":
			state = "on, STARTING (snmpd was asked to start; not seen running yet)"
		case "waiting-install":
			state = "on, but snmpd isn't installed yet (an upgrade installs it in the background)"
		case "failed":
			state = fmt.Sprintf("on, NOT RUNNING (%d start(s) so far", st.Attempts)
			if st.NextRetry != nil {
				state += ", next try " + st.NextRetry.Local().Format("15:04:05")
			}
			state += ")"
		case "gave-up":
			state = "on, NOT RUNNING: gave up retrying (commit, or change the config or a credential, to try again)"
		case "error":
			state = "on, NOT APPLIED: the config or credentials can't be turned into snmpd's config"
		default:
			state = "on, " + st.State
		}
		if !st.ConfigCurrent && st.State != "error" && st.State != "waiting-install" {
			state += "; snmpd's config file is not up to date"
		}
	}
	fmt.Println("SNMP agent:", state)
	if st.Error != "" {
		fmt.Println("Last error:", st.Error)
	}
	if st.CredsError != "" {
		fmt.Println("Credentials:", st.CredsError)
	}
	if !st.Enabled && len(st.Credentials) == 0 {
		fmt.Println("Turn it on in configure mode: set snmp enabled on, set snmp v3-users NAME (after request snmp credential add NAME v3 ...).")
		return nil
	}
	if st.Location != "" || st.Contact != "" {
		fmt.Printf("Location: %s   Contact: %s\n", st.Location, st.Contact)
	}
	fmt.Println("Polling: v3 users", orNone(st.V3Users), "  v2c communities", orNone(st.Communities), "from", orNone(st.Managers))
	fmt.Println("SJB-OS-MIB:", st.MIBBase, "(the MIB file: /usr/share/sjb-os/mibs/SJB-OS-MIB.txt)")
	if len(st.Receivers) > 0 {
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "\nTRAP RECEIVER\tADDRESS\tCREDENTIAL\tINFORM")
		for _, r := range st.Receivers {
			inform := "no"
			if r.Inform == "on" {
				inform = "yes"
			}
			fmt.Fprintf(tw, "%s\t%s:%d\t%s\t%s\n", r.Name, r.Address, r.PortOrDefault(), r.Credential, inform)
		}
		tw.Flush()
	}
	if len(st.Credentials) > 0 {
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "\nCREDENTIAL\tKIND\tAUTH\tPRIV")
		for _, c := range st.Credentials {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", c.Name, c.Kind, dash(c.Auth), dash(c.Priv))
		}
		tw.Flush()
	}
	return nil
}

func orNone(s []string) string {
	if len(s) == 0 {
		return "(none)"
	}
	return strings.Join(s, ", ")
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// requestSNMP: credential add NAME v3 auth sha256|sha512 priv aes|aes256,
// credential add NAME v2c, credential change NAME ..., credential delete
// NAME. Secrets are asked for with echo off, never taken on the line.
func requestSNMP(args []string, in io.Reader) error {
	const usage = "request snmp credential add NAME v3 auth sha256|sha512 priv aes|aes256 | credential add NAME v2c | credential change NAME (same arguments) | credential delete NAME"
	if len(args) < 3 || args[0] != "credential" {
		return fmt.Errorf("%s", usage)
	}
	op, name := args[1], args[2]
	switch op {
	case "delete":
		if len(args) != 3 {
			return fmt.Errorf("%s", usage)
		}
		_, err := call("DELETE", "/v1/snmp/credentials/"+name, nil)
		if err == nil {
			fmt.Printf("SNMP credential %s deleted.\n", name)
		}
		return err
	case "add", "change":
	default:
		return fmt.Errorf("%s", usage)
	}
	if len(args) < 4 {
		return fmt.Errorf("%s", usage)
	}
	c := snmp.Credential{Name: name, Kind: args[3]}
	switch c.Kind {
	case snmp.KindV3:
		rest := args[4:]
		for len(rest) >= 2 {
			switch rest[0] {
			case "auth":
				c.Auth = snmp.NormalizeAuth(rest[1])
			case "priv":
				c.Priv = snmp.NormalizePriv(rest[1])
			default:
				return fmt.Errorf("%s", usage)
			}
			rest = rest[2:]
		}
		if len(rest) != 0 {
			return fmt.Errorf("%s", usage)
		}
		if c.Auth == "" {
			c.Auth = "SHA-256"
		}
		if c.Priv == "" {
			c.Priv = "AES"
		}
		var err error
		if c.AuthPass, err = askTwice(in, "Authentication passphrase for "+name+fmt.Sprintf(" (%d+ characters): ", snmp.MinSecret)); err != nil {
			return err
		}
		if c.PrivPass, err = askTwice(in, "Privacy (encryption) passphrase, a different one: "); err != nil {
			return err
		}
	case snmp.KindV2c:
		if len(args) != 4 {
			return fmt.Errorf("%s", usage)
		}
		var err error
		if c.Community, err = askTwice(in, "Community string for "+name+fmt.Sprintf(" (%d+ characters; v2c sends it in clear text): ", snmp.MinSecret)); err != nil {
			return err
		}
	default:
		return fmt.Errorf("%s", usage)
	}
	body, _ := json.Marshal(struct {
		snmp.Credential
		Replace bool `json:"replace"`
	}{c, op == "change"})
	out, err := call("POST", "/v1/snmp/credentials", body)
	if err != nil {
		return err
	}
	var res struct {
		Warnings []string `json:"warnings"`
	}
	json.Unmarshal(out, &res)
	for _, w := range res.Warnings {
		fmt.Println("warning:", w)
	}
	if op == "change" {
		fmt.Printf("SNMP credential %s changed; snmpd uses it now if the config names it.\n", name)
	} else {
		fmt.Printf("SNMP credential %s added. Use it in configure mode, e.g. set snmp v3-users %s or set snmp-trap-receiver NAME credential %s, then commit.\n", name, name, name)
	}
	return nil
}

func askTwice(in io.Reader, label string) (string, error) {
	a, err := askSecret(in, label)
	if err != nil {
		return "", err
	}
	b, err := askSecret(in, "Again: ")
	if err != nil {
		return "", err
	}
	if a != b {
		return "", fmt.Errorf("they don't match; nothing changed")
	}
	return a, nil
}

// requestAPIKey: add NAME scopes SCOPE[,SCOPE] | delete NAME (superusers).
func requestAPIKey(args []string) error {
	const usage = "request api-key add NAME scopes metrics:read|tags:read|tags:write[,...] | delete NAME"
	switch {
	case len(args) == 4 && args[0] == "add" && args[2] == "scopes":
		body, _ := json.Marshal(map[string]any{"name": args[1], "scopes": strings.Split(args[3], ",")})
		out, err := call("POST", "/v1/api-keys", body)
		if err != nil {
			return err
		}
		var k struct {
			Name   string   `json:"name"`
			Scopes []string `json:"scopes"`
			Key    string   `json:"key"`
		}
		if err := json.Unmarshal(out, &k); err != nil {
			return err
		}
		fmt.Printf("API key %s (%s), in use now:\n\n  %s\n\n", k.Name, strings.Join(k.Scopes, ","), k.Key)
		if slicesContains(k.Scopes, "metrics:read") {
			fmt.Println("Prometheus scrapes https://<management address>:8443/metrics with it, e.g.:")
			fmt.Printf("  authorization: {type: Bearer, credentials: %s}\n", k.Key)
		}
		return nil
	case len(args) == 2 && args[0] == "delete":
		if _, err := call("DELETE", "/v1/api-keys/"+args[1], nil); err != nil {
			return err
		}
		fmt.Printf("API key %s deleted; requests with it are refused now.\n", args[1])
		return nil
	}
	return fmt.Errorf("%s", usage)
}

func slicesContains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// showMetrics prints the Prometheus text (what a scraper of /metrics
// gets), optionally only the lines containing TEXT.
func showMetrics(filter string) error {
	out, err := call("GET", "/v1/metrics", nil)
	if err != nil {
		return err
	}
	if filter == "" {
		_, err = os.Stdout.Write(out)
		return err
	}
	for _, l := range bytes.Split(out, []byte("\n")) {
		if !bytes.HasPrefix(l, []byte("#")) && bytes.Contains(l, []byte(filter)) {
			os.Stdout.Write(append(l, '\n'))
		}
	}
	return nil
}
