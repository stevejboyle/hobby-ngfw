package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"
)

type decryptionCA struct {
	Present     bool
	Source      string
	Subject     string
	Fingerprint string
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	PEM         string
}

func showDecryption() error {
	out, err := call("GET", "/v1/decryption", nil)
	if err != nil {
		return err
	}
	var st struct {
		Enabled, Installed, Running, Ready bool
		InUse                              bool `json:"in_use"`
		Mode, State                        string
		Detail                             string `json:"state_detail"`
		CA                                 decryptionCA
		Rules                              []string
		Counts                             map[string]int64
		Active                             int64
		Learned                            int
		Builtin                            bool `json:"builtin_exclusions"`
		CPUs                               int
	}
	if err := json.Unmarshal(out, &st); err != nil {
		return err
	}
	onoff := map[bool]string{true: "on", false: "off"}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintf(tw, "decryption\t%s (system decryption); mode %s\n", onoff[st.Enabled], st.Mode)
	fmt.Fprintf(tw, "state\t%s: %s\n", strings.ToUpper(st.State), st.Detail)
	if st.CA.Present {
		fmt.Fprintf(tw, "CA\t%s (%s), valid until %s\n", st.CA.Subject, st.CA.Source, st.CA.NotAfter.Local().Format("2006-01-02"))
		fmt.Fprintf(tw, "\tSHA-256 %s\n", st.CA.Fingerprint)
	} else {
		fmt.Fprintf(tw, "CA\tnone (request decryption ca generate, or import one)\n")
	}
	if len(st.Rules) == 0 {
		fmt.Fprintf(tw, "rules\tnone (set decryption-rule NAME from inside to outside action decrypt)\n")
	} else {
		fmt.Fprintf(tw, "rules\t%s\n", strings.Join(st.Rules, ", "))
	}
	fmt.Fprintf(tw, "exclusions\tbuilt-in list %s; plus decryption-exclusion objects\n", onoff[st.Builtin])
	if len(st.Counts) > 0 {
		var parts []string
		keys := make([]string, 0, len(st.Counts))
		for k := range st.Counts {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			parts = append(parts, fmt.Sprintf("%s %d", k, st.Counts[k]))
		}
		fmt.Fprintf(tw, "connections\t%d now; since tlsd started: %s\n", st.Active, strings.Join(parts, ", "))
	}
	fmt.Fprintf(tw, "learned\t%d pinned server(s) passed through (show decryption learned)\n", st.Learned)
	cpu := ""
	if st.CPUs < 4 {
		cpu = " (4 recommended for decryption)"
	}
	fmt.Fprintf(tw, "vCPU\t%d%s\n", st.CPUs, cpu)
	return tw.Flush()
}

func showDecryptionCA() error {
	out, err := call("GET", "/v1/decryption/ca", nil)
	if err != nil {
		return err
	}
	var ca decryptionCA
	if err := json.Unmarshal(out, &ca); err != nil {
		return err
	}
	if !ca.Present {
		fmt.Println("no decryption CA yet: request decryption ca generate (or request decryption ca import)")
		return nil
	}
	fmt.Printf("%s (%s)\nvalid %s to %s\nSHA-256 fingerprint %s\n\n", ca.Subject, ca.Source,
		ca.NotBefore.Local().Format("2006-01-02"), ca.NotAfter.Local().Format("2006-01-02"), ca.Fingerprint)
	fmt.Println("Install this certificate as a trusted root on the clients you decrypt (the")
	fmt.Println("web UI's Security > Decryption page offers it as a file). Check the")
	fmt.Println("fingerprint on each client. The private key never leaves the firewall.")
	fmt.Println()
	fmt.Print(ca.PEM)
	return nil
}

func showDecryptionLearned() error {
	out, err := call("GET", "/v1/decryption/learned", nil)
	if err != nil {
		return err
	}
	var es []struct {
		ServerName string `json:"server_name"`
		IP         string
		Expires    time.Time
	}
	if err := json.Unmarshal(out, &es); err != nil {
		return err
	}
	if len(es) == 0 {
		fmt.Println("no learned servers: every client accepted the firewall's certificate")
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "SERVER NAME\tADDRESS\tPASSED THROUGH UNTIL")
	for _, e := range es {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", e.ServerName, e.IP, e.Expires.Local().Format("2006-01-02 15:04"))
	}
	return tw.Flush()
}

// buffered reuses the session's reader, so nothing typed is lost.
func buffered(in io.Reader) *bufio.Reader {
	if b, ok := in.(*bufio.Reader); ok {
		return b
	}
	return bufio.NewReader(in)
}

// confirmLine asks a yes/no question on the CLI.
func confirmLine(in io.Reader, q string) bool {
	fmt.Print(q + " [yes/no] ")
	line, _ := buffered(in).ReadString('\n')
	return strings.TrimSpace(strings.ToLower(line)) == "yes"
}

func requestDecryptionCAGenerate(in io.Reader) error {
	if out, err := call("GET", "/v1/decryption/ca", nil); err == nil {
		var ca decryptionCA
		if json.Unmarshal(out, &ca) == nil && ca.Present &&
			!confirmLine(in, "This replaces the current decryption CA; clients that trust it must be given the new one. Continue?") {
			fmt.Println("nothing changed")
			return nil
		}
	}
	body, _ := json.Marshal(map[string]string{"author": whoami()})
	out, err := call("POST", "/v1/decryption/ca/generate", body)
	if err != nil {
		return err
	}
	var ca decryptionCA
	json.Unmarshal(out, &ca)
	fmt.Printf("new decryption CA: %s\nSHA-256 %s\nshow decryption ca prints its certificate for the clients\n", ca.Subject, ca.Fingerprint)
	return nil
}

// readPEMBlock reads pasted lines up to and including the END line of a
// PEM block (or a line "end").
func readPEMBlock(r *bufio.Reader) (string, error) {
	var b strings.Builder
	for {
		line, err := r.ReadString('\n')
		t := strings.TrimSpace(line)
		if t == "end" {
			break
		}
		if t != "" {
			b.WriteString(t + "\n")
		}
		if strings.HasPrefix(t, "-----END ") || err != nil {
			if err != nil && b.Len() == 0 {
				return "", fmt.Errorf("nothing pasted")
			}
			break
		}
	}
	return b.String(), nil
}

func requestDecryptionCAImport(in io.Reader) error {
	r := buffered(in)
	fmt.Println("Paste the CA certificate (PEM, -----BEGIN CERTIFICATE----- ... -----END CERTIFICATE-----):")
	cert, err := readPEMBlock(r)
	if err != nil {
		return err
	}
	fmt.Println("Paste its private key (PEM, unencrypted; it stays on the firewall):")
	key, err := readPEMBlock(r)
	if err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]string{"author": whoami(), "cert": cert, "key": key})
	out, err := call("POST", "/v1/decryption/ca/import", body)
	if err != nil {
		return err
	}
	var ca decryptionCA
	json.Unmarshal(out, &ca)
	fmt.Printf("decryption CA imported: %s\nSHA-256 %s\n", ca.Subject, ca.Fingerprint)
	return nil
}

func requestDecryptionLearnedClear() error {
	body, _ := json.Marshal(map[string]string{"author": whoami()})
	out, err := call("POST", "/v1/decryption/learned/clear", body)
	if err != nil {
		return err
	}
	var r struct{ Cleared int }
	json.Unmarshal(out, &r)
	fmt.Printf("%d learned server(s) forgotten: they are decrypted again from the next connection\n", r.Cleared)
	return nil
}
