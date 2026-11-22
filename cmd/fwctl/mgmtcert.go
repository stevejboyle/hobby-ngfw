package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"
)

type mgmtCertInfo struct {
	Source      string
	Subject     string
	Issuer      string
	DNSNames    []string  `json:"dns_names"`
	IPAddresses []string  `json:"ip_addresses"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	Fingerprint string
	Chain       int
	Warnings    []string
	PEM         string
}

func printMgmtCert(c mgmtCertInfo, withPEM bool) error {
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintf(tw, "source\t%s\n", c.Source)
	fmt.Fprintf(tw, "subject\t%s\n", c.Subject)
	fmt.Fprintf(tw, "issuer\t%s\n", c.Issuer)
	sans := append(append([]string{}, c.DNSNames...), c.IPAddresses...)
	if len(sans) == 0 {
		sans = []string{"none"}
	}
	fmt.Fprintf(tw, "names (SANs)\t%s\n", strings.Join(sans, ", "))
	fmt.Fprintf(tw, "valid\t%s to %s\n", c.NotBefore.Local().Format("2006-01-02"), c.NotAfter.Local().Format("2006-01-02"))
	fmt.Fprintf(tw, "chain\t%d intermediate(s) sent after it\n", c.Chain)
	fmt.Fprintf(tw, "SHA-256\t%s\n", c.Fingerprint)
	for _, w := range c.Warnings {
		fmt.Fprintf(tw, "warning\t%s\n", w)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if withPEM {
		fmt.Println()
		fmt.Print(c.PEM)
	}
	return nil
}

func showMgmtCert(args []string) error {
	out, err := call("GET", "/v1/mgmt-cert", nil)
	if err != nil {
		return err
	}
	var c mgmtCertInfo
	if err := json.Unmarshal(out, &c); err != nil {
		return err
	}
	return printMgmtCert(c, len(args) > 0 && args[0] == "pem")
}

func requestMgmtCert(args []string, in io.Reader) error {
	switch strings.Join(args, " ") {
	case "import":
		return requestMgmtCertImport(in)
	case "self-signed":
		return requestMgmtCertSelfSigned(in)
	}
	return fmt.Errorf("request management-certificate import | self-signed")
}

func requestMgmtCertImport(in io.Reader) error {
	r := buffered(in)
	fmt.Println("Paste the firewall's certificate (PEM), then the intermediates that issued it,")
	fmt.Println("in order (not the root); finish with a line containing only \"end\":")
	cert, err := readPEMBlock(r, true)
	if err != nil {
		return err
	}
	fmt.Println("Paste its private key (PEM, unencrypted; it stays on the firewall):")
	key, err := readPEMBlock(r, false)
	if err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]string{"cert": cert, "key": key})
	out, err := call("POST", "/v1/mgmt-cert/import", body)
	if err != nil {
		return err
	}
	var c mgmtCertInfo
	json.Unmarshal(out, &c)
	fmt.Println("management certificate imported; new web UI and tag API connections use it now:")
	return printMgmtCert(c, false)
}

func requestMgmtCertSelfSigned(in io.Reader) error {
	if !confirmLine(in, "This replaces the management certificate with a new self-signed one; browsers and tag API clients will warn until they accept it. Continue?") {
		fmt.Println("nothing changed")
		return nil
	}
	out, err := call("POST", "/v1/mgmt-cert/self-signed", []byte("{}"))
	if err != nil {
		return err
	}
	var c mgmtCertInfo
	json.Unmarshal(out, &c)
	fmt.Println("new self-signed management certificate:")
	return printMgmtCert(c, false)
}
