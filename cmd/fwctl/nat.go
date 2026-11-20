package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"text/tabwriter"

	"github.com/stevejboyle/hobby-ngfw/internal/config"
)

type natEntry struct {
	config.NATRule
	PublicIP       string  `json:"public_ip"`
	ServerIP       string  `json:"server_ip"`
	Hits           *uint64 `json:"hits"`
	OutHits        *uint64 `json:"out_hits"`
	AddressApplied *bool   `json:"address_applied"`
	AddressError   string  `json:"address_error"`
}

func count(n *uint64) string {
	if n == nil {
		return "-"
	}
	return strconv.FormatUint(*n, 10)
}

// showNAT prints the running NAT entries by kind, with their counters.
func showNAT() error {
	out, err := call("GET", "/v1/nat", nil)
	if err != nil {
		return err
	}
	var es []natEntry
	if err := json.Unmarshal(out, &es); err != nil {
		return err
	}
	if len(es) == 0 {
		fmt.Println("no NAT entries (add them in the web UI's NAT page, or with set nat NAME type ...)")
		return nil
	}
	public := func(e natEntry) string {
		if e.PublicAddress == "" {
			return e.Interface + " address"
		}
		s := fmt.Sprintf("%s (%s)", e.PublicAddress, e.PublicIP)
		if e.AddressApplied != nil && !*e.AddressApplied {
			s += " [not on " + e.Interface + " yet: " + e.AddressError + "]"
		}
		return s
	}
	server := func(e natEntry) string { return fmt.Sprintf("%s (%s)", e.Server, e.ServerIP) }
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	section := func(title, header string, kind string, row func(natEntry) string) {
		first := true
		for _, e := range es {
			if e.Type != kind {
				continue
			}
			if first {
				fmt.Fprintf(tw, "%s:\n  %s\n", title, header)
				first = false
			}
			fmt.Fprintln(tw, "  "+row(e))
		}
		if !first {
			fmt.Fprintln(tw)
		}
	}
	section("port forwarding", "NAME\tINTERFACE\tPUBLIC\tPORT\tSERVER\tSERVER PORT\tCONNECTIONS", config.NATPortForward, func(e natEntry) string {
		sp := e.ServerPort
		if sp == "" {
			sp = e.PublicPort
		}
		return fmt.Sprintf("%s\t%s\t%s\t%s/%s\t%s\t%s\t%s", e.Name, e.Interface, public(e), e.Protocol, e.PublicPort, server(e), sp, count(e.Hits))
	})
	section("static NAT", "NAME\tINTERFACE\tPUBLIC\tSERVER\tBIDIRECTIONAL\tIN\tOUT", config.NATStatic, func(e natEntry) string {
		bi, outHits := "on", count(e.OutHits)
		if !e.BidirectionalOn() {
			bi, outHits = "off", "-"
		}
		return fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%s\t%s", e.Name, e.Interface, public(e), server(e), bi, count(e.Hits), outHits)
	})
	section("source NAT", "NAME\tFROM\tTO\tSOURCE\tTYPE\tCONNECTIONS", config.NATMasquerade, func(e natEntry) string {
		return fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%s", e.Name, list(e.From), list(e.To), list(e.Source), e.Type, count(e.Hits))
	})
	if err := tw.Flush(); err != nil {
		return err
	}
	fmt.Println("NAT only translates: a security rule naming the server's inside address still has to allow the traffic.")
	return nil
}

func list(xs []string) string {
	if len(xs) == 0 {
		return "any"
	}
	s := ""
	for i, x := range xs {
		if i > 0 {
			s += ","
		}
		s += x
	}
	return s
}
