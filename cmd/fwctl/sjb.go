package main

// SJB-OS (Stops Junk at the Border) easter egg: `fwctl sjb`, a word from
// the border guard. Jokes stay in human-facing output only: nothing here
// changes JSON, XML or exit codes.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"strings"
)

// sayingsFile is installed on the appliance; the built-in list below is the
// fallback anywhere else. One saying per line; # starts a comment.
const sayingsFile = "/usr/share/sjb-os/sayings.txt"

var builtinSayings = []string{
	"Papers, please. Every packet shows its papers at the border.",
	"Default deny. No exceptions. Not even for you.",
	"Commit with -confirm. A guard who can step back can afford to step forward.",
	"Did you run show diff before committing?",
	"Rollback exists so you can be brave. Use it.",
	"Junk stopped: plenty. Good traffic: waved through.",
}

func loadSayings() []string {
	f, err := os.Open(sayingsFile)
	if err != nil {
		return builtinSayings
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	if len(out) == 0 {
		return builtinSayings
	}
	return out
}

// sjbCmd: `fwctl sjb`. A saying, then a report from the gate if ngfwd
// answers.
func sjbCmd() error {
	s := loadSayings()
	fmt.Println(s[rand.IntN(len(s))])

	out, err := call("GET", "/v1/status", nil)
	if err != nil {
		fmt.Println("The gatehouse is quiet: ngfwd is not answering. Is it running?")
		return nil
	}
	var st struct {
		Running   int     `json:"running_revision"`
		ConfirmBy *string `json:"confirm_by"`
		Pending   bool    `json:"uncommitted_changes"`
	}
	if json.Unmarshal(out, &st) != nil {
		return nil
	}
	msg := fmt.Sprintf("Revision %d is on duty", st.Running)
	if st.ConfirmBy != nil {
		msg += ", on probation until someone runs confirm"
	}
	if st.Pending {
		msg += "; a candidate is waiting in the gatehouse"
	}
	fmt.Println(msg + ".")
	return nil
}
