// Package nfqueue reports whether NFQUEUE queues have a listener, from the
// kernel's table in /proc/net/netfilter/nfnetlink_queue. The ruleset hands
// packets to App Identification (queues 0-1) and the IPS (queues 2-3) with
// the bypass flag: with no listener bound, packets go straight on,
// unclassified or uninspected. A running process is not proof of either;
// a bound queue is.
package nfqueue

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

// Path is the kernel's NFQUEUE table.
const Path = "/proc/net/netfilter/nfnetlink_queue"

// State is what the kernel says about a set of queues.
type State struct {
	Bound   bool   // every queue asked about has a listener
	Dropped uint64 // packets dropped or failed open because a queue was full
}

// Read reports on queues (e.g. 2, 3) from the table at path (empty: Path).
// A missing table means no queue is bound.
func Read(path string, queues ...int) State {
	if path == "" {
		path = Path
	}
	f, err := os.Open(path)
	if err != nil {
		return State{}
	}
	defer f.Close()
	want := map[int]bool{}
	for _, q := range queues {
		want[q] = false
	}
	var st State
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		// queue_number peer_portid queue_total copy_mode copy_range
		// queue_dropped user_dropped id_sequence 1
		fl := strings.Fields(sc.Text())
		if len(fl) < 7 {
			continue
		}
		q, err := strconv.Atoi(fl[0])
		if err != nil {
			continue
		}
		if _, ok := want[q]; !ok {
			continue
		}
		if portid, _ := strconv.ParseUint(fl[1], 10, 32); portid != 0 {
			want[q] = true
		}
		qd, _ := strconv.ParseUint(fl[5], 10, 64)
		ud, _ := strconv.ParseUint(fl[6], 10, 64)
		st.Dropped += qd + ud
	}
	st.Bound = len(want) > 0
	for _, ok := range want {
		st.Bound = st.Bound && ok
	}
	return st
}
