package metrics

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// ReadSystem reads uptime, CPU time, load, memory and the free space of
// mounts from the filesystem under root ("/" on the appliance). Anything
// unreadable is left zero.
func ReadSystem(root string, mounts []string) System {
	s := System{CPUSeconds: map[string]float64{}}
	if b, err := os.ReadFile(filepath.Join(root, "proc/uptime")); err == nil {
		if f := strings.Fields(string(b)); len(f) > 0 {
			s.UptimeSeconds, _ = strconv.ParseFloat(f[0], 64)
		}
	}
	if b, err := os.ReadFile(filepath.Join(root, "proc/loadavg")); err == nil {
		f := strings.Fields(string(b))
		for i := 0; i < 3 && i < len(f); i++ {
			s.Load[i], _ = strconv.ParseFloat(f[i], 64)
		}
	}
	readCPU(filepath.Join(root, "proc/stat"), &s)
	readMem(filepath.Join(root, "proc/meminfo"), &s)
	for _, m := range mounts {
		var st syscall.Statfs_t
		if err := syscall.Statfs(filepath.Join(root, m), &st); err != nil {
			continue
		}
		bs := uint64(st.Bsize)
		s.Disks = append(s.Disks, Disk{Mount: m, Size: st.Blocks * bs, Free: st.Bavail * bs})
	}
	return s
}

// userHZ is the kernel's clock tick for /proc/stat (100 on Linux/amd64).
const userHZ = 100

func readCPU(path string, s *System) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) == 0 {
			continue
		}
		if fields[0] == "cpu" {
			// user nice system idle iowait irq softirq steal ...
			names := []string{"user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal"}
			for i, v := range fields[1:] {
				n, err := strconv.ParseFloat(v, 64)
				if err != nil {
					continue
				}
				mode := "other"
				if i < len(names) {
					mode = names[i]
				}
				switch mode {
				case "nice":
					mode = "user"
				case "irq", "softirq", "steal":
					mode = "other"
				}
				if i >= 8 { // guest time is already counted in user
					continue
				}
				s.CPUSeconds[mode] += n / userHZ
			}
		} else if strings.HasPrefix(fields[0], "cpu") {
			s.CPUs++
		}
	}
}

func readMem(path string, s *System) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		n, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}
		switch fields[0] {
		case "MemTotal:":
			s.MemTotal = n * 1024
		case "MemAvailable:":
			s.MemAvailable = n * 1024
		}
	}
}

// ReadInterface reads one interface's counters and state from
// /sys/class/net under root. ok is false when it doesn't exist.
func ReadInterface(root, name string) (Interface, bool) {
	in := Interface{Name: name}
	dir := filepath.Join(root, "sys/class/net", name)
	if _, err := os.Stat(dir); err != nil {
		return in, false
	}
	read := func(f string) uint64 {
		b, err := os.ReadFile(filepath.Join(dir, "statistics", f))
		if err != nil {
			return 0
		}
		n, _ := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
		return n
	}
	in.RxBytes, in.TxBytes = read("rx_bytes"), read("tx_bytes")
	in.RxPackets, in.TxPackets = read("rx_packets"), read("tx_packets")
	in.RxErrors, in.TxErrors = read("rx_errors"), read("tx_errors")
	in.RxDropped, in.TxDropped = read("rx_dropped"), read("tx_dropped")
	if b, err := os.ReadFile(filepath.Join(dir, "operstate")); err == nil {
		st := strings.TrimSpace(string(b))
		in.Up = st == "up" || st == "unknown" // unknown: virtual devices that are up
	}
	return in, true
}

// ReadSessions reads the conntrack table's size and limit.
func ReadSessions(root string) Sessions {
	var s Sessions
	read := func(f string) uint64 {
		b, err := os.ReadFile(filepath.Join(root, "proc/sys/net/netfilter", f))
		if err != nil {
			return 0
		}
		n, _ := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
		return n
	}
	s.Count, s.Max = read("nf_conntrack_count"), read("nf_conntrack_max")
	return s
}
