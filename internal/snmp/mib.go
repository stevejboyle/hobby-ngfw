package snmp

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/stevejboyle/sjb-os/internal/metrics"
)

// Base is SJB-OS's subtree (SJB-OS-MIB). It sits under net-snmp's
// experimental arc until SJB Consulting has an IANA Private Enterprise
// Number; moving it is this constant and the MIB file.
const Base = ".1.3.6.1.4.1.8072.9999.9999.7"

// Object identifiers in SJB-OS-MIB (relative to Base).
const (
	oidSystem     = ".1" // version .1, hostname .2, snapshotAge .3, ngfwdUp .4, uptime .5, rebootRequired .6, osPackagesState .7, osPackagesPending .8
	oidConfig     = ".2" // runningRevision .1, uncommitted .2, lastCommitOK .3, recovery .4
	oidSessions   = ".3" // count .1, max .2
	oidIPS        = ".4" // state .1, up .2, loaded .3, queueDropped .4, exceptionsActive .5, exceptionsInactive .6, fault .7
	oidDecryption = ".5" // state .1, up .2, active .3
	oidAppID      = ".6" // enabled .1, up .2

	oidServiceTable = ".10" // entry .1: index .1, name .2, up .3, used .4, fault .5
	oidRuleTable    = ".11" // entry .1: index .1, name .2, action .3, packets .4, bytes .5
	oidNATTable     = ".12" // entry .1: index .1, name .2, type .3, hits .4, outHits .5, hairpin .6
	oidLogTable     = ".13" // entry .1: index .1, name .2, connected .3, sent .4, dropped .5, queued .6
	oidThreatTable  = ".14" // entry .1: index .1, severity .2, blocked .3, alerted .4
	oidCollectTable = ".15" // entry .1: index .1, section .2, state .3, age .4
)

// Collection states in sjbCollectionTable.
var collectState = map[string]string{metrics.Current: "1", metrics.Stale: "2", metrics.Never: "3", metrics.Failed: "4"}

// Trigger objects (absolute), for snmpd's monitors.
const (
	OIDIPSFault     = Base + oidIPS + ".7.0"
	OIDLastCommitOK = Base + oidConfig + ".3.0"
	OIDServiceFault = Base + oidServiceTable + ".1.5"
	OIDServiceName  = Base + oidServiceTable + ".1.2"
	OIDCommitNote   = Base + oidConfig + ".5.0"
	OIDNgfwdUp      = Base + oidSystem + ".4.0"
	OIDSnapshotAge  = Base + oidSystem + ".3.0"
)

// StaleAfter is how old a snapshot may get before the agent reports ngfwd
// down (ngfwd saves one every 15 s).
const StaleAfter = 60 * time.Second

// varbind is one object: its OID as numbers, a pass_persist type and value.
type varbind struct {
	oid []uint32
	typ string // integer, gauge, counter64, string, timeticks
	val string
}

func parseOID(s string) []uint32 {
	var out []uint32
	for _, p := range strings.Split(strings.Trim(s, "."), ".") {
		if p == "" {
			continue
		}
		n, err := strconv.ParseUint(p, 10, 32)
		if err != nil {
			return nil
		}
		out = append(out, uint32(n))
	}
	return out
}

func oidString(o []uint32) string {
	var b strings.Builder
	for _, n := range o {
		b.WriteByte('.')
		b.WriteString(strconv.FormatUint(uint64(n), 10))
	}
	return b.String()
}

func less(a, b []uint32) bool {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return len(a) < len(b)
}

func b2i(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// cleanString keeps a string value on one line.
func cleanString(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
}

// Objects turns a snapshot into SJB-OS-MIB's objects, sorted. ok is false
// when there's no snapshot yet (SNMP just turned on): nothing to report,
// and no alarm. A snapshot older than StaleAfter means ngfwd stopped
// saving them: ngfwd reads as down. age is how old the snapshot is.
func Objects(s metrics.Snapshot, ok bool, age time.Duration) []varbind {
	stale := ok && age > StaleAfter
	var out []varbind
	add := func(rel, typ, val string) {
		out = append(out, varbind{parseOID(Base + rel), typ, val})
	}
	str := func(rel, v string) { add(rel, "string", cleanString(v)) }
	num := func(rel string, v int64) { add(rel, "integer", strconv.FormatInt(v, 10)) }
	gauge := func(rel string, v uint64) {
		if v > 4294967295 {
			v = 4294967295
		}
		add(rel, "gauge", strconv.FormatUint(v, 10))
	}
	c64 := func(rel string, v uint64) { add(rel, "counter64", strconv.FormatUint(v, 10)) }

	ageSec := int64(age / time.Second)
	if !ok {
		ageSec = -1
	}
	str(oidSystem+".1.0", s.Version)
	str(oidSystem+".2.0", s.Hostname)
	num(oidSystem+".3.0", ageSec)
	add(oidSystem+".4.0", "integer", b2i(!stale))
	add(oidSystem+".5.0", "timeticks", strconv.FormatInt(int64(s.System.UptimeSeconds*100), 10))
	if o := s.System.OS; o != nil {
		add(oidSystem+".6.0", "integer", b2i(o.RebootRequired))
		st := 0
		for i, name := range metrics.OSStates {
			if o.PackagesState == name {
				st = i + 1
			}
		}
		num(oidSystem+".7.0", int64(st))
		gauge(oidSystem+".8.0", uint64(o.PackagesPending))
	}

	num(oidConfig+".1.0", int64(s.Config.RunningRevision))
	add(oidConfig+".2.0", "integer", b2i(s.Config.Uncommitted))
	add(oidConfig+".3.0", "integer", b2i(!ok || s.Config.LastCommitOK))
	add(oidConfig+".4.0", "integer", b2i(s.Config.Recovery))
	str(oidConfig+".5.0", s.Config.LastCommitNote)

	gauge(oidSessions+".1.0", s.Sessions.Count)
	gauge(oidSessions+".2.0", s.Sessions.Max)

	ipsUsed := false
	for _, sv := range s.Services {
		if sv.Name == "suricata" {
			ipsUsed = sv.Used
		}
	}
	str(oidIPS+".1.0", s.IPS.State)
	add(oidIPS+".2.0", "integer", b2i(s.IPS.Up))
	gauge(oidIPS+".3.0", uint64(max(s.IPS.Loaded, 0)))
	c64(oidIPS+".4.0", s.IPS.QueueDropped)
	gauge(oidIPS+".5.0", uint64(s.IPS.ExceptionsActive))
	gauge(oidIPS+".6.0", uint64(s.IPS.ExceptionsIdle))
	// A fault only on a fresh reading: stale or missing values never raise
	// (or clear) an alarm.
	add(oidIPS+".7.0", "integer", b2i(ok && !stale && s.Fresh("ips") && ipsUsed && !s.IPS.Up))

	str(oidDecryption+".1.0", s.Decryption.State)
	add(oidDecryption+".2.0", "integer", b2i(s.Decryption.Up))
	gauge(oidDecryption+".3.0", uint64(max(s.Decryption.Active, 0)))

	add(oidAppID+".1.0", "integer", b2i(s.AppID.Enabled))
	add(oidAppID+".2.0", "integer", b2i(s.AppID.Up))

	// Tables: column-major order is OID order (entry.column.index).
	services := s.Services
	if !ok {
		services = nil
	}
	if stale {
		// ngfwd isn't saving snapshots: say so, whatever the old one said.
		services = []metrics.Service{{Name: "ngfwd", Up: false, Used: true}}
	}
	table := func(rel string, rows int, cols []func(i int) (string, string)) {
		for c, col := range cols {
			for i := 0; i < rows; i++ {
				typ, val := col(i)
				add(fmt.Sprintf("%s.1.%d.%d", rel, c+1, i+1), typ, val)
			}
		}
	}
	idx := func(i int) (string, string) { return "integer", strconv.Itoa(i + 1) }
	table(oidServiceTable, len(services), []func(int) (string, string){
		idx,
		func(i int) (string, string) { return "string", cleanString(services[i].Name) },
		func(i int) (string, string) { return "integer", b2i(services[i].Up) },
		func(i int) (string, string) { return "integer", b2i(services[i].Used) },
		func(i int) (string, string) {
			return "integer", b2i(services[i].Used && !services[i].Up && !services[i].Unknown)
		},
	})
	table(oidRuleTable, len(s.Rules), []func(int) (string, string){
		idx,
		func(i int) (string, string) { return "string", cleanString(s.Rules[i].Name) },
		func(i int) (string, string) { return "string", s.Rules[i].Action },
		func(i int) (string, string) { return "counter64", strconv.FormatUint(s.Rules[i].Packets, 10) },
		func(i int) (string, string) { return "counter64", strconv.FormatUint(s.Rules[i].Bytes, 10) },
	})
	table(oidNATTable, len(s.NAT), []func(int) (string, string){
		idx,
		func(i int) (string, string) { return "string", cleanString(s.NAT[i].Name) },
		func(i int) (string, string) { return "string", s.NAT[i].Type },
		func(i int) (string, string) { return "counter64", strconv.FormatUint(s.NAT[i].Hits, 10) },
		func(i int) (string, string) { return "counter64", strconv.FormatUint(s.NAT[i].OutHits, 10) },
		func(i int) (string, string) { return "counter64", strconv.FormatUint(s.NAT[i].Hairpin, 10) },
	})
	table(oidLogTable, len(s.LogServers), []func(int) (string, string){
		idx,
		func(i int) (string, string) { return "string", cleanString(s.LogServers[i].Name) },
		func(i int) (string, string) { return "integer", b2i(s.LogServers[i].Connected) },
		func(i int) (string, string) { return "counter64", strconv.FormatUint(s.LogServers[i].Sent, 10) },
		func(i int) (string, string) { return "counter64", strconv.FormatUint(s.LogServers[i].Dropped, 10) },
		func(i int) (string, string) { return "gauge", strconv.Itoa(max(s.LogServers[i].Queued, 0)) },
	})
	table(oidThreatTable, len(s.Threats), []func(int) (string, string){
		idx,
		func(i int) (string, string) { return "string", s.Threats[i].Severity },
		func(i int) (string, string) { return "counter64", strconv.FormatUint(s.Threats[i].Blocked, 10) },
		func(i int) (string, string) { return "counter64", strconv.FormatUint(s.Threats[i].Alerted, 10) },
	})
	var secs []string
	if ok {
		secs = metrics.Sections
	}
	table(oidCollectTable, len(secs), []func(int) (string, string){
		idx,
		func(i int) (string, string) { return "string", secs[i] },
		func(i int) (string, string) {
			st := s.Sections[secs[i]].State
			if collectState[st] == "" {
				st = metrics.Never
			}
			return "integer", collectState[st]
		},
		func(i int) (string, string) {
			at := s.Sections[secs[i]].CollectedAt
			if at == nil {
				return "integer", "-1"
			}
			return "integer", strconv.FormatInt(int64(s.Time.Sub(*at)/time.Second)+int64(age/time.Second), 10)
		},
	})
	sort.Slice(out, func(i, j int) bool { return less(out[i].oid, out[j].oid) })
	return out
}

// Pass answers snmpd's pass_persist protocol on in/out: PING, get and
// getnext, reading the snapshot at path (re-read when it changes). Sets
// are refused (the agent is read-only).
func Pass(in io.Reader, out io.Writer, path string, now func() time.Time) error {
	r := bufio.NewReader(in)
	w := bufio.NewWriter(out)
	var (
		objs  []varbind
		mtime time.Time
		at    time.Time // when objs were built
	)
	load := func() {
		t := now()
		fi, err := os.Stat(path)
		if err == nil && objs != nil && fi.ModTime().Equal(mtime) && t.Sub(at) < 5*time.Second {
			return
		}
		var s metrics.Snapshot
		ok := false
		if err == nil {
			if s, err = metrics.Load(path); err == nil {
				ok, mtime = true, fi.ModTime()
			}
		}
		age := time.Duration(0)
		if ok {
			age = t.Sub(s.Time)
		}
		objs, at = Objects(s, ok, age), t
	}
	line := func() (string, error) {
		s, err := r.ReadString('\n')
		return strings.TrimSpace(s), err
	}
	for {
		cmd, err := line()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		switch cmd {
		case "":
			return nil // snmpd closes with an empty line
		case "PING":
			w.WriteString("PONG\n")
		case "get", "getnext":
			oidText, err := line()
			if err != nil {
				return err
			}
			load()
			oid := parseOID(oidText)
			var hit *varbind
			for i := range objs {
				if cmd == "get" && oidString(objs[i].oid) == oidString(oid) {
					hit = &objs[i]
					break
				}
				if cmd == "getnext" && less(oid, objs[i].oid) {
					hit = &objs[i]
					break
				}
			}
			if hit == nil {
				w.WriteString("NONE\n")
			} else {
				fmt.Fprintf(w, "%s\n%s\n%s\n", oidString(hit.oid), hit.typ, hit.val)
			}
		case "set":
			line() // OID
			line() // type and value
			w.WriteString("not-writable\n")
		default:
			w.WriteString("NONE\n")
		}
		if err := w.Flush(); err != nil {
			return err
		}
	}
}
