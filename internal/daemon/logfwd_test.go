package daemon

import (
	"strings"
	"testing"

	"github.com/stevejboyle/hobby-ngfw/internal/accounts"
	"github.com/stevejboyle/hobby-ngfw/internal/config"
	"github.com/stevejboyle/hobby-ngfw/internal/logfwd"
)

type fakeFwd struct {
	servers [][]config.LogServer
	tested  []string
}

func (f *fakeFwd) Configure(s []config.LogServer) []string {
	f.servers = append(f.servers, s)
	return nil
}

func (f *fakeFwd) Status() logfwd.Status {
	st := logfwd.Status{Servers: []logfwd.ServerStatus{}}
	if n := len(f.servers); n > 0 {
		for _, s := range f.servers[n-1] {
			st.Servers = append(st.Servers, logfwd.ServerStatus{Name: s.Name})
		}
	}
	return st
}

func (f *fakeFwd) Test(name, by string) error {
	f.tested = append(f.tested, name+" "+by)
	return nil
}

func TestCommitConfiguresLogForwarding(t *testing.T) {
	d, _ := setup(t)
	f := &fakeFwd{}
	d.SetLogForwarder(f)
	cfg := string(lab(t)) + "\nlog_servers:\n  - name: siem\n    address: 10.0.0.50\n    transport: udp\n    vrf: default\n"
	if err := d.SetCandidate([]byte(cfg)); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Commit("test", "logs", 0); err != nil {
		t.Fatal(err)
	}
	last := f.servers[len(f.servers)-1]
	if len(last) != 1 || last[0].Name != "siem" || last[0].Transport != "udp" {
		t.Fatalf("forwarder got %+v", last)
	}
	if st := d.LogForwarding(); len(st.Servers) != 1 {
		t.Fatalf("status %+v", st)
	}
	if err := d.TestLogServer(accounts.Caller{}, "siem"); err != nil || len(f.tested) != 1 {
		t.Fatalf("test: %v %v", err, f.tested)
	}
	// Removing the servers stops forwarding.
	if err := d.SetCandidate(lab(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Commit("test", "no logs", 0); err != nil {
		t.Fatal(err)
	}
	if last := f.servers[len(f.servers)-1]; len(last) != 0 {
		t.Fatalf("after removal %+v", last)
	}
}

func TestLogServersWithoutForwarder(t *testing.T) {
	d, _ := setup(t)
	cfg := string(lab(t)) + "\nlog_servers:\n  - name: siem\n    address: 10.0.0.50\n"
	if err := d.SetCandidate([]byte(cfg)); err != nil {
		t.Fatal(err)
	}
	res, err := d.Commit("test", "logs", 0)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(res.Warnings, "\n"), "log forwarding isn't available") {
		t.Fatalf("warnings %v", res.Warnings)
	}
}
