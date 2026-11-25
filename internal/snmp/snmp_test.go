package snmp

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stevejboyle/sjb-os/internal/config"
	"github.com/stevejboyle/sjb-os/internal/metrics"
)

var update = flag.Bool("update", false, "rewrite golden files")

func creds() *Credentials {
	return &Credentials{
		InternalPass: "internal-passphrase-000",
		List: []Credential{
			{Name: "nms", Kind: KindV3, Auth: "SHA-256", AuthPass: "auth-pass-1", Priv: "AES", PrivPass: "priv-pass-1"},
			{Name: "lab-ro", Kind: KindV2c, Community: "lab-community"},
		},
	}
}

func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		os.MkdirAll("testdata", 0o755)
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test ./internal/snmp -update)", err)
	}
	if string(want) != got {
		t.Errorf("%s differs:\n%s", name, got)
	}
}

func TestCompile(t *testing.T) {
	base := func() *config.Config {
		c := &config.Config{}
		c.System.Hostname = "sjb-fw"
		c.SNMP = config.SNMP{Enabled: "on", Location: "Lab rack 1", Contact: "steve", V3Users: []string{"nms"}}
		return c
	}
	cases := map[string]func(*config.Config){
		"v3-only.conf": func(c *config.Config) {},
		"v2c-traps.conf": func(c *config.Config) {
			c.SNMP.Communities = []string{"lab-ro"}
			c.SNMP.Managers = []string{"192.168.1.0/24", "10.0.0.5"}
			c.SNMPTrapReceivers = []config.SNMPTrapReceiver{
				{Name: "graylog", Address: "192.168.1.62", Credential: "nms", Inform: "on"},
				{Name: "old-nms", Address: "192.168.1.63", Port: 1162, Credential: "lab-ro"},
			}
		},
	}
	for name, mod := range cases {
		c := base()
		mod(c)
		if err := c.Validate(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		got, err := Compile(c, creds())
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		golden(t, name, got)
	}
	off := base()
	off.SNMP.Enabled = "off"
	if got, err := Compile(off, creds()); got != "" || err != nil {
		t.Errorf("off: %q %v", got, err)
	}
	// Missing and mismatched credentials.
	bad := base()
	bad.SNMP.V3Users = []string{"lab-ro", "ghost"}
	bad.SNMPTrapReceivers = []config.SNMPTrapReceiver{{Name: "r", Address: "192.168.1.9", Credential: "lab-ro", Inform: "on"}}
	_, err := Compile(bad, creds())
	for _, want := range []string{`"lab-ro" is a v2c credential, not v3`, `no SNMP credential "ghost"`, "informs need a v3 credential"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("want %q in %v", want, err)
		}
	}
	if UsedBy(base(), "nms") == "" || UsedBy(base(), "lab-ro") != "" {
		t.Error("UsedBy")
	}
}

func TestConfigValidation(t *testing.T) {
	c := &config.Config{}
	c.SNMP = config.SNMP{Enabled: "yes", Location: `say "hi"`, Communities: []string{"ro"}, V3Users: []string{"ro"}, Managers: []string{"nope"}}
	c.SNMPTrapReceivers = []config.SNMPTrapReceiver{{Name: "a", Address: "10.0.0.1"}, {Name: "a", Address: "10.0.0.1", Inform: "maybe"}}
	err := c.Validate()
	for _, want := range []string{"enabled must be on or off", "location", `"ro" is already listed`, `"nope": not an IPv4 address`, "duplicate name", "credential required", "inform must be on or off", "same address and port"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("want %q in %v", want, err)
		}
	}
	c = &config.Config{}
	c.SNMP = config.SNMP{Enabled: "on", Communities: []string{"ro"}}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "v2c_communities need managers") {
		t.Errorf("communities without managers: %v", err)
	}
}

func TestCredentials(t *testing.T) {
	for _, tc := range []struct {
		c    Credential
		want string
	}{
		{Credential{Name: "nms", Kind: KindV3, Auth: "SHA-256", AuthPass: "auth-pass-1", Priv: "AES", PrivPass: "priv-pass-1"}, ""},
		{Credential{Name: "nms", Kind: KindV3, Auth: "MD5", AuthPass: "auth-pass-1", Priv: "DES", PrivPass: "priv-pass-1"}, "auth must be"},
		{Credential{Name: "nms", Kind: KindV3, Auth: "SHA-256", AuthPass: "short", Priv: "AES", PrivPass: "priv-pass-1"}, "passphrases"},
		{Credential{Name: "nms", Kind: KindV3, Auth: "SHA-256", AuthPass: "same-pass-1", Priv: "AES", PrivPass: "same-pass-1"}, "different"},
		{Credential{Name: "ro", Kind: KindV2c, Community: "has space x"}, "community"},
		{Credential{Name: InternalUser, Kind: KindV2c, Community: "community1"}, "reserved"},
		{Credential{Name: "bad name", Kind: "v1"}, "kind must be"},
	} {
		err := tc.c.Check()
		if (tc.want == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), tc.want)) {
			t.Errorf("%+v: got %v, want %q", tc.c, err, tc.want)
		}
	}
	if NormalizeAuth("sha256") != "SHA-256" || NormalizePriv("aes256") != "AES-256" || NormalizePriv("aes") != "AES" {
		t.Error("normalize")
	}
	path := filepath.Join(t.TempDir(), "snmp-credentials")
	cs := creds()
	cs.InternalPass = ""
	if err := cs.EnsureInternal(); err != nil || len(cs.InternalPass) < 24 {
		t.Fatal(err)
	}
	if err := Save(path, cs); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", fi.Mode())
	}
	got, err := Load(path)
	if err != nil || len(got.List) != 2 || got.InternalPass != cs.InternalPass {
		t.Fatalf("load: %+v %v", got, err)
	}
	if c, ok := got.Get("nms"); !ok || c.Info() != (Info{Name: "nms", Kind: KindV3, Auth: "SHA-256", Priv: "AES"}) {
		t.Errorf("get: %+v", c)
	}
	empty, err := Load(filepath.Join(t.TempDir(), "none"))
	if err != nil || len(empty.List) != 0 {
		t.Errorf("missing file: %v", err)
	}
	b, _ := got.Marshal()
	if back, err := Parse(b); err != nil || len(back.List) != 2 {
		t.Errorf("parse: %v", err)
	}
}

func snapshot(at time.Time) metrics.Snapshot {
	s := metrics.Snapshot{
		Time: at, Version: "0.9.13-r01", Hostname: "sjb-fw",
		Config:   metrics.Config{RunningRevision: 4, LastCommitOK: true},
		Services: []metrics.Service{{Name: "ngfwd", Up: true, Used: true}, {Name: "suricata", Used: true}, {Name: "kea"}},
		Sessions: metrics.Sessions{Count: 12, Max: 1000},
		Rules:    []metrics.Rule{{Name: "web", Action: "allow", Packets: 5, Bytes: 500}, {Name: "default-deny", Action: "deny", Packets: 1, Bytes: 60}},
		IPS:      metrics.IPS{State: "unavailable", Matches: map[string]map[string]uint64{"major": {"block": 2}}},
	}
	s.FillThreats()
	return s
}

// talk runs the pass_persist protocol over a script and returns the replies.
func talk(t *testing.T, path, script string, now time.Time) []string {
	t.Helper()
	var out bytes.Buffer
	if err := Pass(strings.NewReader(script), &out, path, func() time.Time { return now }); err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
}

func TestPass(t *testing.T) {
	now := time.Unix(1795400000, 0)
	path := filepath.Join(t.TempDir(), "metrics.json")
	if err := metrics.Save(path, snapshot(now.Add(-10*time.Second)), 0o644, -1); err != nil {
		t.Fatal(err)
	}
	got := talk(t, path, "PING\nget\n"+Base+".2.1.0\nget\n"+Base+".1.4.0\ngetnext\n"+Base+"\nget\n"+Base+".99.0\nset\n"+Base+".1.1.0\nstring x\n\n", now)
	want := []string{
		"PONG",
		Base + ".2.1.0", "integer", "4",
		Base + ".1.4.0", "integer", "1",
		Base + ".1.1.0", "string", "0.9.13-r01",
		"NONE",
		"not-writable",
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("replies:\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	// Walk the whole subtree with getnext: strictly increasing, ends NONE.
	walk := func(now time.Time) map[string]string {
		vals := map[string]string{}
		oid := Base
		var last []uint32
		for i := 0; i < 500; i++ {
			r := talk(t, path, "getnext\n"+oid+"\n", now)
			if r[0] == "NONE" {
				return vals
			}
			cur := parseOID(r[0])
			if last != nil && !less(last, cur) {
				t.Fatalf("walk not increasing at %s", r[0])
			}
			last, oid = cur, r[0]
			vals[strings.TrimPrefix(r[0], Base)] = r[1] + " " + r[2]
		}
		t.Fatal("walk didn't end")
		return nil
	}
	v := walk(now)
	for k, want := range map[string]string{
		".10.1.2.2": "string suricata",
		".10.1.5.2": "integer 1", // suricata used and down: a fault
		".10.1.5.3": "integer 0", // kea down but unused: fine
		".11.1.2.1": "string web",
		".11.1.4.1": "counter64 5",
		".14.1.3.2": "counter64 2", // major blocked
		".3.1.0":    "gauge 12",
		".4.7.0":    "integer 1", // IPS used and not running
		".2.3.0":    "integer 1",
	} {
		if v[k] != want {
			t.Errorf("%s = %q, want %q", k, v[k], want)
		}
	}

	// A stale snapshot reads as ngfwd down, and only that service row.
	v = walk(now.Add(5 * time.Minute))
	if v[".1.4.0"] != "integer 0" || v[".10.1.2.1"] != "string ngfwd" || v[".10.1.5.1"] != "integer 1" || v[".10.1.2.2"] != "" {
		t.Errorf("stale: %v", v)
	}
	// No snapshot at all: the same, and no false IPS or commit alarm.
	os.Remove(path)
	v = walk(now)
	if v[".1.4.0"] != "integer 0" || v[".4.7.0"] != "integer 0" || v[".2.3.0"] != "integer 1" {
		t.Errorf("missing: %v", v)
	}
}
