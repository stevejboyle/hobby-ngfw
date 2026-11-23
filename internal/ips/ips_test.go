package ips

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/md5"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const sample = `# comment
alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"ET SCAN ssh"; flow:to_server; sid:2001219; rev:20; metadata:created_at 2010_07_30, signature_severity Major;)
# alert http any any -> any any (msg:"disabled upstream"; sid:2000001; rev:1;)
drop ip any any -> any any (msg:"was drop"; sid:2000002; rev:1; metadata:signature_severity Critical;)
alert ip any any -> any any (msg:"no severity"; sid:2000003; rev:1;)
pass ip 10.0.0.1 any -> any any (msg:"pass"; sid:2000004; rev:1;)
alert ip any any -> any any (msg:"turned off here"; sid:2000005; rev:1; metadata:signature_severity Minor;)
alert ip any any -> any any (msg:"unknown sev"; sid:2000006; rev:1; metadata:signature_severity Unknown;)
`

func TestProcess(t *testing.T) {
	// 2000002 and the critical test signature have IPS exceptions: their
	// matches carry the exception code instead of the plain bit.
	tu := Tuning{Disabled: map[int]bool{2000005: true, 9900004: true}, Codes: map[int]uint32{2000002: 0x000e0000, 9900001: 0x00160000}}
	out, counts := Process(map[string][]byte{"emerging-scan.rules": []byte(sample), "notes.txt": []byte("alert junk")}, tu)
	got := string(out)
	for _, want := range []string{
		`sid:2001219; rev:20; metadata:created_at 2010_07_30, signature_severity Major; nfq_set_mark:0x82000000/0x82000000;)`,
		`alert ip any any -> any any (msg:"was drop"; sid:2000002; rev:1; metadata:signature_severity Critical; nfq_set_mark:0x010e0000/0x010e0000;)`,
		`(msg:"no severity"; sid:2000003; rev:1; nfq_set_mark:0x88000000/0x88000000;)`,
		`pass ip 10.0.0.1 any -> any any (msg:"pass"; sid:2000004; rev:1;)`,
		`content:"SJB-IPS-TEST-CRITICAL"; nfq_set_mark:0x01160000/0x01160000; sid:9900001;`,
		`content:"SJB-IPS-TEST-MAJOR"; nfq_set_mark:0x82000000/0x82000000; sid:9900002;`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	for _, not := range []string{"2000001", "2000005", "9900004", "junk", "drop ip"} {
		if strings.Contains(got, not) {
			t.Errorf("%q should be left out:\n%s", not, got)
		}
	}
	// 3 test signatures (info disabled) + 6 ET lines kept.
	if counts["critical"] != 2 || counts["major"] != 2 || counts["minor"] != 1 || counts["informational"] != 3 || counts.Total() != 8 {
		t.Errorf("counts %v", counts)
	}
}

func tarball(t *testing.T, files map[string]string) []byte {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	tw.WriteHeader(&tar.Header{Name: "rules/", Typeflag: tar.TypeDir, Mode: 0o755})
	for n, c := range files {
		tw.WriteHeader(&tar.Header{Name: "rules/" + n, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(c))})
		tw.Write([]byte(c))
	}
	tw.Close()
	zw.Close()
	return buf.Bytes()
}

func TestUpdateAndBuild(t *testing.T) {
	tgz := tarball(t, map[string]string{"emerging-scan.rules": sample, "classification.config": "config classification: bad-unknown,Bad,2\n", "LICENSE": "x"})
	sum := md5.Sum(tgz)
	corrupt := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, ".md5"):
			if corrupt {
				w.Write([]byte("00000000000000000000000000000000\n"))
				return
			}
			w.Write([]byte(hex.EncodeToString(sum[:]) + "\n"))
		case strings.HasSuffix(r.URL.Path, "version.txt"):
			w.Write([]byte("11334\n"))
		default:
			w.Write(tgz)
		}
	}))
	defer srv.Close()
	dir := t.TempDir()
	reloads := 0
	e := &Engine{Dir: dir, URL: srv.URL + "/open/suricata-7.0.10/emerging.rules.tar.gz", Client: srv.Client(),
		Reload: func() error { reloads++; return nil }, Now: func() time.Time { return time.Date(2026, 11, 14, 3, 0, 0, 0, time.UTC) }}

	// Before any download: test signatures only.
	st, err := e.Build(Tuning{})
	if err != nil || st.Source != "test signatures only" || st.Signatures != 4 || !e.Installed() {
		t.Fatalf("%+v %v", st, err)
	}
	// The same rules again: no reload.
	if _, err := e.Build(Tuning{}); err != nil || reloads != 1 {
		t.Fatalf("unchanged rules reloaded: %d %v", reloads, err)
	}
	st, err = e.Update(context.Background(), Tuning{Disabled: map[int]bool{2000003: true}})
	if err != nil {
		t.Fatal(err)
	}
	if st.Source != "ET Open" || st.Version != "11334" || st.Signatures != 4+5 || st.Disabled != 1 || st.Updated.IsZero() || reloads != 2 {
		t.Fatalf("%+v reloads=%d", st, reloads)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, ClassFile)); !strings.Contains(string(b), "bad-unknown") {
		t.Fatalf("classification: %q", b)
	}
	// A bad checksum keeps the rules and says why.
	corrupt = true
	if _, err := e.Update(context.Background(), Tuning{}); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("got %v", err)
	}
	if st := e.Status(); st.LastError == "" || st.Signatures != 9 || st.Source != "ET Open" {
		t.Fatalf("after a failed update: %+v", st)
	}
	// Rebuilding from the kept download needs no network.
	srv.Close()
	if st, err := e.Build(Tuning{}); err != nil || st.Signatures != 10 {
		t.Fatalf("rebuild: %+v %v", st, err)
	}
}

func TestParseEVE(t *testing.T) {
	line := `{"timestamp":"2026-11-14T03:12:01.123456+0000","event_type":"alert","src_ip":"10.10.1.50","src_port":40000,"dest_ip":"93.184.216.34","dest_port":80,"proto":"TCP","alert":{"action":"allowed","signature_id":9900001,"signature":"SJB-OS IPS test signature (critical)","category":"","severity":3,"metadata":{"signature_severity":["critical"]}}}`
	a, ok := ParseEVE([]byte(line))
	if !ok || a.SID != 9900001 || a.Severity != "critical" || a.Proto != "tcp" || a.Src != "10.10.1.50" || a.DPort != 80 || a.Time.Second() != 1 {
		t.Fatalf("%+v %v", a, ok)
	}
	if _, ok := ParseEVE([]byte(`{"event_type":"stats"}`)); ok {
		t.Fatal("only alerts")
	}
}
