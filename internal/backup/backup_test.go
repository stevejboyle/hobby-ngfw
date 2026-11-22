package backup

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stevejboyle/hobby-ngfw/internal/accounts"
)

const cfg = "system:\n  hostname: fw1\n"

func hdr() Header {
	return Header{SJBOS: "0.9.11-r01", Created: time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC), By: "cli:admin", Hostname: "fw1", Revision: 7}
}

func TestConfigOnlyRoundTrip(t *testing.T) {
	data, err := Seal(hdr(), Payload{Config: cfg}, "")
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	if !strings.HasPrefix(s, "SJB-OS backup of fw1, 2026-11-21T10:00:00Z, by cli:admin: config, not encrypted\n"+Begin) || !strings.HasSuffix(s, End+"\n") {
		t.Fatalf("armour:\n%s", s)
	}
	h, p, err := Open(data, "")
	if err != nil {
		t.Fatal(err)
	}
	if p.Config != cfg || h.Has(ContentAccounts) || h.Encrypted() || h.Revision != 7 {
		t.Fatalf("%+v %+v", h, p)
	}
	// Pasted with extra blank lines and indentation still opens.
	pasted := strings.ReplaceAll(s, "\n", "\n  \n")
	if _, _, err := Open([]byte(pasted), ""); err != nil {
		t.Fatalf("pasted: %v", err)
	}
	if FileName(h) != "sjb-os-fw1-20261121-100000.backup" {
		t.Errorf("file name %q", FileName(h))
	}
}

func TestEncryptedRoundTrip(t *testing.T) {
	keys := "tagger tags:read,tags:write 0123456789abcdef01234567\n"
	snap := &accounts.Snapshot{Users: []accounts.SnapshotUser{{Name: "alice", Role: "admin"}}}
	data, err := Seal(hdr(), Payload{Config: cfg, Accounts: snap, APIKeys: &keys}, "a long passphrase")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("alice")) {
		t.Fatal("user name in clear")
	}
	h, err := Inspect(data)
	if err != nil || !h.Encrypted() || !h.Has(ContentAccounts) {
		t.Fatalf("inspect %+v %v", h, err)
	}
	h, p, err := Open(data, "a long passphrase")
	if err != nil {
		t.Fatal(err)
	}
	if p.Accounts.Users[0].Name != "alice" || *p.APIKeys != keys {
		t.Fatalf("%+v", p)
	}
	if _, _, err := Open(data, "the wrong passphrase"); !errors.Is(err, ErrPassphrase) {
		t.Fatalf("wrong passphrase: %v", err)
	}
	if _, _, err := Open(data, ""); !errors.Is(err, ErrPassphrase) {
		t.Fatalf("no passphrase: %v", err)
	}
}

// reseal decodes a backup's envelope, lets f change it, and armours it again.
func reseal(t *testing.T, data []byte, f func(h map[string]any, env *envelope)) []byte {
	t.Helper()
	env, _, err := unarmor(data)
	if err != nil {
		t.Fatal(err)
	}
	var h map[string]any
	json.Unmarshal(env.Header, &h)
	f(h, &env)
	env.Header, _ = json.Marshal(h)
	raw, _ := json.Marshal(env)
	return []byte(Begin + "\n" + base64.StdEncoding.EncodeToString(raw) + "\n" + End + "\n")
}

func TestRefusals(t *testing.T) {
	if _, err := Seal(hdr(), Payload{Config: cfg, Accounts: &accounts.Snapshot{}}, ""); !errors.Is(err, ErrPassphrase) {
		t.Errorf("accounts without a passphrase: %v", err)
	}
	if _, err := Seal(hdr(), Payload{Config: cfg}, "short"); !errors.Is(err, ErrPassphrase) {
		t.Errorf("short passphrase: %v", err)
	}
	if _, err := Seal(hdr(), Payload{}, ""); !errors.Is(err, ErrInvalid) {
		t.Errorf("empty config: %v", err)
	}
	plain, _ := Seal(hdr(), Payload{Config: cfg}, "")
	enc, _ := Seal(hdr(), Payload{Config: cfg, Accounts: &accounts.Snapshot{}}, "a long passphrase")
	cases := []struct {
		name string
		data []byte
		pass string
		want string
	}{
		{"not a backup", []byte("hello"), "", "no -----BEGIN"},
		{"base64", []byte(Begin + "\n!!!\n" + End), "", "base64"},
		{"payload changed", reseal(t, plain, func(_ map[string]any, e *envelope) {
			e.Payload = base64.StdEncoding.EncodeToString([]byte(`{"config":"system: {hostname: evil}"}`))
		}), "", "checksum mismatch"},
		{"header changed (encrypted)", reseal(t, enc, func(h map[string]any, _ *envelope) { h["by"] = "cli:mallory" }), "a long passphrase", "wrong passphrase, or the file was changed"},
		{"accounts claimed unencrypted", reseal(t, plain, func(h map[string]any, _ *envelope) { h["contents"] = []string{"config", "accounts"} }), "", "contents don't match"},
		{"newer format", reseal(t, plain, func(h map[string]any, _ *envelope) { h["version"] = 2; h["sjb_os"] = "1.2.0" }), "", "newer SJB-OS (1.2.0"},
		{"other format", reseal(t, plain, func(h map[string]any, _ *envelope) { h["format"] = "zip" }), "", `format "zip"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := Open(tc.data, tc.pass)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}
