package upgrade

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func testIndex() *Index {
	return &Index{Schema: IndexSchema, Channel: IndexChannel, Published: time.Date(2026, 11, 28, 12, 0, 0, 0, time.UTC),
		Latest: Release{Version: "0.9.17-r01", MinFromVersion: "0.8.0", URL: "https://example.com/b.upgrade", Size: 1000,
			SHA256: strings.Repeat("ab", 32), Notes: "https://example.com/notes"}}
}

func TestIndexSignVerify(t *testing.T) {
	priv, keys := key(t)
	data, err := MarshalIndex(testIndex())
	if err != nil {
		t.Fatal(err)
	}
	sig := SignIndex(data, priv)
	ix, signer, err := VerifyIndex(data, sig, keys)
	if err != nil {
		t.Fatal(err)
	}
	if signer != keys[0].Name || ix.Latest.Version != "0.9.17-r01" || !ix.Published.Equal(testIndex().Published) {
		t.Errorf("got %+v by %q", ix, signer)
	}

	// Tampered contents, another key, a garbled signature file.
	bad := bytes.Replace(data, []byte("0.9.17-r01"), []byte("0.9.18-r01"), 1)
	if _, _, err := VerifyIndex(bad, sig, keys); err == nil {
		t.Error("tampered index accepted")
	}
	_, other := key(t)
	if _, _, err := VerifyIndex(data, sig, other); err == nil {
		t.Error("index accepted with the wrong key")
	}
	if _, _, err := VerifyIndex(data, []byte("not base64!"), keys); err == nil {
		t.Error("garbled signature accepted")
	}
	// A plain signature over the bytes (as a bundle signature is made) is
	// not an index signature.
	plain := ed25519.Sign(priv, data)
	if _, _, err := VerifyIndex(data, []byte(b64(plain)), keys); err == nil {
		t.Error("signature without the index domain accepted")
	}
}

func TestIndexCheck(t *testing.T) {
	for name, mod := range map[string]func(*Index){
		"http URL":       func(ix *Index) { ix.Latest.URL = "http://example.com/b.upgrade" },
		"no host":        func(ix *Index) { ix.Latest.URL = "https:///b.upgrade" },
		"user in URL":    func(ix *Index) { ix.Latest.URL = "https://u:p@example.com/b" },
		"size over cap":  func(ix *Index) { ix.Latest.Size = MaxBundleSize + 1 },
		"zero size":      func(ix *Index) { ix.Latest.Size = 0 },
		"bad sha":        func(ix *Index) { ix.Latest.SHA256 = "abc" },
		"bad version":    func(ix *Index) { ix.Latest.Version = "latest" },
		"bad min-from":   func(ix *Index) { ix.Latest.MinFromVersion = "x" },
		"schema":         func(ix *Index) { ix.Schema = 2 },
		"channel":        func(ix *Index) { ix.Channel = "beta" },
		"no publish":     func(ix *Index) { ix.Published = time.Time{} },
		"http notes URL": func(ix *Index) { ix.Latest.Notes = "http://example.com/n" },
	} {
		ix := testIndex()
		mod(ix)
		if _, err := MarshalIndex(ix); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
