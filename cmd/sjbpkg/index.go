package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/stevejboyle/sjb-os/internal/upgrade"
)

// index writes the release index an update server publishes for a bundle:
// OUT/v1/stable.json and its signature. The bundle is verified against the
// public half of the signing key first, so an index never names a bundle the
// appliances would refuse.
func index(args []string) error {
	fl := flag.NewFlagSet("index", flag.ExitOnError)
	bundle := fl.String("bundle", "", "the release's .upgrade file")
	u := fl.String("url", "", "https URL the bundle is downloaded from")
	notes := fl.String("notes", "", "https URL of the release notes (optional)")
	keyFile := fl.String("key", "", "private signing key (the one that signed the bundle)")
	out := fl.String("o", "", "directory to write v1/stable.json and v1/stable.json.sig under")
	published := fl.String("published", "", "publish time, RFC 3339 (default now)")
	fl.Parse(args)
	if *bundle == "" || *u == "" || *keyFile == "" || *out == "" {
		return fmt.Errorf("index needs -bundle, -url, -key and -o")
	}
	kd, err := os.ReadFile(*keyFile)
	if err != nil {
		return err
	}
	key, err := upgrade.ParsePrivateKey(kd)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(*bundle)
	if err != nil {
		return err
	}
	keys := []upgrade.PublicKey{{Name: "signing key", Key: key.Public().(ed25519.PublicKey)}}
	b, err := upgrade.Read(bytes.NewReader(data), keys)
	if err != nil {
		return fmt.Errorf("%s: %w (was it signed with this key?)", *bundle, err)
	}
	when := time.Now().UTC().Truncate(time.Second)
	if *published != "" {
		if when, err = time.Parse(time.RFC3339, *published); err != nil {
			return err
		}
	}
	sum := sha256.Sum256(data)
	ix := &upgrade.Index{
		Schema: upgrade.IndexSchema, Channel: upgrade.IndexChannel, Published: when.UTC(),
		Latest: upgrade.Release{
			Version: b.Manifest.Version, MinFromVersion: b.Manifest.MinFromVersion,
			URL: *u, Size: int64(len(data)), SHA256: hex.EncodeToString(sum[:]), Notes: *notes,
		},
	}
	js, err := upgrade.MarshalIndex(ix)
	if err != nil {
		return err
	}
	dir := filepath.Join(*out, filepath.Dir(filepath.FromSlash(upgrade.IndexPath)))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(*out, filepath.FromSlash(upgrade.IndexPath)), js, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(*out, filepath.FromSlash(upgrade.IndexSigPath)), upgrade.SignIndex(js, key), 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s/%s: SJB-OS %s, %d bytes, published %s\n", *out, upgrade.IndexPath, ix.Latest.Version, ix.Latest.Size, ix.Published.Format(time.RFC3339))
	return nil
}
