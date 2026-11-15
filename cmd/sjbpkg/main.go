// Command sjbpkg makes and checks SJB-OS upgrade bundles. It runs on the
// build machine, not the appliance.
//
//	sjbpkg keygen -out KEYFILE [-name NAME]
//	sjbpkg build -root DIR -version V [-min-from V] -key KEYFILE -o FILE
//	sjbpkg verify -keys DIR FILE
package main

import (
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"

	"github.com/stevejboyle/hobby-ngfw/internal/upgrade"
)

const usage = `usage:
  sjbpkg keygen -out KEYFILE [-name NAME]   new signing key; writes KEYFILE and KEYFILE.pub
  sjbpkg build -root DIR -version V [-min-from V] -key KEYFILE -o FILE
                                              sign the overlay under DIR into a bundle
  sjbpkg verify -keys DIR FILE              check a bundle against the *.pub keys in DIR
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = keygen(os.Args[2:])
	case "build":
		err = build(os.Args[2:])
	case "verify":
		err = verify(os.Args[2:])
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "sjbpkg:", err)
		os.Exit(1)
	}
}

func keygen(args []string) error {
	fl := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fl.String("out", "", "private key file to create")
	name := fl.String("name", "sjb-os-release", "key name recorded in the .pub file")
	fl.Parse(args)
	if *out == "" {
		return fmt.Errorf("keygen needs -out")
	}
	if _, err := os.Stat(*out); err == nil {
		return fmt.Errorf("%s exists; refusing to overwrite a signing key", *out)
	}
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(*out, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(upgrade.FormatPrivateKey(priv)); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.WriteFile(*out+".pub", []byte(upgrade.FormatPublicKey(pub, *name)), 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s (keep it secret) and %s.pub (bake into the image)\n", *out, *out)
	return nil
}

func build(args []string) error {
	fl := flag.NewFlagSet("build", flag.ExitOnError)
	root := fl.String("root", "", "staged overlay of the appliance filesystem")
	version := fl.String("version", "", "version this bundle installs")
	minFrom := fl.String("min-from", "", "oldest installed version it may upgrade")
	keyFile := fl.String("key", "", "private signing key")
	out := fl.String("o", "", "bundle file to write")
	fl.Parse(args)
	if *root == "" || *version == "" || *keyFile == "" || *out == "" {
		return fmt.Errorf("build needs -root, -version, -key and -o")
	}
	data, err := os.ReadFile(*keyFile)
	if err != nil {
		return err
	}
	key, err := upgrade.ParsePrivateKey(data)
	if err != nil {
		return err
	}
	tmp := *out + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	m, err := upgrade.Build(f, *root, *version, *minFrom, key)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, *out); err != nil {
		return err
	}
	fmt.Printf("wrote %s: SJB-OS %s, %d files\n", *out, m.Version, len(m.Files))
	return nil
}

func verify(args []string) error {
	fl := flag.NewFlagSet("verify", flag.ExitOnError)
	keysDir := fl.String("keys", "", "directory of trusted *.pub keys")
	fl.Parse(args)
	if *keysDir == "" || fl.NArg() != 1 {
		return fmt.Errorf("usage: verify -keys DIR FILE")
	}
	keys, err := upgrade.LoadKeys(*keysDir)
	if err != nil {
		return err
	}
	b, err := upgrade.ReadFile(fl.Arg(0), keys)
	if errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err != nil {
		return err
	}
	fmt.Printf("OK: SJB-OS %s signed by %q\n", b.Manifest.Version, b.KeyName)
	for _, f := range b.Manifest.Files {
		fmt.Printf("  %04o %s\n", f.Mode, f.Path)
	}
	return nil
}
