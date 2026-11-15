// Package upgrade builds, verifies and applies SJB-OS upgrade bundles: a
// signed overlay of appliance files (binaries, units, scripts) installed in
// place, with the replaced files kept so a failed or unwanted upgrade can be
// undone. Config, state and secrets are never part of a bundle.
//
// A bundle file is a tar holding two members:
//
//	bundle.tar.gz  manifest.json + files/<path> for each manifest entry
//	bundle.sig     ed25519 signature over bundle.tar.gz
package upgrade

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// MaxBundleSize bounds what Read accepts, so an upload cannot exhaust memory.
const MaxBundleSize = 256 << 20

// KeyPrefix starts every public key line, so a key file says what it is for.
const KeyPrefix = "sjb-os-upgrade-ed25519"

// legacyKeyPrefix is the token key files had before 0.8.0; still accepted.
const legacyKeyPrefix = "groot-os-upgrade-ed25519"

// File is one manifest entry. Path is relative to the root filesystem.
type File struct {
	Path   string `json:"path"`
	Mode   uint32 `json:"mode"`
	SHA256 string `json:"sha256"`
}

// Manifest describes a bundle.
type Manifest struct {
	Version        string `json:"version"`
	MinFromVersion string `json:"min_from_version,omitempty"`
	Files          []File `json:"files"`
}

// Bundle is a verified bundle held in memory.
type Bundle struct {
	Manifest Manifest
	Contents map[string][]byte // path -> data
	KeyName  string            // which trusted key signed it
}

// ErrInvalid marks a bundle that fails verification.
var ErrInvalid = errors.New("invalid upgrade bundle")

// allowed lists where a bundle may write. Everything else (config in
// /etc/ngfw, state in /var/lib, accounts, network settings written at first
// boot) belongs to the operator and is never touched.
var allowedPrefixes = []string{
	"usr/local/sbin/",
	"usr/share/sjb-os/",
	// The shared directory's name before 0.8.0: the transition bundle
	// (installable by older versions) ships under it, and it stays an alias
	// until the move finishes.
	"usr/share/groot-os/",
	"etc/systemd/system/",
	"etc/update-motd.d/",
	"etc/sysctl.d/",
	"etc/ssh/sshd_config.d/",
}

var allowedFiles = map[string]bool{"etc/ngfw-version": true}

// Allowed reports whether a bundle may install p.
func Allowed(p string) bool {
	if p == "" || strings.HasPrefix(p, "/") || path.Clean(p) != p || strings.HasPrefix(p, "..") || strings.Contains(p, "/../") {
		return false
	}
	if allowedFiles[p] {
		return true
	}
	for _, pre := range allowedPrefixes {
		if strings.HasPrefix(p, pre) && len(p) > len(pre) {
			return true
		}
	}
	return false
}

// PublicKey is a trusted signing key.
type PublicKey struct {
	Name string
	Key  ed25519.PublicKey
}

// FormatPublicKey renders a key as one line: "<prefix> <base64> <name>".
func FormatPublicKey(k ed25519.PublicKey, name string) string {
	return fmt.Sprintf("%s %s %s\n", KeyPrefix, base64.StdEncoding.EncodeToString(k), name)
}

// ParsePublicKey reads a line written by FormatPublicKey.
func ParsePublicKey(line string) (PublicKey, error) {
	f := strings.Fields(line)
	if len(f) < 2 || (f[0] != KeyPrefix && f[0] != legacyKeyPrefix) {
		return PublicKey{}, fmt.Errorf("not a %s key", KeyPrefix)
	}
	b, err := base64.StdEncoding.DecodeString(f[1])
	if err != nil || len(b) != ed25519.PublicKeySize {
		return PublicKey{}, fmt.Errorf("bad key data")
	}
	name := "unnamed"
	if len(f) > 2 {
		name = strings.Join(f[2:], " ")
	}
	return PublicKey{Name: name, Key: ed25519.PublicKey(b)}, nil
}

// LoadKeys reads every *.pub file in dir.
func LoadKeys(dir string) ([]PublicKey, error) {
	matches, err := filepath.Glob(filepath.Join(dir, "*.pub"))
	if err != nil {
		return nil, err
	}
	var keys []PublicKey
	for _, m := range matches {
		data, err := os.ReadFile(m)
		if err != nil {
			return nil, err
		}
		for _, line := range strings.Split(string(data), "\n") {
			if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
				continue
			}
			k, err := ParsePublicKey(line)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", m, err)
			}
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("no upgrade signing keys in %s", dir)
	}
	return keys, nil
}

// PrivateKey file format: one line, base64 of the 32-byte seed.

// FormatPrivateKey renders a key's seed.
func FormatPrivateKey(k ed25519.PrivateKey) string {
	return base64.StdEncoding.EncodeToString(k.Seed()) + "\n"
}

// ParsePrivateKey reads a FormatPrivateKey file.
func ParsePrivateKey(data []byte) (ed25519.PrivateKey, error) {
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("bad private key")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// Build packs the files under root (a staged overlay of the appliance
// filesystem) into a signed bundle written to w. Every file must be Allowed.
func Build(w io.Writer, root, version, minFrom string, key ed25519.PrivateKey) (*Manifest, error) {
	if _, err := ParseVersion(version); err != nil {
		return nil, err
	}
	if minFrom != "" {
		if _, err := ParseVersion(minFrom); err != nil {
			return nil, err
		}
	}
	m := &Manifest{Version: version, MinFromVersion: minFrom}
	contents := map[string][]byte{}
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		if !d.Type().IsRegular() {
			return fmt.Errorf("%s: only regular files can go in a bundle", rel)
		}
		if !Allowed(rel) {
			return fmt.Errorf("%s: a bundle may not write there", rel)
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		m.Files = append(m.Files, File{Path: rel, Mode: uint32(info.Mode().Perm()), SHA256: hex.EncodeToString(sum[:])})
		contents[rel] = data
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(m.Files) == 0 {
		return nil, fmt.Errorf("no files under %s", root)
	}
	sort.Slice(m.Files, func(i, j int) bool { return m.Files[i].Path < m.Files[j].Path })

	var inner bytes.Buffer
	gz := gzip.NewWriter(&inner)
	tw := tar.NewWriter(gz)
	mj, _ := json.MarshalIndent(m, "", "  ")
	if err := writeMember(tw, "manifest.json", 0o644, mj); err != nil {
		return nil, err
	}
	for _, f := range m.Files {
		if err := writeMember(tw, "files/"+f.Path, int64(f.Mode), contents[f.Path]); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	sig := ed25519.Sign(key, inner.Bytes())

	outer := tar.NewWriter(w)
	if err := writeMember(outer, "bundle.tar.gz", 0o644, inner.Bytes()); err != nil {
		return nil, err
	}
	if err := writeMember(outer, "bundle.sig", 0o644, sig); err != nil {
		return nil, err
	}
	return m, outer.Close()
}

func writeMember(tw *tar.Writer, name string, mode int64, data []byte) error {
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: mode, Size: int64(len(data)), Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}); err != nil {
		return err
	}
	_, err := tw.Write(data)
	return err
}

// ReadFile verifies the bundle at path against keys.
func ReadFile(p string, keys []PublicKey) (*Bundle, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Read(f, keys)
}

// Read verifies a bundle: the signature against keys, then the manifest and
// every file's hash. It does not check versions; see CheckVersion.
func Read(r io.Reader, keys []PublicKey) (*Bundle, error) {
	members, err := readTar(io.LimitReader(r, MaxBundleSize+1), MaxBundleSize)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	inner, sig := members["bundle.tar.gz"], members["bundle.sig"]
	if inner == nil || sig == nil || len(members) != 2 {
		return nil, fmt.Errorf("%w: expected bundle.tar.gz and bundle.sig", ErrInvalid)
	}
	var signer string
	for _, k := range keys {
		if ed25519.Verify(k.Key, inner, sig) {
			signer = k.Name
			break
		}
	}
	if signer == "" {
		return nil, fmt.Errorf("%w: signature does not match any trusted key", ErrInvalid)
	}
	gz, err := gzip.NewReader(bytes.NewReader(inner))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	files, err := readTar(gz, MaxBundleSize)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	b := &Bundle{Contents: map[string][]byte{}, KeyName: signer}
	if err := json.Unmarshal(files["manifest.json"], &b.Manifest); err != nil {
		return nil, fmt.Errorf("%w: manifest: %v", ErrInvalid, err)
	}
	if _, err := ParseVersion(b.Manifest.Version); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if len(b.Manifest.Files) == 0 {
		return nil, fmt.Errorf("%w: no files", ErrInvalid)
	}
	for _, mf := range b.Manifest.Files {
		if !Allowed(mf.Path) {
			return nil, fmt.Errorf("%w: %s: a bundle may not write there", ErrInvalid, mf.Path)
		}
		data, ok := files["files/"+mf.Path]
		if !ok {
			return nil, fmt.Errorf("%w: %s missing", ErrInvalid, mf.Path)
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != mf.SHA256 {
			return nil, fmt.Errorf("%w: %s: checksum mismatch", ErrInvalid, mf.Path)
		}
		if _, dup := b.Contents[mf.Path]; dup {
			return nil, fmt.Errorf("%w: %s listed twice", ErrInvalid, mf.Path)
		}
		b.Contents[mf.Path] = data
	}
	if len(files) != len(b.Manifest.Files)+1 {
		return nil, fmt.Errorf("%w: files not listed in the manifest", ErrInvalid)
	}
	return b, nil
}

func readTar(r io.Reader, limit int64) (map[string][]byte, error) {
	tr := tar.NewReader(r)
	out := map[string][]byte{}
	var total int64
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		if h.Typeflag != tar.TypeReg {
			return nil, fmt.Errorf("%s: not a regular file", h.Name)
		}
		total += h.Size
		if total > limit {
			return nil, fmt.Errorf("bundle too large")
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			return nil, err
		}
		if _, dup := out[h.Name]; dup {
			return nil, fmt.Errorf("%s appears twice", h.Name)
		}
		out[h.Name] = data
	}
}
