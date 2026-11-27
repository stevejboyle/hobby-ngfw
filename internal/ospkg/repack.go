package ospkg

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// controlFiles are the dpkg info files a .deb's control archive can carry,
// with their modes.
var controlFiles = []struct {
	ext  string
	mode int64
}{
	{"preinst", 0o755}, {"postinst", 0o755}, {"prerm", 0o755}, {"postrm", 0o755},
	{"config", 0o755}, {"templates", 0o644}, {"triggers", 0o644},
	{"shlibs", 0o644}, {"symbols", 0o644}, {"md5sums", 0o644},
}

// debFileName is how Debian names a package file.
func debFileName(pkg, version, arch string) string {
	return fmt.Sprintf("%s_%s_%s.deb", pkg, strings.ReplaceAll(version, ":", "%3a"), arch)
}

// repack rebuilds the installed package pkg as a .deb in dir, from dpkg's
// own records under root: its status entry, maintainer scripts and the files
// it owns as they are now (changed config files included). It is what a
// rollback reinstalls, so the exact installed version can come back without
// a download. Returns the file written.
func repack(root string, s stanza, dir string) (string, error) {
	pkg, ver, arch := s.get("Package"), s.get("Version"), s.get("Architecture")
	if pkg == "" || ver == "" || arch == "" {
		return "", fmt.Errorf("repack: incomplete dpkg entry for %q", pkg)
	}
	mtime := time.Now()
	ctl, err := controlTar(root, s, mtime)
	if err != nil {
		return "", fmt.Errorf("repack %s: %w", pkg, err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	data, err := os.CreateTemp(dir, ".data-*.tar.gz")
	if err != nil {
		return "", err
	}
	defer os.Remove(data.Name())
	defer data.Close()
	if err := dataTar(root, s, data); err != nil {
		return "", fmt.Errorf("repack %s: %w", pkg, err)
	}
	size, err := data.Seek(0, io.SeekCurrent)
	if err != nil {
		return "", err
	}
	if _, err := data.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	out := filepath.Join(dir, debFileName(pkg, ver, arch))
	f, err := os.CreateTemp(dir, ".deb-*")
	if err != nil {
		return "", err
	}
	defer os.Remove(f.Name())
	w := bufio.NewWriter(f)
	w.WriteString("!<arch>\n")
	arMember(w, "debian-binary", mtime, int64(len("2.0\n")), strings.NewReader("2.0\n"))
	arMember(w, "control.tar.gz", mtime, int64(len(ctl)), bytes.NewReader(ctl))
	if err := arMember(w, "data.tar.gz", mtime, size, data); err != nil {
		f.Close()
		return "", err
	}
	if err := w.Flush(); err != nil {
		f.Close()
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	return out, os.Rename(f.Name(), out)
}

func arMember(w io.Writer, name string, mtime time.Time, size int64, r io.Reader) error {
	fmt.Fprintf(w, "%-16s%-12d%-6d%-6d%-8o%-10d`\n", name, mtime.Unix(), 0, 0, 0o100644, size)
	n, err := io.Copy(w, r)
	if err != nil {
		return err
	}
	if n != size {
		return fmt.Errorf("ar member %s: wrote %d of %d bytes", name, n, size)
	}
	if size%2 == 1 {
		_, err = w.Write([]byte{'\n'})
	}
	return err
}

// controlText is the package's control file: its status entry without the
// fields that describe the installation rather than the package.
func controlText(s stanza) string {
	var b strings.Builder
	for _, k := range s.keys {
		switch k {
		case "Status", "Conffiles", "Config-Version":
			continue
		}
		fmt.Fprintf(&b, "%s: %s\n", k, s.fields[k])
	}
	return b.String()
}

// conffileList is the conffiles control file: the package's current
// (not obsolete) config files.
func conffileList(s stanza) string {
	var b strings.Builder
	for _, line := range strings.Split(s.get("Conffiles"), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && !(len(f) >= 3 && f[2] == "obsolete") {
			b.WriteString(f[0] + "\n")
		}
	}
	return b.String()
}

func controlTar(root string, s stanza, mtime time.Time) ([]byte, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	add := func(name string, mode int64, data []byte) error {
		if err := tw.WriteHeader(&tar.Header{Name: "./" + name, Mode: mode, Size: int64(len(data)), ModTime: mtime, Typeflag: tar.TypeReg, Format: tar.FormatGNU}); err != nil {
			return err
		}
		_, err := tw.Write(data)
		return err
	}
	if err := tw.WriteHeader(&tar.Header{Name: "./", Mode: 0o755, ModTime: mtime, Typeflag: tar.TypeDir, Format: tar.FormatGNU}); err != nil {
		return nil, err
	}
	if err := add("control", 0o644, []byte(controlText(s))); err != nil {
		return nil, err
	}
	if c := conffileList(s); c != "" {
		if err := add("conffiles", 0o644, []byte(c)); err != nil {
			return nil, err
		}
	}
	for _, cf := range controlFiles {
		data, err := os.ReadFile(infoFile(root, s, cf.ext))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if err := add(cf.ext, cf.mode, data); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// dataTar writes the files the package owns, as they are now, to w.
// Paths dpkg lists that no longer exist are left out.
func dataTar(root string, s stanza, w io.Writer) error {
	list, err := os.ReadFile(infoFile(root, s, "list"))
	if err != nil {
		return fmt.Errorf("file list: %w", err)
	}
	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)
	seen := map[string]bool{}
	for _, p := range strings.Split(string(list), "\n") {
		p = strings.TrimSpace(p)
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		rel := strings.TrimPrefix(p, "/")
		name := "./" + rel
		if rel == "." || rel == "" {
			name = "./"
		}
		full := filepath.Join(root, rel)
		info, err := os.Lstat(full)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return err
		}
		hdr := &tar.Header{Name: name, Mode: int64(info.Mode().Perm()), ModTime: info.ModTime(), Format: tar.FormatGNU}
		if info.Mode()&fs.ModeSetuid != 0 {
			hdr.Mode |= 0o4000
		}
		if info.Mode()&fs.ModeSetgid != 0 {
			hdr.Mode |= 0o2000
		}
		if info.Mode()&fs.ModeSticky != 0 {
			hdr.Mode |= 0o1000
		}
		if st, ok := info.Sys().(*syscall.Stat_t); ok {
			hdr.Uid, hdr.Gid = int(st.Uid), int(st.Gid)
		}
		switch {
		case info.IsDir():
			hdr.Typeflag = tar.TypeDir
			if !strings.HasSuffix(hdr.Name, "/") {
				hdr.Name += "/"
			}
			if err := tw.WriteHeader(hdr); err != nil {
				return err
			}
		case info.Mode()&fs.ModeSymlink != 0:
			target, err := os.Readlink(full)
			if err != nil {
				return err
			}
			hdr.Typeflag, hdr.Linkname = tar.TypeSymlink, target
			if err := tw.WriteHeader(hdr); err != nil {
				return err
			}
		case info.Mode().IsRegular():
			hdr.Typeflag, hdr.Size = tar.TypeReg, info.Size()
			if err := tw.WriteHeader(hdr); err != nil {
				return err
			}
			f, err := os.Open(full)
			if err != nil {
				return err
			}
			_, err = io.CopyN(tw, f, info.Size())
			f.Close()
			if err != nil {
				return err
			}
		default:
			// Devices, sockets, pipes: Debian packages don't ship them.
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return gz.Close()
}
