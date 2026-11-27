package ospkg

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"strings"
)

// Paths under the root filesystem.
const (
	dpkgStatus = "var/lib/dpkg/status"
	dpkgInfo   = "var/lib/dpkg/info"
)

// stanza is one package's entry in dpkg's status file: its fields in order,
// with continuation lines kept as they are.
type stanza struct {
	keys   []string
	fields map[string]string
}

func (s stanza) get(k string) string { return s.fields[k] }

// installed reports whether dpkg considers the package fully installed.
func (s stanza) installed() bool {
	st := strings.Fields(s.get("Status"))
	return len(st) == 3 && st[2] == "installed"
}

// readStatus parses dpkg's status file under root.
func readStatus(root string) ([]stanza, error) {
	data, err := os.ReadFile(filepath.Join(root, dpkgStatus))
	if err != nil {
		return nil, err
	}
	var out []stanza
	cur := stanza{fields: map[string]string{}}
	last := ""
	flush := func() {
		if len(cur.keys) > 0 {
			out = append(out, cur)
		}
		cur, last = stanza{fields: map[string]string{}}, ""
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			flush()
		case line[0] == ' ' || line[0] == '\t':
			if last != "" {
				cur.fields[last] += "\n" + line
			}
		default:
			k, v, ok := strings.Cut(line, ":")
			if !ok {
				continue
			}
			last = k
			cur.keys = append(cur.keys, k)
			cur.fields[k] = strings.TrimLeft(v, " ")
		}
	}
	flush()
	return out, sc.Err()
}

// installedPackages maps each fully installed package name to its stanza.
// For a Multi-Arch: same package installed for several architectures, the
// first one wins (SJB-OS appliances are amd64 only).
func installedPackages(root string) (map[string]stanza, error) {
	all, err := readStatus(root)
	if err != nil {
		return nil, err
	}
	m := map[string]stanza{}
	for _, s := range all {
		if !s.installed() {
			continue
		}
		if _, dup := m[s.get("Package")]; !dup {
			m[s.get("Package")] = s
		}
	}
	return m, nil
}

// infoFile is the path of one of a package's dpkg info files (list,
// conffiles, postinst, ...). Multi-Arch: same packages carry the
// architecture in the name.
func infoFile(root string, s stanza, ext string) string {
	name := s.get("Package")
	plain := filepath.Join(root, dpkgInfo, name+"."+ext)
	qualified := filepath.Join(root, dpkgInfo, name+":"+s.get("Architecture")+"."+ext)
	if s.get("Multi-Arch") == "same" {
		if _, err := os.Lstat(qualified); err == nil {
			return qualified
		}
	}
	if _, err := os.Lstat(plain); err == nil {
		return plain
	}
	if _, err := os.Lstat(qualified); err == nil {
		return qualified
	}
	return plain
}
