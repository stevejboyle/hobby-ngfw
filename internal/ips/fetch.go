package ips

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"
)

// ETOpenURL is the Emerging Threats Open rule set for the Suricata release
// SJB-OS ships (Debian 13's 7.0.10). Its .md5 sits beside it.
const ETOpenURL = "https://rules.emergingthreats.net/open/suricata-7.0.10/emerging.rules.tar.gz"

// maxDownload caps the tarball (about 6 MB today).
const maxDownload = 64 << 20

// Download fetches the rule tarball and checks it against the published
// MD5.
func Download(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	get := func(u string, limit int64) ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "SJB-OS IPS")
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("%s: %s", u, resp.Status)
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
		if err != nil {
			return nil, err
		}
		if int64(len(b)) > limit {
			return nil, fmt.Errorf("%s: larger than %d bytes", u, limit)
		}
		return b, nil
	}
	sum, err := get(url+".md5", 1024)
	if err != nil {
		return nil, err
	}
	want := strings.ToLower(strings.TrimSpace(strings.Fields(string(sum) + " ")[0]))
	tgz, err := get(url, maxDownload)
	if err != nil {
		return nil, err
	}
	got := md5.Sum(tgz)
	if hex.EncodeToString(got[:]) != want {
		return nil, fmt.Errorf("%s: checksum mismatch (got %x, published %s)", url, got, want)
	}
	return tgz, nil
}

// Unpack reads the files of a rule tarball, keyed by base name: the
// *.rules files and classification.config.
func Unpack(tgz []byte) (map[string][]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(tgz))
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(zr)
	files := map[string][]byte{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		name := path.Base(h.Name)
		if !strings.HasSuffix(name, ".rules") && name != "classification.config" {
			continue
		}
		b, err := io.ReadAll(io.LimitReader(tr, maxDownload))
		if err != nil {
			return nil, err
		}
		files[name] = b
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no rule files in the archive")
	}
	return files, nil
}
