package decrypt

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// clientHello captures the bytes a Go TLS client sends first.
func clientHello(t *testing.T, cfg *tls.Config) []byte {
	t.Helper()
	a, b := net.Pipe()
	go func() {
		c := tls.Client(a, cfg)
		c.SetDeadline(time.Now().Add(2 * time.Second))
		c.Handshake()
		a.Close()
	}()
	b.SetDeadline(time.Now().Add(2 * time.Second))
	var buf bytes.Buffer
	chunk := make([]byte, 4096)
	for {
		n, err := b.Read(chunk)
		buf.Write(chunk[:n])
		if err != nil {
			break
		}
		if _, _, err := ReadHello(bytes.NewReader(buf.Bytes())); err == nil {
			break
		}
	}
	b.Close()
	return buf.Bytes()
}

func TestReadHello(t *testing.T) {
	raw := clientHello(t, &tls.Config{ServerName: "WWW.Example.COM", NextProtos: []string{"h2", "http/1.1"}})
	got, h, err := ReadHello(bytes.NewReader(append(append([]byte{}, raw...), "trailing"...)))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, raw) {
		t.Fatalf("raw bytes: got %d, want the %d of the hello", len(got), len(raw))
	}
	if h.ServerName != "www.example.com" || len(h.ALPN) != 2 || h.ALPN[0] != "h2" || h.MaxVersion != tls.VersionTLS13 || h.ECH {
		t.Fatalf("hello: %+v", h)
	}
	_, h, err = ReadHello(bytes.NewReader(clientHello(t, &tls.Config{ServerName: "a.example", MaxVersion: tls.VersionTLS12})))
	if err != nil || h.MaxVersion != tls.VersionTLS12 || h.ServerName != "a.example" || len(h.ALPN) != 0 {
		t.Fatalf("TLS 1.2 hello: %+v %v", h, err)
	}
	_, h, err = ReadHello(bytes.NewReader(clientHello(t, &tls.Config{InsecureSkipVerify: true})))
	if err != nil || h.ServerName != "" {
		t.Fatalf("no SNI: %+v %v", h, err)
	}
}

// A hello split across two records still parses, and the raw bytes are
// both records.
func TestReadHelloSplit(t *testing.T) {
	raw := clientHello(t, &tls.Config{ServerName: "split.example"})
	body := raw[5:]
	half := len(body) / 2
	var split []byte
	for _, part := range [][]byte{body[:half], body[half:]} {
		split = append(split, 22, 3, 1, byte(len(part)>>8), byte(len(part)))
		split = append(split, part...)
	}
	got, h, err := ReadHello(bytes.NewReader(split))
	if err != nil || h.ServerName != "split.example" || !bytes.Equal(got, split) {
		t.Fatalf("split: %+v %v (%d of %d bytes)", h, err, len(got), len(split))
	}
}

func TestReadHelloNotTLS(t *testing.T) {
	for name, in := range map[string][]byte{
		"http":        []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
		"ssh":         []byte("SSH-2.0-OpenSSH_9.6\r\n"),
		"alert":       {21, 3, 3, 0, 2, 2, 40},
		"server":      {22, 3, 3, 0, 4, 2, 0, 0, 0},
		"zero length": {22, 3, 1, 0, 0},
		"bad length":  {22, 3, 1, 0, 9, 1, 0, 0, 5, 3, 3, 0, 0, 0},
	} {
		raw, _, err := ReadHello(bytes.NewReader(in))
		if !errors.Is(err, ErrNotTLS) {
			t.Errorf("%s: want ErrNotTLS, got %v", name, err)
		}
		if len(raw) == 0 || !bytes.HasPrefix(in, raw) {
			t.Errorf("%s: raw should be what was read: %q", name, raw)
		}
	}
	if _, _, err := ReadHello(bytes.NewReader([]byte{22, 3})); err == nil || errors.Is(err, ErrNotTLS) {
		t.Errorf("short read: want an I/O error, got %v", err)
	}
	if _, _, err := ReadHello(io.LimitReader(bytes.NewReader(clientHello(t, &tls.Config{ServerName: "x.example"})), 20)); err == nil {
		t.Error("truncated hello should fail")
	}
}

// Malformed hellos never panic, whatever is cut or flipped.
func TestParseHelloFuzzish(t *testing.T) {
	raw := clientHello(t, &tls.Config{ServerName: "fuzz.example", NextProtos: []string{"h2"}})
	msg := raw[9:]
	for i := 0; i < len(msg); i++ {
		ParseHello(msg[:i])
		m := append([]byte{}, msg...)
		m[i] ^= 0xff
		ParseHello(m)
	}
}
