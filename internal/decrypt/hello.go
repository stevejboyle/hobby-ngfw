// Package decrypt is TLS decryption's shared code: the policy ngfwd hands
// tlsd, the decryption CA, the client-hello reader, server-name matching
// and the learned (pinned) list. tlsd (cmd/tlsd) does the networking.
package decrypt

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Hello is what tlsd needs from a client's TLS hello.
type Hello struct {
	ServerName string   // SNI, lower case; "" if none
	ALPN       []string // offered application protocols, in order
	// MaxVersion is the highest TLS version offered (0x0303 = 1.2, 0x0304 = 1.3).
	MaxVersion uint16
	// ECH: the client offered encrypted client hello; ServerName is then
	// only the outer, public name.
	ECH bool
}

// ErrNotTLS: the connection didn't start with a TLS handshake.
var ErrNotTLS = errors.New("not a TLS client hello")

// maxHello bounds how much of a connection is buffered looking for the
// hello (post-quantum key shares make hellos a few KB).
const maxHello = 64 << 10

// ReadHello reads the client hello from r. It returns every byte it read
// (to be passed on unchanged) and the parsed hello. With ErrNotTLS the raw
// bytes read so far are still returned, so the connection can be passed
// through.
func ReadHello(r io.Reader) ([]byte, Hello, error) {
	var raw, body []byte
	need := -1 // handshake message length once known
	for need < 0 || len(body) < need {
		var hdr [5]byte
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			return raw, Hello{}, fmt.Errorf("reading the client hello: %w", err)
		}
		raw = append(raw, hdr[:]...)
		if hdr[0] != 22 || hdr[1] != 3 { // handshake record, TLS 1.x framing
			return raw, Hello{}, ErrNotTLS
		}
		n := int(binary.BigEndian.Uint16(hdr[3:]))
		if n == 0 || n > 1<<14+2048 || len(raw)+n > maxHello {
			return raw, Hello{}, ErrNotTLS
		}
		rec := make([]byte, n)
		if _, err := io.ReadFull(r, rec); err != nil {
			return append(raw, rec...), Hello{}, fmt.Errorf("reading the client hello: %w", err)
		}
		raw = append(raw, rec...)
		body = append(body, rec...)
		if need < 0 && len(body) >= 4 {
			if body[0] != 1 { // client_hello
				return raw, Hello{}, ErrNotTLS
			}
			need = 4 + (int(body[1])<<16 | int(body[2])<<8 | int(body[3]))
			if need > maxHello {
				return raw, Hello{}, ErrNotTLS
			}
		}
	}
	h, err := ParseHello(body[4:need])
	if err != nil {
		return raw, Hello{}, err
	}
	return raw, h, nil
}

// reader walks a byte slice; any overrun sets bad.
type reader struct {
	b   []byte
	bad bool
}

func (r *reader) take(n int) []byte {
	if r.bad || n > len(r.b) || n < 0 {
		r.bad = true
		return nil
	}
	out := r.b[:n]
	r.b = r.b[n:]
	return out
}
func (r *reader) u8() int {
	b := r.take(1)
	if b == nil {
		return 0
	}
	return int(b[0])
}
func (r *reader) u16() int {
	b := r.take(2)
	if b == nil {
		return 0
	}
	return int(binary.BigEndian.Uint16(b))
}
func (r *reader) vec8() *reader  { return &reader{b: r.take(r.u8()), bad: r.bad} }
func (r *reader) vec16() *reader { n := r.u16(); return &reader{b: r.take(n), bad: r.bad} }

// ParseHello parses a client hello message body (after the 4-byte
// handshake header).
func ParseHello(msg []byte) (Hello, error) {
	r := &reader{b: msg}
	var h Hello
	h.MaxVersion = uint16(r.u16()) // legacy_version
	r.take(32)                     // random
	r.vec8()                       // session id
	r.vec16()                      // cipher suites
	r.vec8()                       // compression methods
	if r.bad {
		return Hello{}, ErrNotTLS
	}
	if len(r.b) == 0 {
		return h, nil // no extensions (very old clients)
	}
	exts := r.vec16()
	for len(exts.b) > 0 && !exts.bad {
		typ := exts.u16()
		data := exts.vec16()
		if exts.bad || data.bad {
			return Hello{}, ErrNotTLS
		}
		switch typ {
		case 0: // server_name
			list := data.vec16()
			for len(list.b) > 0 && !list.bad {
				kind := list.u8()
				name := list.vec16()
				if kind == 0 && !name.bad {
					h.ServerName = strings.ToLower(strings.TrimSuffix(string(name.b), "."))
				}
			}
		case 16: // application_layer_protocol_negotiation
			list := data.vec16()
			for len(list.b) > 0 && !list.bad {
				p := list.vec8()
				if !p.bad && len(p.b) > 0 {
					h.ALPN = append(h.ALPN, string(p.b))
				}
			}
		case 43: // supported_versions
			list := data.vec8()
			for len(list.b) > 0 && !list.bad {
				if v := uint16(list.u16()); v > h.MaxVersion && v <= 0x0304 { // GREASE values (0x?a?a) are all higher
					h.MaxVersion = v
				}
			}
		case 0xfe0d: // encrypted_client_hello
			h.ECH = true
		}
	}
	if exts.bad {
		return Hello{}, ErrNotTLS
	}
	if !validServerName(h.ServerName) {
		h.ServerName = ""
	}
	return h, nil
}

func validServerName(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_') {
			return false
		}
	}
	return true
}
