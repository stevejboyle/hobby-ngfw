package daemon

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"github.com/stevejboyle/hobby-ngfw/internal/netdev"
	"github.com/stevejboyle/hobby-ngfw/internal/nicaddr"
)

const maxBody = 1 << 20

// MgmtHandler serves the local management API. It is meant for a
// root-only Unix socket, so it has no authentication of its own.
func (d *Daemon) MgmtHandler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, r *http.Request) {
		s, err := d.Status()
		reply(w, s, err)
	})
	mux.HandleFunc("GET /v1/config/running", func(w http.ResponseWriter, r *http.Request) {
		n, data, err := d.Running()
		if err != nil {
			fail(w, err)
			return
		}
		w.Header().Set("X-Revision", strconv.Itoa(n))
		w.Header().Set("Content-Type", "application/yaml")
		w.Write(data)
	})
	mux.HandleFunc("GET /v1/config/candidate", func(w http.ResponseWriter, r *http.Request) {
		data, err := d.Candidate()
		if err != nil {
			fail(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/yaml")
		w.Write(data)
	})
	mux.HandleFunc("PUT /v1/config/candidate", func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(io.LimitReader(r.Body, maxBody))
		if err == nil {
			err = d.SetCandidate(data)
		}
		reply(w, map[string]string{"status": "candidate updated"}, err)
	})
	mux.HandleFunc("POST /v1/config/revert", func(w http.ResponseWriter, r *http.Request) {
		reply(w, map[string]string{"status": "candidate reverted to running"}, d.RevertCandidate())
	})
	mux.HandleFunc("GET /v1/config/diff", func(w http.ResponseWriter, r *http.Request) {
		s, err := d.Diff()
		if err != nil {
			fail(w, err)
			return
		}
		io.WriteString(w, s)
	})
	mux.HandleFunc("GET /v1/config/compiled", func(w http.ResponseWriter, r *http.Request) {
		res, err := d.Preview()
		if err != nil {
			fail(w, err)
			return
		}
		reply(w, map[string]any{"ruleset": res.Ruleset, "warnings": res.Warnings}, nil)
	})
	mux.HandleFunc("GET /v1/revisions", func(w http.ResponseWriter, r *http.Request) {
		revs, err := d.Revisions()
		reply(w, revs, err)
	})
	mux.HandleFunc("GET /v1/revisions/{n}", func(w http.ResponseWriter, r *http.Request) {
		n, err := strconv.Atoi(r.PathValue("n"))
		if err != nil {
			fail(w, fmt.Errorf("%w: revision must be a number", ErrInvalid))
			return
		}
		data, err := d.Revision(n)
		if err != nil {
			fail(w, fmt.Errorf("%w: %v", ErrInvalid, err))
			return
		}
		w.Header().Set("Content-Type", "application/yaml")
		w.Write(data)
	})
	mux.HandleFunc("POST /v1/commit", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Author         string `json:"author"`
			Message        string `json:"message"`
			ConfirmSeconds int    `json:"confirm_seconds"`
		}
		if !decode(w, r, &req) {
			return
		}
		res, err := d.Commit(req.Author, req.Message, time.Duration(req.ConfirmSeconds)*time.Second)
		reply(w, res, err)
	})
	mux.HandleFunc("POST /v1/confirm", func(w http.ResponseWriter, r *http.Request) {
		reply(w, map[string]string{"status": "confirmed"}, d.Confirm())
	})
	mux.HandleFunc("POST /v1/rollback", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Revision int    `json:"revision"`
			Author   string `json:"author"`
		}
		if !decode(w, r, &req) {
			return
		}
		res, err := d.Rollback(req.Revision, req.Author)
		reply(w, res, err)
	})
	mux.HandleFunc("GET /v1/routes", func(w http.ResponseWriter, r *http.Request) {
		reply(w, d.Routes(), nil)
	})
	mux.HandleFunc("GET /v1/routing/{what}", func(w http.ResponseWriter, r *http.Request) {
		v, err := d.RoutingStatus(r.PathValue("what"), r.URL.Query().Get("vrf"))
		reply(w, v, err)
	})
	mux.HandleFunc("GET /v1/apps", func(w http.ResponseWriter, r *http.Request) {
		reply(w, d.Apps(), nil)
	})
	mux.HandleFunc("GET /v1/apps/categories", func(w http.ResponseWriter, r *http.Request) {
		reply(w, d.AppCategories(), nil)
	})
	mux.HandleFunc("GET /v1/apps/catalog", func(w http.ResponseWriter, r *http.Request) {
		v, err := d.AppCatalog(r.URL.Query().Get("q"))
		reply(w, v, err)
	})
	mux.HandleFunc("GET /v1/stats", func(w http.ResponseWriter, r *http.Request) {
		win := r.URL.Query().Get("window")
		if win == "" {
			win = "1h"
		}
		v, err := d.Stats(win)
		if err != nil {
			http.Error(w, `{"error":"window must be 1h, 24h or 7d"}`, http.StatusBadRequest)
			return
		}
		reply(w, v, nil)
	})
	mux.HandleFunc("GET /v1/ips", func(w http.ResponseWriter, r *http.Request) {
		reply(w, d.IPS(), nil)
	})
	mux.HandleFunc("POST /v1/ips/update", func(w http.ResponseWriter, r *http.Request) {
		v, err := d.UpdateIPS(r.Context())
		reply(w, v, err)
	})
	mux.HandleFunc("GET /v1/decryption", func(w http.ResponseWriter, r *http.Request) {
		reply(w, d.Decryption(), nil)
	})
	mux.HandleFunc("GET /v1/decryption/ca", func(w http.ResponseWriter, r *http.Request) {
		reply(w, d.DecryptionCA(), nil)
	})
	mux.HandleFunc("POST /v1/decryption/ca/generate", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Author string `json:"author"`
		}
		if !decode(w, r, &req) {
			return
		}
		v, err := d.GenerateDecryptionCA(req.Author)
		reply(w, v, err)
	})
	mux.HandleFunc("POST /v1/decryption/ca/import", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Author string `json:"author"`
			Cert   string `json:"cert"`
			Key    string `json:"key"`
		}
		if !decode(w, r, &req) {
			return
		}
		v, err := d.ImportDecryptionCA(req.Author, []byte(req.Cert), []byte(req.Key))
		reply(w, v, err)
	})
	mux.HandleFunc("GET /v1/decryption/learned", func(w http.ResponseWriter, r *http.Request) {
		v, err := d.DecryptionLearned()
		reply(w, v, err)
	})
	mux.HandleFunc("POST /v1/decryption/learned/clear", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Author string `json:"author"`
		}
		if !decode(w, r, &req) {
			return
		}
		n, err := d.ClearDecryptionLearned(req.Author)
		reply(w, map[string]int{"cleared": n}, err)
	})
	mux.HandleFunc("GET /v1/dhcp", func(w http.ResponseWriter, r *http.Request) {
		reply(w, d.DHCP(), nil)
	})
	mux.HandleFunc("GET /v1/dhcp/leases", func(w http.ResponseWriter, r *http.Request) {
		v, err := d.DHCPLeases(r.URL.Query().Get("interface"))
		reply(w, v, err)
	})
	mux.HandleFunc("GET /v1/netdev", func(w http.ResponseWriter, r *http.Request) {
		states := d.NetDevices()
		if states == nil {
			states = []netdev.State{}
		}
		reply(w, states, nil)
	})
	mux.HandleFunc("GET /v1/nics", func(w http.ResponseWriter, r *http.Request) {
		states := d.NICs()
		if states == nil {
			states = []nicaddr.State{}
		}
		reply(w, states, nil)
	})
	d.tagRoutes(mux, "/v1/tags", nil)
	return brandHeader(mux)
}

// brandHeader adds "X-SJB-OS: Stops Junk at the Border" to every
// response: headers are where a firewall can say it without breaking any
// client.
func brandHeader(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-SJB-OS", "Stops Junk at the Border")
		h.ServeHTTP(w, r)
	})
}

// tagRoutes registers the JSON tag API under prefix. wrap, if set, guards
// each handler with a scope check.
func (d *Daemon) tagRoutes(mux *http.ServeMux, prefix string, wrap func(scope string, h http.HandlerFunc) http.HandlerFunc) {
	if wrap == nil {
		wrap = func(_ string, h http.HandlerFunc) http.HandlerFunc { return h }
	}
	list := func(w http.ResponseWriter, r *http.Request) {
		reply(w, d.ListTags(r.PathValue("tag")), nil)
	}
	mux.HandleFunc("GET "+prefix, wrap(ScopeTagsRead, list))
	mux.HandleFunc("GET "+prefix+"/{tag}", wrap(ScopeTagsRead, list))
	mux.HandleFunc("POST "+prefix+"/register", wrap(ScopeTagsWrite, func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			IP   string   `json:"ip"`
			Tags []string `json:"tags"`
			TTL  int      `json:"ttl"`
		}
		if !decode(w, r, &req) {
			return
		}
		ip, err := parseIP(req.IP, req.Tags)
		if err == nil && req.TTL < 0 {
			err = fmt.Errorf("%w: ttl must be >= 0", ErrInvalid)
		}
		if err == nil {
			err = d.RegisterTags(ip, req.Tags, time.Duration(req.TTL)*time.Second)
		}
		reply(w, map[string]any{"registered": req.Tags, "ip": req.IP}, err)
	}))
	mux.HandleFunc("POST "+prefix+"/unregister", wrap(ScopeTagsWrite, func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			IP   string   `json:"ip"`
			Tags []string `json:"tags"`
		}
		if !decode(w, r, &req) {
			return
		}
		ip, err := parseIP(req.IP, req.Tags)
		if err == nil {
			err = d.UnregisterTags(ip, req.Tags)
		}
		reply(w, map[string]any{"unregistered": req.Tags, "ip": req.IP}, err)
	}))
}

func parseIP(s string, tagList []string) (netip.Addr, error) {
	ip, err := netip.ParseAddr(s)
	if err != nil {
		return ip, fmt.Errorf("%w: bad ip %q", ErrInvalid, s)
	}
	if len(tagList) == 0 {
		return ip, fmt.Errorf("%w: at least one tag required", ErrInvalid)
	}
	return ip, nil
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(io.LimitReader(r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil && !errors.Is(err, io.EOF) {
		fail(w, fmt.Errorf("%w: bad JSON: %v", ErrInvalid, err))
		return false
	}
	return true
}

func reply(w http.ResponseWriter, v any, err error) {
	if err != nil {
		fail(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, err error) {
	code := http.StatusInternalServerError
	if errors.Is(err, ErrInvalid) {
		code = http.StatusBadRequest
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}
