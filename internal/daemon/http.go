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

	"github.com/stevejboyle/sjb-os/internal/accounts"
	"github.com/stevejboyle/sjb-os/internal/backup"
	"github.com/stevejboyle/sjb-os/internal/logs"
	"github.com/stevejboyle/sjb-os/internal/metrics"
	"github.com/stevejboyle/sjb-os/internal/netdev"
	"github.com/stevejboyle/sjb-os/internal/nicaddr"
	"github.com/stevejboyle/sjb-os/internal/snmp"
)

const maxBody = 1 << 20

// mgmtRoute is one management API call and what it needs.
type mgmtRoute struct {
	pattern string
	need    accounts.Need
	h       func(w http.ResponseWriter, r *http.Request, c accounts.Caller)
}

// MgmtHandler serves the local management API on the Unix socket. ngfwd
// attaches the caller (the socket peer's Unix user) to each request with
// WithCaller; every route says what it needs, and the caller's current
// role is checked before it runs.
func (d *Daemon) MgmtHandler() http.Handler {
	mux := http.NewServeMux()
	for _, rt := range d.mgmtRoutes() {
		if !rt.need.Valid() {
			panic("management route without a permission: " + rt.pattern)
		}
		rt := rt
		mux.HandleFunc(rt.pattern, func(w http.ResponseWriter, r *http.Request) {
			c, ok := CallerFrom(r.Context())
			if !ok {
				if d.accounts != nil {
					fail(w, fmt.Errorf("%w: caller unknown", accounts.ErrForbidden))
					return
				}
				c = accounts.Root // no access control configured (tests, development)
			}
			if _, err := d.Authorize(c, rt.need); err != nil {
				fail(w, err)
				return
			}
			rt.h(w, r, c)
		})
	}
	return brandHeader(mux)
}

func (d *Daemon) mgmtRoutes() []mgmtRoute {
	view, change := accounts.NeedView, accounts.NeedChange
	A := accounts.Anyone
	yaml := func(w http.ResponseWriter, data []byte) {
		w.Header().Set("Content-Type", "application/yaml")
		w.Write(data)
	}
	rs := []mgmtRoute{
		{"GET /v1/status", A, func(w http.ResponseWriter, r *http.Request, c accounts.Caller) {
			s, err := d.Status()
			reply(w, s, err)
		}},
		{"GET /v1/me", A, func(w http.ResponseWriter, r *http.Request, c accounts.Caller) {
			v, err := d.Me(c)
			reply(w, v, err)
		}},
		{"GET /v1/config/running", accounts.ConfigView, func(w http.ResponseWriter, r *http.Request, c accounts.Caller) {
			n, data, err := d.Running()
			if err != nil {
				fail(w, err)
				return
			}
			w.Header().Set("X-Revision", strconv.Itoa(n))
			yaml(w, data)
		}},
		{"GET /v1/config/candidate", accounts.ConfigView, func(w http.ResponseWriter, r *http.Request, c accounts.Caller) {
			data, err := d.Candidate()
			if err != nil {
				fail(w, err)
				return
			}
			yaml(w, data)
		}},
		{"PUT /v1/config/candidate", accounts.ConfigEdit, func(w http.ResponseWriter, r *http.Request, c accounts.Caller) {
			data, err := io.ReadAll(io.LimitReader(r.Body, maxBody))
			if err == nil {
				err = d.SetCandidateAs(c, data)
			}
			reply(w, map[string]string{"status": "candidate updated"}, err)
		}},
		{"POST /v1/config/revert", accounts.ConfigEdit, func(w http.ResponseWriter, r *http.Request, c accounts.Caller) {
			reply(w, map[string]string{"status": "candidate reverted to running"}, d.RevertCandidateAs(c))
		}},
		{"GET /v1/config/diff", accounts.ConfigView, func(w http.ResponseWriter, r *http.Request, c accounts.Caller) {
			s, err := d.Diff()
			if err != nil {
				fail(w, err)
				return
			}
			io.WriteString(w, s)
		}},
		{"GET /v1/config/compiled", accounts.ConfigView, func(w http.ResponseWriter, r *http.Request, c accounts.Caller) {
			res, err := d.Preview()
			if err != nil {
				fail(w, err)
				return
			}
			reply(w, map[string]any{"ruleset": res.Ruleset, "warnings": res.Warnings}, nil)
		}},
		{"GET /v1/revisions", view(accounts.Revisions), func(w http.ResponseWriter, r *http.Request, c accounts.Caller) {
			revs, err := d.Revisions()
			reply(w, revs, err)
		}},
		{"GET /v1/revisions/{n}", view(accounts.Revisions), func(w http.ResponseWriter, r *http.Request, c accounts.Caller) {
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
			yaml(w, data)
		}},
		// The author fields clients send are ignored: the caller is known.
		{"POST /v1/commit", accounts.ConfigEdit, func(w http.ResponseWriter, r *http.Request, c accounts.Caller) {
			var req struct {
				Author         string `json:"author"`
				Message        string `json:"message"`
				ConfirmSeconds int    `json:"confirm_seconds"`
			}
			if !decode(w, r, &req) {
				return
			}
			res, err := d.CommitAs(c, req.Message, time.Duration(req.ConfirmSeconds)*time.Second)
			reply(w, res, err)
		}},
		{"POST /v1/confirm", change(accounts.Revisions), func(w http.ResponseWriter, r *http.Request, c accounts.Caller) {
			reply(w, map[string]string{"status": "confirmed"}, d.ConfirmAs(c))
		}},
		{"POST /v1/rollback", change(accounts.Revisions), func(w http.ResponseWriter, r *http.Request, c accounts.Caller) {
			var req struct {
				Revision int    `json:"revision"`
				Author   string `json:"author"`
			}
			if !decode(w, r, &req) {
				return
			}
			res, err := d.RollbackAs(c, req.Revision)
			reply(w, res, err)
		}},
		{"GET /v1/routes", view(accounts.Monitoring), func(w http.ResponseWriter, r *http.Request, c accounts.Caller) {
			reply(w, d.Routes(), nil)
		}},
		{"GET /v1/nat", view(accounts.Monitoring), func(w http.ResponseWriter, r *http.Request, c accounts.Caller) {
			reply(w, d.NAT(), nil)
		}},
		{"GET /v1/routing/{what}", view(accounts.Monitoring), func(w http.ResponseWriter, r *http.Request, c accounts.Caller) {
			v, err := d.RoutingStatus(r.PathValue("what"), r.URL.Query().Get("vrf"))
			reply(w, v, err)
		}},
		{"GET /v1/apps", view(accounts.Monitoring), func(w http.ResponseWriter, r *http.Request, c accounts.Caller) {
			reply(w, d.Apps(), nil)
		}},
		{"GET /v1/apps/categories", A, func(w http.ResponseWriter, r *http.Request, c accounts.Caller) {
			reply(w, d.AppCategories(), nil)
		}},
		{"GET /v1/apps/catalog", A, func(w http.ResponseWriter, r *http.Request, c accounts.Caller) {
			v, err := d.AppCatalog(r.URL.Query().Get("q"))
			reply(w, v, err)
		}},
		{"GET /v1/stats", view(accounts.Monitoring), func(w http.ResponseWriter, r *http.Request, c accounts.Caller) {
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
		}},
		{"GET /v1/logs/{kind}", view(accounts.Monitoring), func(w http.ResponseWriter, r *http.Request, c accounts.Caller) {
			n, _ := strconv.Atoi(r.URL.Query().Get("n"))
			v, err := d.Logs(r.PathValue("kind"), n, r.URL.Query().Get("q"))
			if err != nil && !errors.Is(err, logs.ErrQuery) && !errors.Is(err, accounts.ErrNotFound) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusServiceUnavailable)
				json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}
			reply(w, v, err)
		}},
		{"GET /v1/ips", view(accounts.IPS), func(w http.ResponseWriter, r *http.Request, c accounts.Caller) {
			reply(w, d.IPS(), nil)
		}},
		{"POST /v1/ips/update", change(accounts.IPS), func(w http.ResponseWriter, r *http.Request, c accounts.Caller) {
			d.log.Info("IPS signature update requested", "by", c.Author())
			v, err := d.UpdateIPS(r.Context())
			reply(w, v, err)
		}},
		{"GET /v1/geoip", view(accounts.IPS), func(w http.ResponseWriter, r *http.Request, c accounts.Caller) {
			reply(w, d.GeoIP(), nil)
		}},
		{"GET /v1/geoip/lookup", view(accounts.IPS), func(w http.ResponseWriter, r *http.Request, c accounts.Caller) {
			v, err := d.GeoIPLookup(r.URL.Query().Get("ip"))
			reply(w, v, err)
		}},
		{"POST /v1/geoip/update", change(accounts.IPS), func(w http.ResponseWriter, r *http.Request, c accounts.Caller) {
			d.log.Info("country database update requested", "by", c.Author())
			v, err := d.UpdateGeoIP(r.Context())
			reply(w, v, err)
		}},
		{"POST /v1/geoip/import", change(accounts.IPS), func(w http.ResponseWriter, r *http.Request, c accounts.Caller) {
			data, err := io.ReadAll(io.LimitReader(r.Body, 64<<20))
			if err != nil {
				fail(w, err)
				return
			}
			v, err := d.ImportGeoIP(c, data)
			reply(w, v, err)
		}},
		{"GET /v1/decryption", view(accounts.Decryption), func(w http.ResponseWriter, r *http.Request, c accounts.Caller) {
			reply(w, d.Decryption(), nil)
		}},
		{"GET /v1/decryption/ca", view(accounts.DecryptionCA), func(w http.ResponseWriter, r *http.Request, c accounts.Caller) {
			reply(w, d.DecryptionCA(), nil)
		}},
		{"POST /v1/decryption/ca/generate", change(accounts.DecryptionCA), func(w http.ResponseWriter, r *http.Request, c accounts.Caller) {
			var req struct {
				Author string `json:"author"`
			}
			if !decode(w, r, &req) {
				return
			}
			v, err := d.GenerateDecryptionCA(c.Author())
			reply(w, v, err)
		}},
		{"POST /v1/decryption/ca/import", change(accounts.DecryptionCA), func(w http.ResponseWriter, r *http.Request, c accounts.Caller) {
			var req struct {
				Author string `json:"author"`
				Cert   string `json:"cert"`
				Key    string `json:"key"`
			}
			if !decode(w, r, &req) {
				return
			}
			v, err := d.ImportDecryptionCA(c.Author(), []byte(req.Cert), []byte(req.Key))
			reply(w, v, err)
		}},
		{"GET /v1/mgmt-cert", view(accounts.Certificates), func(w http.ResponseWriter, r *http.Request, c accounts.Caller) {
			v, err := d.MgmtCert()
			reply(w, v, err)
		}},
		{"POST /v1/mgmt-cert/import", change(accounts.Certificates), func(w http.ResponseWriter, r *http.Request, c accounts.Caller) {
			var req struct {
				Cert string `json:"cert"`
				Key  string `json:"key"`
			}
			if !decode(w, r, &req) {
				return
			}
			v, err := d.ImportMgmtCert(c.Author(), []byte(req.Cert), []byte(req.Key))
			reply(w, v, err)
		}},
		{"POST /v1/mgmt-cert/self-signed", change(accounts.Certificates), func(w http.ResponseWriter, r *http.Request, c accounts.Caller) {
			v, err := d.ResetMgmtCert(c.Author())
			reply(w, v, err)
		}},
		{"GET /v1/decryption/learned", view(accounts.Decryption), func(w http.ResponseWriter, r *http.Request, c accounts.Caller) {
			v, err := d.DecryptionLearned()
			reply(w, v, err)
		}},
		{"POST /v1/decryption/learned/clear", change(accounts.Decryption), func(w http.ResponseWriter, r *http.Request, c accounts.Caller) {
			var req struct {
				Author string `json:"author"`
			}
			if !decode(w, r, &req) {
				return
			}
			n, err := d.ClearDecryptionLearned(c.Author())
			reply(w, map[string]int{"cleared": n}, err)
		}},
		{"POST /v1/backup/export", accounts.ConfigView, func(w http.ResponseWriter, r *http.Request, c accounts.Caller) {
			var req struct {
				Accounts   bool   `json:"accounts"`
				Passphrase string `json:"passphrase"`
			}
			if !decode(w, r, &req) {
				return
			}
			v, err := d.ExportBackup(c, req.Accounts, req.Passphrase)
			reply(w, v, err)
		}},
		{"POST /v1/backup/inspect", accounts.ConfigView, func(w http.ResponseWriter, r *http.Request, c accounts.Caller) {
			var req struct {
				Data string `json:"data"`
			}
			if !decodeLimit(w, r, &req, backup.MaxSize*2) {
				return
			}
			v, err := d.InspectBackup(c, []byte(req.Data))
			reply(w, v, err)
		}},
		{"POST /v1/backup/restore", accounts.ConfigEdit, func(w http.ResponseWriter, r *http.Request, c accounts.Caller) {
			var req RestoreRequest
			if !decodeLimit(w, r, &req, backup.MaxSize*2) {
				return
			}
			v, err := d.RestoreBackup(c, req)
			reply(w, v, err)
		}},
		{"GET /v1/updates", view(accounts.Upgrades), func(w http.ResponseWriter, r *http.Request, c accounts.Caller) {
			reply(w, d.Updates(), nil)
		}},
		{"POST /v1/updates/check", change(accounts.Upgrades), func(w http.ResponseWriter, r *http.Request, c accounts.Caller) {
			v, err := d.StartUpdateCheck(c, 20*time.Second)
			reply(w, v, err)
		}},
		{"POST /v1/updates/install", change(accounts.Upgrades), func(w http.ResponseWriter, r *http.Request, c accounts.Caller) {
			v, err := d.InstallUpdate(c)
			reply(w, v, err)
		}},
		{"POST /v1/reboot", change(accounts.Upgrades), func(w http.ResponseWriter, r *http.Request, c accounts.Caller) {
			reply(w, map[string]bool{"rebooting": true}, d.Reboot(c))
		}},
		{"GET /v1/logforwarding", view(accounts.Logging), func(w http.ResponseWriter, r *http.Request, c accounts.Caller) {
			reply(w, d.LogForwarding(), nil)
		}},
		{"POST /v1/logforwarding/test", change(accounts.Logging), func(w http.ResponseWriter, r *http.Request, c accounts.Caller) {
			var req struct {
				Name string `json:"name"`
			}
			if !decode(w, r, &req) {
				return
			}
			reply(w, map[string]bool{"sent": true}, d.TestLogServer(c, req.Name))
		}},
		{"GET /v1/dhcp", view(accounts.DHCP), func(w http.ResponseWriter, r *http.Request, c accounts.Caller) {
			reply(w, d.DHCP(), nil)
		}},
		{"GET /v1/dhcp/leases", view(accounts.DHCP), func(w http.ResponseWriter, r *http.Request, c accounts.Caller) {
			v, err := d.DHCPLeases(r.URL.Query().Get("interface"))
			reply(w, v, err)
		}},
		{"GET /v1/netdev", view(accounts.Monitoring), func(w http.ResponseWriter, r *http.Request, c accounts.Caller) {
			states := d.NetDevices()
			if states == nil {
				states = []netdev.State{}
			}
			reply(w, states, nil)
		}},
		{"GET /v1/nics", view(accounts.Monitoring), func(w http.ResponseWriter, r *http.Request, c accounts.Caller) {
			states := d.NICs()
			if states == nil {
				states = []nicaddr.State{}
			}
			reply(w, states, nil)
		}},
		{"GET /v1/api-keys", accounts.SuperuserOnly, func(w http.ResponseWriter, r *http.Request, c accounts.Caller) {
			data, err := d.APIKeys(c)
			if err != nil {
				fail(w, err)
				return
			}
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Write(data)
		}},
		{"POST /v1/api-keys", accounts.SuperuserOnly, func(w http.ResponseWriter, r *http.Request, c accounts.Caller) {
			var req struct {
				Name   string   `json:"name"`
				Scopes []string `json:"scopes"`
			}
			if !decode(w, r, &req) {
				return
			}
			k, err := d.AddAPIKey(c, req.Name, req.Scopes)
			reply(w, map[string]any{"name": k.Name, "scopes": keyScopes(k), "key": k.Key}, err)
		}},
		{"DELETE /v1/api-keys/{name}", accounts.SuperuserOnly, func(w http.ResponseWriter, r *http.Request, c accounts.Caller) {
			reply(w, map[string]bool{"deleted": true}, d.DeleteAPIKey(c, r.PathValue("name")))
		}},
		{"GET /v1/snmp", view(accounts.Logging), func(w http.ResponseWriter, r *http.Request, c accounts.Caller) {
			reply(w, d.SNMP(), nil)
		}},
		{"POST /v1/snmp/credentials", accounts.SuperuserOnly, func(w http.ResponseWriter, r *http.Request, c accounts.Caller) {
			var req struct {
				snmp.Credential
				Replace bool `json:"replace"`
			}
			if !decode(w, r, &req) {
				return
			}
			warnings, err := d.AddSNMPCredential(c, req.Credential, req.Replace)
			reply(w, map[string]any{"saved": true, "warnings": warnings}, err)
		}},
		{"DELETE /v1/snmp/credentials/{name}", accounts.SuperuserOnly, func(w http.ResponseWriter, r *http.Request, c accounts.Caller) {
			reply(w, map[string]bool{"deleted": true}, d.DeleteSNMPCredential(c, r.PathValue("name")))
		}},
		{"GET /v1/metrics", view(accounts.Monitoring), func(w http.ResponseWriter, r *http.Request, c accounts.Caller) {
			w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
			metrics.WritePrometheus(w, d.Metrics())
		}},
		{"GET /v1/tags", view(accounts.Tags), func(w http.ResponseWriter, r *http.Request, c accounts.Caller) {
			reply(w, d.ListTags(""), nil)
		}},
		{"GET /v1/tags/{tag}", view(accounts.Tags), func(w http.ResponseWriter, r *http.Request, c accounts.Caller) {
			reply(w, d.ListTags(r.PathValue("tag")), nil)
		}},
		{"POST /v1/tags/register", change(accounts.Tags), func(w http.ResponseWriter, r *http.Request, c accounts.Caller) {
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
				err = d.RegisterTagsAs(c, ip, req.Tags, time.Duration(req.TTL)*time.Second)
			}
			reply(w, map[string]any{"registered": req.Tags, "ip": req.IP}, err)
		}},
		{"POST /v1/tags/unregister", change(accounts.Tags), func(w http.ResponseWriter, r *http.Request, c accounts.Caller) {
			var req struct {
				IP   string   `json:"ip"`
				Tags []string `json:"tags"`
			}
			if !decode(w, r, &req) {
				return
			}
			ip, err := parseIP(req.IP, req.Tags)
			if err == nil {
				err = d.UnregisterTagsAs(c, ip, req.Tags)
			}
			reply(w, map[string]any{"unregistered": req.Tags, "ip": req.IP}, err)
		}},
	}
	return append(rs, d.accountRoutes()...)
}

// accountRoutes are users, roles and the caller's own password and keys.
// The methods themselves check superuser-or-self.
func (d *Daemon) accountRoutes() []mgmtRoute {
	A := accounts.Anyone
	return []mgmtRoute{
		{"GET /v1/areas", A, func(w http.ResponseWriter, r *http.Request, c accounts.Caller) {
			reply(w, accounts.Areas, nil)
		}},
		{"POST /v1/password", A, func(w http.ResponseWriter, r *http.Request, c accounts.Caller) {
			var req struct {
				User    string `json:"user"` // ignored: you change your own
				Current string `json:"current"`
				New     string `json:"new"`
			}
			if !decode(w, r, &req) {
				return
			}
			reply(w, map[string]string{"status": "password changed"}, d.ChangeOwnPassword(c, req.Current, req.New))
		}},
		{"GET /v1/users", accounts.SuperuserOnly, func(w http.ResponseWriter, r *http.Request, c accounts.Caller) {
			v, err := d.Users(c)
			reply(w, v, err)
		}},
		{"POST /v1/users", accounts.SuperuserOnly, func(w http.ResponseWriter, r *http.Request, c accounts.Caller) {
			var req struct{ Name, Role, Password string }
			if !decode(w, r, &req) {
				return
			}
			reply(w, map[string]string{"status": "user added"}, d.AddUser(c, req.Name, req.Role, req.Password))
		}},
		{"GET /v1/users/{name}", A, func(w http.ResponseWriter, r *http.Request, c accounts.Caller) {
			v, err := d.User(c, r.PathValue("name"))
			reply(w, v, err)
		}},
		{"PATCH /v1/users/{name}", accounts.SuperuserOnly, func(w http.ResponseWriter, r *http.Request, c accounts.Caller) {
			var req struct {
				Role     *string `json:"role"`
				Disabled *bool   `json:"disabled"`
			}
			if !decode(w, r, &req) {
				return
			}
			reply(w, map[string]string{"status": "user changed"}, d.UpdateUser(c, r.PathValue("name"), req.Role, req.Disabled))
		}},
		{"DELETE /v1/users/{name}", accounts.SuperuserOnly, func(w http.ResponseWriter, r *http.Request, c accounts.Caller) {
			reply(w, map[string]string{"status": "user deleted"}, d.DeleteUser(c, r.PathValue("name")))
		}},
		{"POST /v1/users/{name}/password", accounts.SuperuserOnly, func(w http.ResponseWriter, r *http.Request, c accounts.Caller) {
			var req struct{ Password string }
			if !decode(w, r, &req) {
				return
			}
			reply(w, map[string]string{"status": "password set"}, d.SetUserPassword(c, r.PathValue("name"), req.Password))
		}},
		{"POST /v1/users/{name}/unlock", accounts.SuperuserOnly, func(w http.ResponseWriter, r *http.Request, c accounts.Caller) {
			reply(w, map[string]string{"status": "user unlocked"}, d.UnlockUser(c, r.PathValue("name")))
		}},
		{"POST /v1/users/{name}/ssh-keys", A, func(w http.ResponseWriter, r *http.Request, c accounts.Caller) {
			var req struct{ Key string }
			if !decode(w, r, &req) {
				return
			}
			v, err := d.AddSSHKey(c, r.PathValue("name"), req.Key)
			reply(w, v, err)
		}},
		{"DELETE /v1/users/{name}/ssh-keys/{which}", A, func(w http.ResponseWriter, r *http.Request, c accounts.Caller) {
			reply(w, map[string]string{"status": "key deleted"}, d.DeleteSSHKey(c, r.PathValue("name"), r.PathValue("which")))
		}},
		{"GET /v1/roles", accounts.SuperuserOnly, func(w http.ResponseWriter, r *http.Request, c accounts.Caller) {
			v, err := d.Roles(c)
			reply(w, v, err)
		}},
		{"PUT /v1/roles/{name}", accounts.SuperuserOnly, func(w http.ResponseWriter, r *http.Request, c accounts.Caller) {
			var role accounts.Role
			if !decode(w, r, &role) {
				return
			}
			role.Name = r.PathValue("name")
			reply(w, map[string]string{"status": "role saved"}, d.PutRole(c, role))
		}},
		{"DELETE /v1/roles/{name}", accounts.SuperuserOnly, func(w http.ResponseWriter, r *http.Request, c accounts.Caller) {
			reply(w, map[string]string{"status": "role deleted"}, d.DeleteRole(c, r.PathValue("name")))
		}},
	}
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
	return decodeLimit(w, r, v, maxBody)
}

// decodeLimit is decode with a body limit of n bytes.
func decodeLimit(w http.ResponseWriter, r *http.Request, v any, n int64) bool {
	dec := json.NewDecoder(io.LimitReader(r.Body, n))
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

// HTTPStatus maps an error to its HTTP status.
func HTTPStatus(err error) int {
	switch {
	case errors.Is(err, accounts.ErrForbidden):
		return http.StatusForbidden
	case errors.Is(err, accounts.ErrNotFound):
		return http.StatusNotFound
	case errors.Is(err, ErrInvalid), errors.Is(err, accounts.ErrInvalid), errors.Is(err, logs.ErrQuery):
		return http.StatusBadRequest
	}
	return http.StatusInternalServerError
}

func fail(w http.ResponseWriter, err error) {
	code := HTTPStatus(err)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}
