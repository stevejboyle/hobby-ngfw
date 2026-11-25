// Package webui is the SJB-OS web interface: a session-authenticated JSON
// API over the daemon's commit and tag operations, plus the embedded static
// pages that use it. It serves on the management interface only.
package webui

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/stevejboyle/sjb-os/internal/accounts"
	"github.com/stevejboyle/sjb-os/internal/backup"
	"github.com/stevejboyle/sjb-os/internal/config"
	"github.com/stevejboyle/sjb-os/internal/daemon"
	"github.com/stevejboyle/sjb-os/internal/logs"
	"github.com/stevejboyle/sjb-os/internal/netdev"
	"github.com/stevejboyle/sjb-os/internal/snmp"
	"github.com/stevejboyle/sjb-os/internal/nicaddr"
	"github.com/stevejboyle/sjb-os/internal/upgrade"
)

//go:embed static
var static embed.FS

// Upgrader runs appliance upgrades for the UI.
type Upgrader interface {
	Status() (upgrade.Status, error)
	// Stage verifies an uploaded bundle and keeps it for Start.
	Stage(r io.Reader) (*upgrade.Manifest, error)
	// Start applies the staged bundle in the background.
	Start() error
	// Rollback returns to the previous version in the background.
	Rollback() error
}

// Options configures the UI.
type Options struct {
	Upgrader Upgrader
	Logs     logs.Reader // nil: the Logs page says logs aren't available
	Log      *slog.Logger
	Now      func() time.Time
	// Interfaces returns live addresses per interface name; nil uses the
	// host's interfaces.
	Interfaces func(name string) []string
}

type server struct {
	d     *daemon.Daemon
	o     Options
	sess  *sessions
	limit *limiter
}

// New returns the UI handler.
func New(d *daemon.Daemon, o Options) http.Handler {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Log == nil {
		o.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if o.Interfaces == nil {
		o.Interfaces = hostAddrs
	}
	s := &server{
		d: d, o: o,
		sess:  &sessions{m: map[string]*session{}, now: o.Now},
		limit: &limiter{m: map[string]*attempts{}, now: o.Now},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /ui/api/login", s.login)
	mux.HandleFunc("POST /ui/api/logout", s.auth(accounts.Anyone, s.logout))
	mux.HandleFunc("GET /ui/api/session", s.auth(accounts.Anyone, s.whoami))
	mux.HandleFunc("POST /ui/api/password", s.auth(accounts.Anyone, s.password))
	mux.HandleFunc("GET /ui/api/status", s.auth(accounts.Anyone, s.status))
	mux.HandleFunc("GET /ui/api/config/{which}", s.auth(accounts.ConfigView, s.getConfig))
	mux.HandleFunc("PUT /ui/api/config/candidate", s.auth(accounts.ConfigEdit, s.putCandidate))
	mux.HandleFunc("POST /ui/api/config/revert", s.auth(accounts.ConfigEdit, s.revert))
	mux.HandleFunc("GET /ui/api/diff", s.auth(accounts.ConfigView, s.diff))
	mux.HandleFunc("GET /ui/api/preview", s.auth(accounts.ConfigView, s.preview))
	mux.HandleFunc("POST /ui/api/commit", s.auth(accounts.ConfigEdit, s.commit))
	mux.HandleFunc("POST /ui/api/confirm", s.auth(accounts.NeedChange(accounts.Revisions), s.confirm))
	mux.HandleFunc("POST /ui/api/rollback", s.auth(accounts.NeedChange(accounts.Revisions), s.rollback))
	mux.HandleFunc("GET /ui/api/revisions", s.auth(accounts.NeedView(accounts.Revisions), s.revisions))
	mux.HandleFunc("GET /ui/api/revisions/{n}", s.auth(accounts.NeedView(accounts.Revisions), s.revision))
	mux.HandleFunc("GET /ui/api/routes", s.auth(accounts.NeedView(accounts.Monitoring), func(w http.ResponseWriter, r *http.Request, _ *session, _ string) {
		reply(w, s.d.Routes(), nil)
	}))
	mux.HandleFunc("GET /ui/api/nat", s.auth(accounts.NeedView(accounts.Monitoring), func(w http.ResponseWriter, r *http.Request, _ *session, _ string) {
		reply(w, s.d.NAT(), nil)
	}))
	mux.HandleFunc("GET /ui/api/logs/{kind}", s.auth(accounts.NeedView(accounts.Monitoring), s.logs))
	mux.HandleFunc("GET /ui/api/logs/traffic/columns", s.auth(accounts.NeedView(accounts.Monitoring), func(w http.ResponseWriter, r *http.Request, _ *session, _ string) {
		reply(w, map[string]any{"columns": logs.TrafficColumns, "default": logs.DefaultTrafficColumns,
			"threat_columns": logs.ThreatColumns, "threat_default": logs.DefaultThreatColumns,
			"decryption_columns": logs.DecryptionColumns, "decryption_default": logs.DefaultDecryptionColumns,
			"fields": map[string]any{"traffic": logs.TrafficSchema.Fields(), "threat": logs.ThreatSchema.Fields(),
				"decryption": logs.DecryptionSchema.Fields(), "system": logs.SystemSchema.Fields()}}, nil)
	}))
	mux.HandleFunc("GET /ui/api/stats", s.auth(accounts.NeedView(accounts.Monitoring), func(w http.ResponseWriter, r *http.Request, _ *session, _ string) {
		win := r.URL.Query().Get("window")
		if win == "" {
			win = "1h"
		}
		v, err := s.d.Stats(win)
		if err != nil {
			fail(w, http.StatusBadRequest, err.Error())
			return
		}
		reply(w, v, nil)
	}))
	mux.HandleFunc("GET /ui/api/ips", s.auth(accounts.NeedView(accounts.IPS), func(w http.ResponseWriter, r *http.Request, _ *session, _ string) {
		reply(w, s.d.IPS(), nil)
	}))
	mux.HandleFunc("POST /ui/api/ips/update", s.auth(accounts.NeedChange(accounts.IPS), func(w http.ResponseWriter, r *http.Request, ss *session, _ string) {
		s.o.Log.Info("IPS signature update requested", "by", s.author(ss))
		v, err := s.d.UpdateIPS(r.Context())
		reply(w, v, err)
	}))
	mux.HandleFunc("POST /ui/api/backup/export", s.auth(accounts.ConfigView, func(w http.ResponseWriter, r *http.Request, ss *session, _ string) {
		var req struct {
			Accounts   bool   `json:"accounts"`
			Passphrase string `json:"passphrase"`
		}
		if !decode(w, r, &req) {
			return
		}
		v, err := s.d.ExportBackup(ss.caller(), req.Accounts, req.Passphrase)
		if err != nil {
			daemonFail(w, err)
			return
		}
		reply(w, v, nil)
	}))
	mux.HandleFunc("POST /ui/api/backup/inspect", s.auth(accounts.ConfigView, func(w http.ResponseWriter, r *http.Request, ss *session, _ string) {
		var req struct {
			Data string `json:"data"`
		}
		if !decodeLimit(w, r, &req, 2*backup.MaxSize) {
			return
		}
		v, err := s.d.InspectBackup(ss.caller(), []byte(req.Data))
		if err != nil {
			daemonFail(w, err)
			return
		}
		reply(w, v, nil)
	}))
	mux.HandleFunc("POST /ui/api/backup/restore", s.auth(accounts.ConfigEdit, func(w http.ResponseWriter, r *http.Request, ss *session, _ string) {
		var req daemon.RestoreRequest
		if !decodeLimit(w, r, &req, 2*backup.MaxSize) {
			return
		}
		v, err := s.d.RestoreBackup(ss.caller(), req)
		if err != nil {
			daemonFail(w, err)
			return
		}
		reply(w, v, nil)
	}))
	mux.HandleFunc("GET /ui/api/logforwarding", s.auth(accounts.NeedView(accounts.Logging), func(w http.ResponseWriter, r *http.Request, _ *session, _ string) {
		reply(w, s.d.LogForwarding(), nil)
	}))
	mux.HandleFunc("POST /ui/api/logforwarding/test", s.auth(accounts.NeedChange(accounts.Logging), func(w http.ResponseWriter, r *http.Request, ss *session, _ string) {
		var req struct {
			Name string `json:"name"`
		}
		if !decode(w, r, &req) {
			return
		}
		if err := s.d.TestLogServer(ss.caller(), req.Name); err != nil {
			daemonFail(w, err)
			return
		}
		reply(w, map[string]bool{"sent": true}, nil)
	}))
	mux.HandleFunc("GET /ui/api/snmp", s.auth(accounts.NeedView(accounts.Logging), func(w http.ResponseWriter, r *http.Request, _ *session, _ string) {
		reply(w, s.d.SNMP(), nil)
	}))
	mux.HandleFunc("POST /ui/api/snmp/credentials", s.auth(accounts.SuperuserOnly, func(w http.ResponseWriter, r *http.Request, ss *session, _ string) {
		var req struct {
			snmp.Credential
			Replace bool `json:"replace"`
		}
		if !decode(w, r, &req) {
			return
		}
		if err := s.d.AddSNMPCredential(ss.caller(), req.Credential, req.Replace); err != nil {
			daemonFail(w, err)
			return
		}
		reply(w, map[string]bool{"saved": true}, nil)
	}))
	mux.HandleFunc("POST /ui/api/snmp/credentials/delete", s.auth(accounts.SuperuserOnly, func(w http.ResponseWriter, r *http.Request, ss *session, _ string) {
		var req struct {
			Name string `json:"name"`
		}
		if !decode(w, r, &req) {
			return
		}
		if err := s.d.DeleteSNMPCredential(ss.caller(), req.Name); err != nil {
			daemonFail(w, err)
			return
		}
		reply(w, map[string]bool{"deleted": true}, nil)
	}))
	mux.HandleFunc("GET /ui/api/api-keys", s.auth(accounts.SuperuserOnly, func(w http.ResponseWriter, r *http.Request, ss *session, _ string) {
		v, err := s.d.ListAPIKeys(ss.caller())
		if err != nil {
			daemonFail(w, err)
			return
		}
		reply(w, v, nil)
	}))
	mux.HandleFunc("POST /ui/api/api-keys", s.auth(accounts.SuperuserOnly, func(w http.ResponseWriter, r *http.Request, ss *session, _ string) {
		var req struct {
			Name   string   `json:"name"`
			Scopes []string `json:"scopes"`
		}
		if !decode(w, r, &req) {
			return
		}
		k, err := s.d.AddAPIKey(ss.caller(), req.Name, req.Scopes)
		if err != nil {
			daemonFail(w, err)
			return
		}
		reply(w, map[string]any{"name": k.Name, "key": k.Key}, nil)
	}))
	mux.HandleFunc("POST /ui/api/api-keys/delete", s.auth(accounts.SuperuserOnly, func(w http.ResponseWriter, r *http.Request, ss *session, _ string) {
		var req struct {
			Name string `json:"name"`
		}
		if !decode(w, r, &req) {
			return
		}
		if err := s.d.DeleteAPIKey(ss.caller(), req.Name); err != nil {
			daemonFail(w, err)
			return
		}
		reply(w, map[string]bool{"deleted": true}, nil)
	}))
	mux.HandleFunc("GET /ui/api/decryption", s.auth(accounts.NeedView(accounts.Decryption), func(w http.ResponseWriter, r *http.Request, _ *session, _ string) {
		reply(w, s.d.Decryption(), nil)
	}))
	mux.HandleFunc("GET /ui/api/decryption/ca", s.auth(accounts.NeedView(accounts.DecryptionCA), func(w http.ResponseWriter, r *http.Request, _ *session, _ string) {
		reply(w, s.d.DecryptionCA(), nil)
	}))
	// The CA certificate as a file, to install on clients.
	mux.HandleFunc("GET /ui/api/decryption/ca.crt", s.auth(accounts.NeedView(accounts.DecryptionCA), func(w http.ResponseWriter, r *http.Request, _ *session, _ string) {
		ca := s.d.DecryptionCA()
		if !ca.Present {
			fail(w, http.StatusNotFound, "no decryption CA yet")
			return
		}
		w.Header().Set("Content-Type", "application/x-x509-ca-cert")
		w.Header().Set("Content-Disposition", `attachment; filename="sjb-os-decryption-ca.crt"`)
		io.WriteString(w, ca.PEM)
	}))
	mux.HandleFunc("POST /ui/api/decryption/ca/generate", s.auth(accounts.NeedChange(accounts.DecryptionCA), func(w http.ResponseWriter, r *http.Request, ss *session, _ string) {
		v, err := s.d.GenerateDecryptionCA(s.author(ss))
		if err != nil {
			daemonFail(w, err)
			return
		}
		reply(w, v, nil)
	}))
	mux.HandleFunc("POST /ui/api/decryption/ca/import", s.auth(accounts.NeedChange(accounts.DecryptionCA), func(w http.ResponseWriter, r *http.Request, ss *session, _ string) {
		var req struct {
			Cert string `json:"cert"`
			Key  string `json:"key"`
		}
		if !decode(w, r, &req) {
			return
		}
		v, err := s.d.ImportDecryptionCA(s.author(ss), []byte(req.Cert), []byte(req.Key))
		if err != nil {
			daemonFail(w, err)
			return
		}
		reply(w, v, nil)
	}))
	mux.HandleFunc("GET /ui/api/mgmt-cert", s.auth(accounts.NeedView(accounts.Certificates), func(w http.ResponseWriter, r *http.Request, _ *session, _ string) {
		v, err := s.d.MgmtCert()
		if err != nil {
			daemonFail(w, err)
			return
		}
		reply(w, v, nil)
	}))
	mux.HandleFunc("POST /ui/api/mgmt-cert/import", s.auth(accounts.NeedChange(accounts.Certificates), func(w http.ResponseWriter, r *http.Request, ss *session, _ string) {
		var req struct {
			Cert string `json:"cert"`
			Key  string `json:"key"`
		}
		if !decode(w, r, &req) {
			return
		}
		v, err := s.d.ImportMgmtCert(s.author(ss), []byte(req.Cert), []byte(req.Key))
		if err != nil {
			daemonFail(w, err)
			return
		}
		reply(w, v, nil)
	}))
	mux.HandleFunc("POST /ui/api/mgmt-cert/self-signed", s.auth(accounts.NeedChange(accounts.Certificates), func(w http.ResponseWriter, r *http.Request, ss *session, _ string) {
		v, err := s.d.ResetMgmtCert(s.author(ss))
		if err != nil {
			daemonFail(w, err)
			return
		}
		reply(w, v, nil)
	}))
	mux.HandleFunc("GET /ui/api/decryption/learned", s.auth(accounts.NeedView(accounts.Decryption), func(w http.ResponseWriter, r *http.Request, _ *session, _ string) {
		v, err := s.d.DecryptionLearned()
		if err != nil {
			daemonFail(w, err)
			return
		}
		reply(w, v, nil)
	}))
	mux.HandleFunc("POST /ui/api/decryption/learned/clear", s.auth(accounts.NeedChange(accounts.Decryption), func(w http.ResponseWriter, r *http.Request, ss *session, _ string) {
		n, err := s.d.ClearDecryptionLearned(s.author(ss))
		if err != nil {
			daemonFail(w, err)
			return
		}
		reply(w, map[string]int{"cleared": n}, nil)
	}))
	mux.HandleFunc("GET /ui/api/routing/{what}", s.auth(accounts.NeedView(accounts.Monitoring), func(w http.ResponseWriter, r *http.Request, _ *session, _ string) {
		v, err := s.d.RoutingStatus(r.PathValue("what"), r.URL.Query().Get("vrf"))
		reply(w, v, err)
	}))
	mux.HandleFunc("GET /ui/api/apps", s.auth(accounts.NeedView(accounts.Monitoring), func(w http.ResponseWriter, r *http.Request, _ *session, _ string) {
		reply(w, s.d.Apps(), nil)
	}))
	mux.HandleFunc("GET /ui/api/apps/categories", s.auth(accounts.Anyone, func(w http.ResponseWriter, r *http.Request, _ *session, _ string) {
		reply(w, s.d.AppCategories(), nil)
	}))
	mux.HandleFunc("GET /ui/api/apps/catalog", s.auth(accounts.Anyone, func(w http.ResponseWriter, r *http.Request, _ *session, _ string) {
		v, err := s.d.AppCatalog(r.URL.Query().Get("q"))
		reply(w, v, err)
	}))
	mux.HandleFunc("GET /ui/api/dhcp", s.auth(accounts.NeedView(accounts.DHCP), func(w http.ResponseWriter, r *http.Request, _ *session, _ string) {
		reply(w, s.d.DHCP(), nil)
	}))
	mux.HandleFunc("GET /ui/api/dhcp/leases", s.auth(accounts.NeedView(accounts.DHCP), func(w http.ResponseWriter, r *http.Request, _ *session, _ string) {
		v, err := s.d.DHCPLeases(r.URL.Query().Get("interface"))
		reply(w, v, err)
	}))
	mux.HandleFunc("GET /ui/api/netdev", s.auth(accounts.NeedView(accounts.Monitoring), func(w http.ResponseWriter, r *http.Request, _ *session, _ string) {
		st := s.d.NetDevices()
		if st == nil {
			st = []netdev.State{}
		}
		reply(w, st, nil)
	}))
	mux.HandleFunc("GET /ui/api/nics", s.auth(accounts.NeedView(accounts.Monitoring), func(w http.ResponseWriter, r *http.Request, _ *session, _ string) {
		st := s.d.NICs()
		if st == nil {
			st = []nicaddr.State{}
		}
		reply(w, st, nil)
	}))
	mux.HandleFunc("GET /ui/api/arp", s.auth(accounts.NeedView(accounts.Monitoring), func(w http.ResponseWriter, r *http.Request, _ *session, _ string) {
		nb, err := s.d.Neighbors()
		reply(w, nb, err)
	}))
	mux.HandleFunc("GET /ui/api/tags", s.auth(accounts.NeedView(accounts.Tags), s.tags))
	mux.HandleFunc("POST /ui/api/tags/{op}", s.auth(accounts.NeedChange(accounts.Tags), s.tagOp))
	mux.HandleFunc("GET /ui/api/upgrade", s.auth(accounts.NeedView(accounts.Upgrades), s.upgradeStatus))
	mux.HandleFunc("POST /ui/api/upgrade", s.auth(accounts.NeedChange(accounts.Upgrades), s.upgradeUpload))
	mux.HandleFunc("POST /ui/api/upgrade/start", s.auth(accounts.NeedChange(accounts.Upgrades), s.upgradeStart))
	mux.HandleFunc("POST /ui/api/upgrade/rollback", s.auth(accounts.NeedChange(accounts.Upgrades), s.upgradeRollback))
	s.accountRoutes(mux)
	mux.HandleFunc("/ui/api/", func(w http.ResponseWriter, r *http.Request) {
		fail(w, http.StatusNotFound, "no such API call")
	})
	sub, _ := fs.Sub(static, "static")
	mux.Handle("/", http.FileServerFS(sub))
	return headers(mux)
}

func headers(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("X-SJB-OS", "Stops Junk at the Border")
		hd.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("Referrer-Policy", "no-referrer")
		hd.Set("Cache-Control", "no-store")
		h.ServeHTTP(w, r)
	})
}

type ctxHandler func(w http.ResponseWriter, r *http.Request, ss *session, tok string)

// auth requires a session whose user still exists, isn't disabled and
// hasn't changed password since; the CSRF header on anything but GET; and
// that the user's current role meets need.
func (s *server) auth(need accounts.Need, h ctxHandler) http.HandlerFunc {
	if !need.Valid() {
		panic("web route without a permission")
	}
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(cookieName)
		var ss *session
		if err == nil {
			ss = s.sess.get(c.Value)
		}
		if ss == nil {
			fail(w, http.StatusUnauthorized, "not logged in")
			return
		}
		p, err := s.principal(ss)
		if err != nil {
			s.sess.drop(c.Value)
			fail(w, http.StatusUnauthorized, "session ended: "+strings.TrimPrefix(err.Error(), accounts.ErrForbidden.Error()+": "))
			return
		}
		if r.Method != http.MethodGet && r.Header.Get(csrfHeader) != ss.csrf {
			fail(w, http.StatusForbidden, "missing or wrong "+csrfHeader+" header")
			return
		}
		if err := p.Check(need); err != nil {
			fail(w, http.StatusForbidden, strings.TrimPrefix(err.Error(), accounts.ErrForbidden.Error()+": "))
			return
		}
		h(w, r, ss, c.Value)
	}
}

// principal is the session user's current role.
func (s *server) principal(ss *session) (accounts.Principal, error) {
	if a := s.d.Accounts(); a != nil {
		return a.Principal(ss.user, ss.since)
	}
	p := accounts.RootPrincipal()
	p.Name = ss.user
	return p, nil
}

func clientAddr(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *server) login(w http.ResponseWriter, r *http.Request) {
	var req struct{ User, Password string }
	if !decode(w, r, &req) {
		return
	}
	addr := clientAddr(r)
	if d := s.limit.blocked(addr); d > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(int(d.Seconds())+1))
		fail(w, http.StatusTooManyRequests, fmt.Sprintf("too many failed logins; try again in %ds", int(d.Seconds())+1))
		return
	}
	a := s.d.Accounts()
	if a == nil {
		fail(w, http.StatusServiceUnavailable, "no user database on this system")
		return
	}
	if _, err := a.Authenticate(req.User, req.Password, addr); err != nil {
		switch {
		case errors.Is(err, accounts.ErrLocked), errors.Is(err, accounts.ErrDisabled):
			s.o.Log.Warn("web login refused", "user", req.User, "from", addr, "why", err.Error())
			fail(w, http.StatusForbidden, err.Error())
		case errors.Is(err, accounts.ErrBadLogin):
			s.limit.fail(addr)
			s.o.Log.Warn("web login failed", "user", req.User, "from", addr)
			fail(w, http.StatusUnauthorized, "wrong user name or password")
		default:
			fail(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	s.limit.ok(addr)
	tok, ss := s.sess.create(req.User)
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: tok, Path: "/", HttpOnly: true, Secure: true,
		SameSite: http.SameSiteStrictMode, MaxAge: int(SessionIdle.Seconds()),
	})
	s.o.Log.Info("web login", "user", req.User, "from", addr)
	s.whoami(w, r, ss, tok)
}

func (s *server) logout(w http.ResponseWriter, r *http.Request, ss *session, tok string) {
	s.sess.drop(tok)
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	reply(w, map[string]bool{"ok": true}, nil)
}

func (s *server) whoami(w http.ResponseWriter, r *http.Request, ss *session, _ string) {
	me, err := s.d.Me(ss.caller())
	if err != nil {
		daemonFail(w, err)
		return
	}
	reply(w, map[string]any{"user": ss.user, "csrf": ss.csrf, "role": me.Role, "superuser": me.Superuser,
		"permissions": me.Permissions, "config_view": me.ConfigView, "config_edit": me.ConfigEdit, "areas": me.Areas}, nil)
}

func (s *server) password(w http.ResponseWriter, r *http.Request, ss *session, tok string) {
	var req struct {
		Current string `json:"current"`
		New     string `json:"new"`
	}
	if !decode(w, r, &req) {
		return
	}
	if err := s.d.ChangeOwnPassword(ss.caller(), req.Current, req.New); err != nil {
		daemonFail(w, err)
		return
	}
	// Other sessions of this user end; this one carries on.
	s.sess.dropUser(ss.user, tok)
	if u, err := s.d.Accounts().User(ss.user); err == nil && u.PasswordChanged != nil {
		s.sess.setSince(tok, *u.PasswordChanged)
	}
	s.o.Log.Info("web password changed", "user", ss.user)
	reply(w, map[string]bool{"ok": true}, nil)
}

func (s *server) author(ss *session) string { return ss.caller().Author() }

// --- status --------------------------------------------------------------

type ifaceStatus struct {
	Name  string   `json:"name"`
	Zone  string   `json:"zone"`
	Addrs []string `json:"addrs"`
}

func (s *server) status(w http.ResponseWriter, r *http.Request, _ *session, _ string) {
	st, err := s.d.Status()
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := map[string]any{
		"running_revision":    st.Running,
		"uncommitted_changes": st.Pending,
		"confirm_by":          st.ConfirmBy,
		"now":                 s.o.Now().UTC(),
	}
	if s.o.Upgrader != nil {
		if us, err := s.o.Upgrader.Status(); err == nil {
			out["version"] = us.Version
		}
	}
	host, _ := os.Hostname()
	out["hostname"] = host
	counts := map[string]int{}
	var ifaces []ifaceStatus
	if _, run, err := s.d.Running(); err == nil && len(run) > 0 {
		if cfg, err := config.Parse(run); err == nil {
			counts = map[string]int{
				"zones": len(cfg.Zones), "rules": len(cfg.Rules), "nat": len(cfg.NAT),
				"addresses": len(cfg.Addresses), "address_groups": len(cfg.AddressGroups), "services": len(cfg.Services),
				"routes": len(cfg.Routes),
			}
			if cfg.System.MgmtInterface != "" {
				ifaces = append(ifaces, ifaceStatus{Name: cfg.System.MgmtInterface, Zone: "(management)", Addrs: s.o.Interfaces(cfg.System.MgmtInterface)})
			}
			for _, i := range cfg.Interfaces {
				if i.Name == cfg.System.MgmtInterface {
					continue
				}
				ifaces = append(ifaces, ifaceStatus{Name: i.Name, Zone: i.Zone, Addrs: s.o.Interfaces(i.Name)})
			}
		}
	}
	out["counts"] = counts
	out["interfaces"] = ifaces
	perTag := map[string]int{}
	for _, e := range s.d.ListTags("") {
		perTag[e.Tag]++
	}
	out["tags"] = perTag
	reply(w, out, nil)
}

func hostAddrs(name string) []string {
	out := []string{}
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return out
	}
	addrs, _ := ifi.Addrs()
	for _, a := range addrs {
		if p, err := netip.ParsePrefix(a.String()); err == nil && p.Addr().Is4() {
			out = append(out, p.String())
		}
	}
	return out
}

// --- config --------------------------------------------------------------

func (s *server) getConfig(w http.ResponseWriter, r *http.Request, _ *session, _ string) {
	var data []byte
	var err error
	switch r.PathValue("which") {
	case "candidate":
		data, err = s.d.Candidate()
	case "running":
		_, data, err = s.d.Running()
	default:
		fail(w, http.StatusNotFound, "config is candidate or running")
		return
	}
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	if r.URL.Query().Get("format") == "yaml" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write(data)
		return
	}
	cfg := &config.Config{}
	if len(strings.TrimSpace(string(data))) > 0 {
		if cfg, err = config.Parse(data); err != nil {
			fail(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	reply(w, cfg, nil)
}

// putCandidate takes the whole config as JSON, stores it as YAML.
func (s *server) putCandidate(w http.ResponseWriter, r *http.Request, ss *session, _ string) {
	var cfg config.Config
	if !decode(w, r, &cfg) {
		return
	}
	data, err := yaml.Marshal(&cfg)
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.d.SetCandidateAs(ss.caller(), data); err != nil {
		daemonFail(w, err)
		return
	}
	s.o.Log.Info("candidate changed", "author", s.author(ss))
	reply(w, map[string]bool{"ok": true}, nil)
}

func (s *server) revert(w http.ResponseWriter, r *http.Request, ss *session, _ string) {
	err := s.d.RevertCandidateAs(ss.caller())
	reply(w, map[string]bool{"ok": err == nil}, err)
}

func (s *server) diff(w http.ResponseWriter, r *http.Request, _ *session, _ string) {
	d, err := s.d.Diff()
	reply(w, map[string]string{"diff": d}, err)
}

func (s *server) preview(w http.ResponseWriter, r *http.Request, _ *session, _ string) {
	res, err := s.d.Preview()
	if err != nil {
		daemonFail(w, err)
		return
	}
	warn := res.Warnings
	if warn == nil {
		warn = []string{}
	}
	reply(w, map[string]any{"ruleset": res.Ruleset, "warnings": warn}, nil)
}

func (s *server) commit(w http.ResponseWriter, r *http.Request, ss *session, _ string) {
	var req struct {
		Message        string `json:"message"`
		ConfirmMinutes int    `json:"confirm_minutes"`
	}
	if !decode(w, r, &req) {
		return
	}
	if req.ConfirmMinutes < 0 || req.ConfirmMinutes > 60 {
		fail(w, http.StatusBadRequest, "confirm_minutes must be 0-60")
		return
	}
	res, err := s.d.CommitAs(ss.caller(), req.Message, time.Duration(req.ConfirmMinutes)*time.Minute)
	if err != nil {
		daemonFail(w, err)
		return
	}
	reply(w, res, nil)
}

func (s *server) confirm(w http.ResponseWriter, r *http.Request, ss *session, _ string) {
	if err := s.d.ConfirmAs(ss.caller()); err != nil {
		daemonFail(w, err)
		return
	}
	reply(w, map[string]bool{"ok": true}, nil)
}

func (s *server) rollback(w http.ResponseWriter, r *http.Request, ss *session, _ string) {
	var req struct {
		Revision int `json:"revision"`
	}
	if !decode(w, r, &req) {
		return
	}
	res, err := s.d.RollbackAs(ss.caller(), req.Revision)
	if err != nil {
		daemonFail(w, err)
		return
	}
	reply(w, res, nil)
}

func (s *server) revisions(w http.ResponseWriter, r *http.Request, _ *session, _ string) {
	revs, err := s.d.Revisions()
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	sort.Slice(revs, func(i, j int) bool { return revs[i].N > revs[j].N })
	n, _, _ := s.d.Running()
	reply(w, map[string]any{"running": n, "revisions": revs}, nil)
}

func (s *server) revision(w http.ResponseWriter, r *http.Request, _ *session, _ string) {
	n, err := strconv.Atoi(r.PathValue("n"))
	if err != nil || n < 1 {
		fail(w, http.StatusBadRequest, "revision must be a positive number")
		return
	}
	data, err := s.d.Revision(n)
	if err != nil {
		fail(w, http.StatusNotFound, err.Error())
		return
	}
	reply(w, map[string]any{"n": n, "yaml": string(data)}, nil)
}

// --- tags ----------------------------------------------------------------

func (s *server) tags(w http.ResponseWriter, r *http.Request, _ *session, _ string) {
	now := s.o.Now()
	type row struct {
		IP        string     `json:"ip"`
		Tag       string     `json:"tag"`
		Expires   *time.Time `json:"expires,omitempty"`
		Remaining int        `json:"remaining_seconds"`
	}
	rows := []row{}
	for _, e := range s.d.ListTags("") {
		rw := row{IP: e.IP.String(), Tag: e.Tag}
		if !e.Expires.IsZero() {
			t := e.Expires
			rw.Expires = &t
			rw.Remaining = int(e.Remaining(now).Seconds())
		}
		rows = append(rows, rw)
	}
	reply(w, rows, nil)
}

func (s *server) tagOp(w http.ResponseWriter, r *http.Request, ss *session, _ string) {
	var req struct {
		IP   string   `json:"ip"`
		Tags []string `json:"tags"`
		TTL  int      `json:"ttl"`
	}
	if !decode(w, r, &req) {
		return
	}
	ip, err := netip.ParseAddr(strings.TrimSpace(req.IP))
	if err != nil || !ip.Is4() {
		fail(w, http.StatusBadRequest, "ip must be an IPv4 address")
		return
	}
	if len(req.Tags) == 0 {
		fail(w, http.StatusBadRequest, "at least one tag required")
		return
	}
	switch r.PathValue("op") {
	case "register":
		if req.TTL < 0 {
			fail(w, http.StatusBadRequest, "ttl must be >= 0")
			return
		}
		err = s.d.RegisterTagsAs(ss.caller(), ip, req.Tags, time.Duration(req.TTL)*time.Second)
	case "unregister":
		err = s.d.UnregisterTagsAs(ss.caller(), ip, req.Tags)
	default:
		fail(w, http.StatusNotFound, "tags/register or tags/unregister")
		return
	}
	if err != nil {
		daemonFail(w, err)
		return
	}
	reply(w, map[string]bool{"ok": true}, nil)
}

// --- logs ----------------------------------------------------------------

func (s *server) logs(w http.ResponseWriter, r *http.Request, _ *session, _ string) {
	if s.o.Logs == nil {
		fail(w, http.StatusServiceUnavailable, "logs are not available on this system")
		return
	}
	n, _ := strconv.Atoi(r.URL.Query().Get("n"))
	q := r.URL.Query().Get("q")
	var v any
	var err error
	switch r.PathValue("kind") {
	case "traffic":
		var t []logs.Traffic
		t, err = s.o.Logs.Traffic(n, q)
		if t == nil {
			t = []logs.Traffic{}
		}
		v = t
	case "system":
		var sy []logs.System
		sy, err = s.o.Logs.System(n, q)
		if sy == nil {
			sy = []logs.System{}
		}
		v = sy
	case "threat":
		var th []logs.Threat
		th, err = s.o.Logs.Threat(n, q)
		if th == nil {
			th = []logs.Threat{}
		}
		v = th
	case "decryption":
		var de []logs.Decryption
		de, err = s.o.Logs.Decryption(n, q)
		if de == nil {
			de = []logs.Decryption{}
		}
		v = de
	default:
		fail(w, http.StatusNotFound, "logs are traffic, threat, decryption or system")
		return
	}
	if errors.Is(err, logs.ErrQuery) {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	if err != nil {
		fail(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	reply(w, v, nil)
}

// --- upgrades ------------------------------------------------------------

func (s *server) upgrader(w http.ResponseWriter) bool {
	if s.o.Upgrader == nil {
		fail(w, http.StatusNotImplemented, "upgrades are not available on this system")
		return false
	}
	return true
}

func (s *server) upgradeStatus(w http.ResponseWriter, r *http.Request, _ *session, _ string) {
	if !s.upgrader(w) {
		return
	}
	st, err := s.o.Upgrader.Status()
	reply(w, st, err)
}

func (s *server) upgradeUpload(w http.ResponseWriter, r *http.Request, ss *session, _ string) {
	if !s.upgrader(w) {
		return
	}
	m, err := s.o.Upgrader.Stage(http.MaxBytesReader(w, r.Body, upgrade.MaxBundleSize))
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	s.o.Log.Info("upgrade bundle staged", "author", s.author(ss), "version", m.Version)
	reply(w, map[string]any{"version": m.Version, "files": len(m.Files)}, nil)
}

func (s *server) upgradeStart(w http.ResponseWriter, r *http.Request, ss *session, _ string) {
	if !s.upgrader(w) {
		return
	}
	if st, err := s.d.Status(); err == nil && st.ConfirmBy != nil {
		fail(w, http.StatusConflict, errPendingConfirm)
		return
	}
	if err := s.o.Upgrader.Start(); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	s.o.Log.Info("upgrade started", "author", s.author(ss))
	reply(w, map[string]bool{"started": true}, nil)
}

func (s *server) upgradeRollback(w http.ResponseWriter, r *http.Request, ss *session, _ string) {
	if !s.upgrader(w) {
		return
	}
	if st, err := s.d.Status(); err == nil && st.ConfirmBy != nil {
		fail(w, http.StatusConflict, errPendingConfirm)
		return
	}
	if err := s.o.Upgrader.Rollback(); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	s.o.Log.Info("upgrade rollback started", "author", s.author(ss))
	reply(w, map[string]bool{"started": true}, nil)
}

// errPendingConfirm: an upgrade restarts ngfwd, which must not race a
// commit's auto-rollback.
const errPendingConfirm = "a commit is waiting for confirmation; confirm it (or let it roll back) first"

// --- helpers -------------------------------------------------------------

const maxBody = 4 << 20

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	return decodeLimit(w, r, v, maxBody)
}

func decodeLimit(w http.ResponseWriter, r *http.Request, v any, n int64) bool {
	dec := json.NewDecoder(io.LimitReader(r.Body, n))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil && !errors.Is(err, io.EOF) {
		fail(w, http.StatusBadRequest, "bad JSON: "+err.Error())
		return false
	}
	return true
}

func reply(w http.ResponseWriter, v any, err error) {
	if err != nil {
		daemonFail(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// daemonFail maps daemon errors: validation problems are 400 with each
// problem listed separately so the UI can show them against fields.
func daemonFail(w http.ResponseWriter, err error) {
	code := daemon.HTTPStatus(err)
	if code != http.StatusBadRequest {
		msg := err.Error()
		for _, e := range []error{accounts.ErrForbidden, accounts.ErrNotFound} {
			msg = strings.TrimPrefix(msg, e.Error()+": ")
		}
		fail(w, code, msg)
		return
	}
	msg := strings.TrimPrefix(err.Error(), daemon.ErrInvalid.Error()+": ")
	var list []string
	for _, l := range strings.Split(msg, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			list = append(list, l)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(map[string]any{"error": msg, "errors": list})
}
