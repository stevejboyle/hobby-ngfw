package webui

import (
	"net/http"

	"github.com/stevejboyle/sjb-os/internal/accounts"
)

// accountRoutes: users and roles (superusers), and every user's own SSH
// keys. They call the same Daemon methods as the CLI, which check
// superuser-or-self again.
func (s *server) accountRoutes(mux *http.ServeMux) {
	su, any := accounts.SuperuserOnly, accounts.Anyone
	ok := func(w http.ResponseWriter, err error) { reply(w, map[string]bool{"ok": true}, err) }

	mux.HandleFunc("GET /ui/api/areas", s.auth(any, func(w http.ResponseWriter, r *http.Request, _ *session, _ string) {
		reply(w, accounts.Areas, nil)
	}))
	mux.HandleFunc("GET /ui/api/me", s.auth(any, func(w http.ResponseWriter, r *http.Request, ss *session, _ string) {
		v, err := s.d.User(ss.caller(), ss.user)
		reply(w, v, err)
	}))
	mux.HandleFunc("GET /ui/api/users", s.auth(su, func(w http.ResponseWriter, r *http.Request, ss *session, _ string) {
		v, err := s.d.Users(ss.caller())
		reply(w, v, err)
	}))
	mux.HandleFunc("POST /ui/api/users", s.auth(su, func(w http.ResponseWriter, r *http.Request, ss *session, _ string) {
		var req struct {
			Name     string `json:"name"`
			Role     string `json:"role"`
			Password string `json:"password"`
		}
		if decode(w, r, &req) {
			ok(w, s.d.AddUser(ss.caller(), req.Name, req.Role, req.Password))
		}
	}))
	mux.HandleFunc("PATCH /ui/api/users/{name}", s.auth(su, func(w http.ResponseWriter, r *http.Request, ss *session, _ string) {
		var req struct {
			Role     *string `json:"role"`
			Disabled *bool   `json:"disabled"`
		}
		if decode(w, r, &req) {
			ok(w, s.d.UpdateUser(ss.caller(), r.PathValue("name"), req.Role, req.Disabled))
		}
	}))
	mux.HandleFunc("DELETE /ui/api/users/{name}", s.auth(su, func(w http.ResponseWriter, r *http.Request, ss *session, _ string) {
		ok(w, s.d.DeleteUser(ss.caller(), r.PathValue("name")))
	}))
	mux.HandleFunc("POST /ui/api/users/{name}/password", s.auth(su, func(w http.ResponseWriter, r *http.Request, ss *session, _ string) {
		var req struct {
			Password string `json:"password"`
		}
		if decode(w, r, &req) {
			ok(w, s.d.SetUserPassword(ss.caller(), r.PathValue("name"), req.Password))
		}
	}))
	mux.HandleFunc("POST /ui/api/users/{name}/unlock", s.auth(su, func(w http.ResponseWriter, r *http.Request, ss *session, _ string) {
		ok(w, s.d.UnlockUser(ss.caller(), r.PathValue("name")))
	}))
	// SSH keys: anyone for their own account, superusers for any.
	mux.HandleFunc("POST /ui/api/users/{name}/ssh-keys", s.auth(any, func(w http.ResponseWriter, r *http.Request, ss *session, _ string) {
		var req struct {
			Key string `json:"key"`
		}
		if decode(w, r, &req) {
			v, err := s.d.AddSSHKey(ss.caller(), r.PathValue("name"), req.Key)
			reply(w, v, err)
		}
	}))
	mux.HandleFunc("DELETE /ui/api/users/{name}/ssh-keys/{which}", s.auth(any, func(w http.ResponseWriter, r *http.Request, ss *session, _ string) {
		ok(w, s.d.DeleteSSHKey(ss.caller(), r.PathValue("name"), r.PathValue("which")))
	}))
	mux.HandleFunc("GET /ui/api/roles", s.auth(su, func(w http.ResponseWriter, r *http.Request, ss *session, _ string) {
		v, err := s.d.Roles(ss.caller())
		reply(w, v, err)
	}))
	mux.HandleFunc("PUT /ui/api/roles/{name}", s.auth(su, func(w http.ResponseWriter, r *http.Request, ss *session, _ string) {
		var role accounts.Role
		if decode(w, r, &role) {
			role.Name = r.PathValue("name")
			ok(w, s.d.PutRole(ss.caller(), role))
		}
	}))
	mux.HandleFunc("DELETE /ui/api/roles/{name}", s.auth(su, func(w http.ResponseWriter, r *http.Request, ss *session, _ string) {
		ok(w, s.d.DeleteRole(ss.caller(), r.PathValue("name")))
	}))
}
