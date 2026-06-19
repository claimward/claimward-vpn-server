// Package admin serves the multi-tenant management API and the embedded Svelte
// WebUI under /admin. The API is guarded by a static ADMIN_TOKEN (bearer); the
// SPA is served unauthenticated (it holds the token client-side and presents it
// on each API call).
package admin

import (
	"crypto/subtle"
	"encoding/json"
	"io/fs"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/claimward/claimward-vpn-server/internal/mailer"
	"github.com/claimward/claimward-vpn-server/internal/settings"
	"github.com/claimward/claimward-vpn-server/internal/store"
	"github.com/claimward/claimward-vpn-server/internal/tenant"
)

// Server is the admin HTTP surface.
type Server struct {
	tenants  *tenant.Store
	peers    *store.Store
	token    string
	ui       fs.FS
	mailer   *mailer.Mailer
	settings *settings.Store
	log      *slog.Logger
}

// New builds the admin server. token is the ADMIN_TOKEN; if empty, the admin
// API and UI are disabled. mailer (may be disabled) emails newly-invited members;
// settings holds the admin-editable sender address.
func New(tenants *tenant.Store, peers *store.Store, token string, ui fs.FS, ml *mailer.Mailer, set *settings.Store, log *slog.Logger) *Server {
	return &Server{tenants: tenants, peers: peers, token: token, ui: ui, mailer: ml, settings: set, log: log}
}

// Enabled reports whether the admin surface is configured.
func (s *Server) Enabled() bool { return s.token != "" }

// Register mounts the admin routes on the given mux.
func (s *Server) Register(mux *http.ServeMux) {
	if !s.Enabled() {
		s.log.Warn("ADMIN_TOKEN not set — admin UI/API disabled")
		mux.HandleFunc("/admin/", func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "admin disabled (set ADMIN_TOKEN)", http.StatusServiceUnavailable)
		})
		return
	}
	mux.HandleFunc("GET /admin/api/overview", s.guard(s.overview))
	mux.HandleFunc("GET /admin/api/peers", s.guard(s.listPeers))
	mux.HandleFunc("GET /admin/api/tenants", s.guard(s.listTenants))
	mux.HandleFunc("POST /admin/api/tenants", s.guard(s.createTenant))
	mux.HandleFunc("GET /admin/api/tenants/{id}", s.guard(s.getTenant))
	mux.HandleFunc("PUT /admin/api/tenants/{id}", s.guard(s.updateTenant))
	mux.HandleFunc("DELETE /admin/api/tenants/{id}", s.guard(s.deleteTenant))
	mux.HandleFunc("GET /admin/api/settings", s.guard(s.getSettings))
	mux.HandleFunc("PUT /admin/api/settings", s.guard(s.updateSettings))
	// SPA + assets.
	mux.Handle("/admin/", http.StripPrefix("/admin/", http.FileServer(http.FS(s.ui))))
}

func (s *Server) guard(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := ""
		if h := r.Header.Get("Authorization"); len(h) > 7 && strings.EqualFold(h[:7], "Bearer ") {
			tok = strings.TrimSpace(h[7:])
		}
		if subtle.ConstantTimeCompare([]byte(tok), []byte(s.token)) != 1 {
			writeErr(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		h(w, r)
	}
}

func (s *Server) overview(w http.ResponseWriter, _ *http.Request) {
	tenants := s.tenants.List()
	writeJSON(w, http.StatusOK, map[string]any{
		"tenants":  len(tenants),
		"peers":    len(s.peers.List()),
		"watchers": s.tenants.WatcherCount(),
	})
}

// peerView is the admin-facing JSON shape for an enrolled peer.
type peerView struct {
	Email       string    `json:"email"`
	Tenant      string    `json:"tenant"`
	Device      string    `json:"device"`
	OS          string    `json:"os"`
	Platform    string    `json:"platform"`
	IP          string    `json:"ip"`
	EnrolledAt  time.Time `json:"enrolled_at"`
	LeaseExpiry time.Time `json:"lease_expiry"`
}

// listPeers returns the currently enrolled peers, most recently connected first.
func (s *Server) listPeers(w http.ResponseWriter, _ *http.Request) {
	peers := s.peers.List()
	out := make([]peerView, 0, len(peers))
	for _, p := range peers {
		out = append(out, peerView{
			Email:       p.Email,
			Tenant:      p.Tenant,
			Device:      p.Device.Name,
			OS:          p.Device.OS,
			Platform:    p.Device.Platform,
			IP:          p.IP.String(),
			EnrolledAt:  p.EnrolledAt,
			LeaseExpiry: p.LeaseExpiry,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].EnrolledAt.After(out[j].EnrolledAt) })
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) listTenants(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.tenants.List())
}

func (s *Server) getTenant(w http.ResponseWriter, r *http.Request) {
	t, ok := s.tenants.Get(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "tenant not found")
		return
	}
	writeJSON(w, http.StatusOK, t)
}

func (s *Server) createTenant(w http.ResponseWriter, r *http.Request) {
	var in tenant.Tenant
	if !decode(w, r, &in) {
		return
	}
	t, err := s.tenants.Create(in)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.inviteNew(nil, t.Members, t)
	s.log.Info("tenant created", "id", t.ID)
	writeJSON(w, http.StatusOK, t)
}

func (s *Server) updateTenant(w http.ResponseWriter, r *http.Request) {
	var in tenant.Tenant
	if !decode(w, r, &in) {
		return
	}
	id := r.PathValue("id")
	var oldMembers []string
	if prev, ok := s.tenants.Get(id); ok {
		oldMembers = prev.Members
	}
	t, err := s.tenants.Update(id, in.Name, in.Domains, in.Members, in.AllowedIPs, in.DNS)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.inviteNew(oldMembers, t.Members, t)
	s.log.Info("tenant routes updated", "id", t.ID, "serial", t.Serial, "allowed_ips", t.AllowedIPs)
	writeJSON(w, http.StatusOK, t)
}

// inviteNew emails every member present in current but not in old. Sends run in
// the background so a slow/failing MTA never blocks the API response.
func (s *Server) inviteNew(old, current []string, t tenant.Tenant) {
	if !s.mailer.Enabled() {
		return
	}
	seen := make(map[string]bool, len(old))
	for _, m := range old {
		seen[strings.ToLower(strings.TrimSpace(m))] = true
	}
	for _, m := range current {
		addr := strings.TrimSpace(m)
		if addr == "" || !strings.Contains(addr, "@") {
			continue
		}
		if !seen[strings.ToLower(addr)] {
			go s.mailer.SendInvite(addr, t.Name, t.ID)
		}
	}
}

// settingsView is the admin-facing JSON shape for server settings. The mail_*
// fields are editable; enabled is read-only context for the UI.
type settingsView struct {
	settings.Settings
	Enabled bool `json:"enabled"`
}

func (s *Server) getSettings(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, settingsView{Settings: s.settings.Get(), Enabled: s.mailer.Enabled()})
}

func (s *Server) updateSettings(w http.ResponseWriter, r *http.Request) {
	var in settings.Settings
	if !decode(w, r, &in) {
		return
	}
	cur, err := s.settings.Update(in)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.log.Info("settings updated", "mail_from", cur.MailFrom, "smtp_addr", cur.SMTPAddr)
	writeJSON(w, http.StatusOK, settingsView{Settings: cur, Enabled: s.mailer.Enabled()})
}

func (s *Server) deleteTenant(w http.ResponseWriter, r *http.Request) {
	if err := s.tenants.Delete(r.PathValue("id")); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
