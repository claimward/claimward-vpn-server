// Package api wires the HTTP handlers for claimward-vpn-server together with
// the OIDC verifier, IP allocator, peer store and WireGuard gateway.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/claimward/claimward-vpn-client/pkg/protocol"
	"github.com/claimward/claimward-vpn-server/internal/auth"
	"github.com/claimward/claimward-vpn-server/internal/config"
	"github.com/claimward/claimward-vpn-server/internal/ipam"
	"github.com/claimward/claimward-vpn-server/internal/metrics"
	"github.com/claimward/claimward-vpn-server/internal/store"
	"github.com/claimward/claimward-vpn-server/internal/tenant"
	"github.com/claimward/claimward-vpn-server/internal/wg"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Server holds the dependencies shared by all handlers.
type Server struct {
	cfg          *config.Config
	verifier     auth.Verifier
	alloc        *ipam.Allocator
	store        *store.Store
	gw           wg.Gateway
	tenants      *tenant.Store
	metrics      *metrics.Metrics
	serverPubKey string
	log          *slog.Logger
}

// New builds the API server.
func New(cfg *config.Config, v auth.Verifier, alloc *ipam.Allocator, st *store.Store, gw wg.Gateway, ts *tenant.Store, m *metrics.Metrics, serverPub string, log *slog.Logger) *Server {
	return &Server{cfg: cfg, verifier: v, alloc: alloc, store: st, gw: gw, tenants: ts, metrics: m, serverPubKey: serverPub, log: log}
}

// Handler returns the configured HTTP mux.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+protocol.PathHealthz, s.handleHealthz)
	mux.Handle("POST "+protocol.PathEnroll, s.authenticated(s.handleEnroll))
	mux.Handle("POST "+protocol.PathHeartbeat, s.authenticated(s.handleHeartbeat))
	mux.Handle("POST "+protocol.PathDeregister, s.authenticated(s.handleDeregister))
	mux.Handle("GET "+protocol.PathTenants, s.authenticated(s.handleTenants))
	return s.withLogging(mux)
}

// claimsKey is the context key carrying verified identity claims.
type claimsKey struct{}

// authenticated verifies the bearer ID token and injects the claims.
func (s *Server) authenticated(next func(http.ResponseWriter, *http.Request, *auth.Claims)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := bearerToken(r)
		if raw == "" {
			writeErr(w, http.StatusUnauthorized, "missing_token", "Authorization: Bearer <id_token> required")
			return
		}
		claims, err := s.verifier.Verify(r.Context(), raw)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "invalid_token", err.Error())
			return
		}
		ctx := context.WithValue(r.Context(), claimsKey{}, claims)
		next(w, r.WithContext(ctx), claims)
	})
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleTenants returns the tenants the authenticated user may connect to.
func (s *Server) handleTenants(w http.ResponseWriter, _ *http.Request, claims *auth.Claims) {
	entitled := s.tenants.TenantsForEmail(claims.Email)
	out := make([]protocol.TenantInfo, 0, len(entitled))
	for _, t := range entitled {
		out = append(out, protocol.TenantInfo{ID: t.ID, Name: t.Name})
	}
	writeJSON(w, http.StatusOK, out)
}

// chooseTenant resolves which tenant to use from the user's entitled set and
// their optional explicit choice. ok is false when the set is empty, the choice
// is ambiguous (multiple tenants, none specified), or the chosen tenant is not
// one the user belongs to.
func chooseTenant(entitled []tenant.Tenant, chosen string) (string, bool) {
	if len(entitled) == 0 {
		return "", false
	}
	if chosen == "" {
		if len(entitled) == 1 {
			return entitled[0].ID, true
		}
		return "", false
	}
	for _, t := range entitled {
		if t.ID == chosen {
			return t.ID, true
		}
	}
	return "", false
}

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request, claims *auth.Claims) {
	var req protocol.EnrollRequest
	if !decode(w, r, &req) {
		return
	}
	pub, err := wgtypes.ParseKey(req.PublicKey)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_public_key", err.Error())
		return
	}

	// Resolve and authorize the tenant. Access is by explicit membership; the
	// user picks among the tenants they were invited to.
	entitled := s.tenants.TenantsForEmail(claims.Email)
	tenantID, ok := chooseTenant(entitled, req.Tenant)
	if !ok {
		switch {
		case len(entitled) == 0:
			writeErr(w, http.StatusForbidden, "no_tenant", "you have not been invited to any tenant")
		case req.Tenant == "":
			writeErr(w, http.StatusBadRequest, "tenant_required", "you belong to multiple tenants; specify which to connect to")
		default:
			writeErr(w, http.StatusForbidden, "not_a_member", "you are not a member of tenant "+req.Tenant)
		}
		return
	}

	expiry := time.Now().Add(s.cfg.LeaseTTL)

	// Reuse the existing assignment if this device is already enrolled.
	var ip net.IP
	if existing := s.store.Get(req.PublicKey); existing != nil {
		ip = existing.IP
	} else {
		ip, err = s.alloc.Allocate()
		if err != nil {
			writeErr(w, http.StatusServiceUnavailable, "pool_exhausted", err.Error())
			return
		}
	}

	if err := s.gw.AddPeer(pub, ip); err != nil {
		s.alloc.Release(ip)
		s.log.Error("gateway add peer failed", "err", err)
		writeErr(w, http.StatusInternalServerError, "gateway_error", "could not program gateway")
		return
	}

	s.store.Put(&store.Peer{
		PublicKey:   req.PublicKey,
		Subject:     claims.Subject,
		Email:       claims.Email,
		Tenant:      tenantID,
		IP:          ip,
		Device:      req.Device,
		EnrolledAt:  time.Now(),
		LeaseExpiry: expiry,
	})
	s.log.Info("enrolled", "email", claims.Email, "ip", ip.String(), "device", req.Device.Name, "platform", req.Device.Platform)

	rs := s.tenants.Routes(tenantID)
	s.metrics.EnrollInc(tenantID)
	s.log.Info("enrolled tenant routes", "tenant", tenantID, "email", claims.Email, "routes", rs.AllowedIPs)
	writeJSON(w, http.StatusOK, protocol.EnrollResponse{
		AssignedIP:          ip.String() + "/32",
		ServerPublicKey:     s.serverPubKey,
		Endpoint:            s.cfg.WGEndpoint,
		AllowedIPs:          rs.AllowedIPs,
		DNS:                 rs.DNS,
		GRPCEndpoint:        s.cfg.GRPCEndpoint,
		PersistentKeepalive: s.cfg.Keepalive,
		LeaseExpiresAt:      expiry,
	})
}

func (s *Server) handleHeartbeat(w http.ResponseWriter, r *http.Request, claims *auth.Claims) {
	var req protocol.HeartbeatRequest
	if !decode(w, r, &req) {
		return
	}
	peer := s.store.Get(req.PublicKey)
	if peer == nil || peer.Subject != claims.Subject {
		writeErr(w, http.StatusNotFound, "not_enrolled", "no active enrollment for this key")
		return
	}
	expiry := time.Now().Add(s.cfg.LeaseTTL)
	s.store.Renew(req.PublicKey, expiry)
	writeJSON(w, http.StatusOK, protocol.HeartbeatResponse{LeaseExpiresAt: expiry})
}

func (s *Server) handleDeregister(w http.ResponseWriter, r *http.Request, claims *auth.Claims) {
	var req protocol.DeregisterRequest
	if !decode(w, r, &req) {
		return
	}
	peer := s.store.Get(req.PublicKey)
	if peer == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if peer.Subject != claims.Subject {
		writeErr(w, http.StatusForbidden, "not_owner", "this key belongs to another user")
		return
	}
	pub, err := wgtypes.ParseKey(req.PublicKey)
	if err == nil {
		if err := s.gw.RemovePeer(pub); err != nil {
			s.log.Error("gateway remove peer failed", "err", err)
		}
	}
	s.store.Delete(req.PublicKey)
	s.alloc.Release(peer.IP)
	s.log.Info("deregistered", "email", claims.Email, "ip", peer.IP.String())
	w.WriteHeader(http.StatusNoContent)
}

// ReapExpired removes peers whose lease has ended. Called periodically.
func (s *Server) ReapExpired() {
	now := time.Now()
	for _, p := range s.store.Expired(now) {
		if pub, err := wgtypes.ParseKey(p.PublicKey); err == nil {
			if err := s.gw.RemovePeer(pub); err != nil {
				s.log.Error("reap remove peer failed", "err", err)
			}
		}
		s.store.Delete(p.PublicKey)
		s.alloc.Release(p.IP)
		s.log.Info("lease expired, peer removed", "email", p.Email, "ip", p.IP.String())
	}
}

// --- helpers ---

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "Bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, protocol.ErrorResponse{Error: code, Message: msg})
}

func (s *Server) withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		s.log.Debug("request", "method", r.Method, "path", r.URL.Path, "status", sw.status, "dur", time.Since(start).String())
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

var _ = errors.New // reserved for future typed errors
