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
	"github.com/go-authn/wireguard"
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

	// peers, when set, is the provider's list of registered keys: a key is
	// enrolled only if its owner registered it there (AUTH_PROVIDER=go-authn).
	peers Registry
}

// Registry says whose a WireGuard key is, and until when -- the go-authn
// provider's list (internal/peers).
type Registry interface {
	Lookup(key string) (wireguard.Peer, bool)
}

// UsePeers makes enrollment depend on reg: a key must be registered there,
// by the person enrolling it.
func (s *Server) UsePeers(reg Registry) { s.peers = reg }

// registered is whether the key may be enrolled by claims' subject, and the
// latest its lease may run to. Without a registry every key may, until the
// lease TTL.
func (s *Server) registered(key string, claims *auth.Claims, lease time.Time) (time.Time, bool) {
	if s.peers == nil {
		return lease, true
	}
	p, ok := s.peers.Lookup(key)
	if !ok || p.Subject != claims.Subject {
		return time.Time{}, false
	}
	if p.Expires.Before(lease) {
		lease = p.Expires
	}
	return lease, true
}

// Reconcile drops every enrolled peer allowed no longer: a key the provider
// took back, or one now registered to somebody else.
func (s *Server) Reconcile(allowed func(key, subject string) bool) {
	for _, p := range s.store.List() {
		if allowed(p.PublicKey, p.Subject) {
			continue
		}
		if pub, err := wgtypes.ParseKey(p.PublicKey); err == nil {
			if err := s.gw.RemovePeer(pub); err != nil {
				s.log.Error("reconcile remove peer failed", "err", err)
			}
		}
		s.store.Delete(p.PublicKey)
		s.alloc.Release(p.IP)
		s.log.Info("key no longer registered, peer removed", "email", p.Email, "ip", p.IP.String())
	}
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

// handleTenants lists the tenants the caller may connect to, for a client to
// offer the choice.
func (s *Server) handleTenants(w http.ResponseWriter, _ *http.Request, claims *auth.Claims) {
	ts := s.tenants.For(claims.Tenancy())
	out := make([]protocol.TenantInfo, 0, len(ts))
	for _, t := range ts {
		out = append(out, protocol.TenantInfo{ID: t.ID, Name: t.Name})
	}
	writeJSON(w, http.StatusOK, out)
}

// chooseTenant is the tenant an enrollment is for: the one asked for, if the
// caller is a member; with none asked for, the caller's only tenant. A
// person in several must choose -- connecting them to one picked here would
// route them into a network they did not ask for. A non-zero code is the
// refusal, with its error code and message.
func (s *Server) chooseTenant(asked string, claims *auth.Claims) (string, int, [2]string) {
	ts := s.tenants.For(claims.Tenancy())
	if asked == "" {
		if len(ts) == 1 {
			return ts[0].ID, 0, [2]string{}
		}
		ids := make([]string, 0, len(ts))
		for _, t := range ts {
			ids = append(ids, t.ID)
		}
		return "", http.StatusConflict, [2]string{"tenant_required", "you belong to several tenants; choose one of: " + strings.Join(ids, ", ")}
	}
	for _, t := range ts {
		if t.ID == asked {
			return asked, 0, [2]string{}
		}
	}
	return "", http.StatusForbidden, [2]string{"not_a_member", "you are not a member of tenant " + asked}
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
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

	expiry, ok := s.registered(req.PublicKey, claims, time.Now().Add(s.cfg.LeaseTTL))
	if !ok {
		writeErr(w, http.StatusForbidden, "key_not_registered", "register this device's key with the identity provider first")
		return
	}
	tenantID, code, why := s.chooseTenant(req.Tenant, claims)
	if code != 0 {
		writeErr(w, code, why[0], why[1])
		return
	}

	// Reuse the existing assignment if this device is already enrolled.
	var ip net.IP
	if existing := s.store.Get(req.PublicKey); existing != nil {
		// ⛔ A public key is public: anybody can read one off a peer list or
		// a configuration. Enrolling it again under another identity used to
		// make that identity its owner -- and the owner may deregister it --
		// so a key stays with whoever enrolled it, as heartbeat and
		// deregister already assumed.
		if existing.Subject != claims.Subject {
			writeErr(w, http.StatusConflict, "key_taken", "this key is enrolled by another user")
			return
		}
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
		IP:          ip,
		Device:      req.Device,
		EnrolledAt:  time.Now(),
		LeaseExpiry: expiry,
		Tenant:      tenantID,
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
	// A person removed from the tenant -- a group, a domain, an institution
	// taken off it -- renews nothing in it.
	if !s.tenants.IsMember(peer.Tenant, claims.Tenancy()) {
		writeErr(w, http.StatusForbidden, "not_a_member", "you are no longer a member of this tenant")
		return
	}
	// A lease is renewed only while the key is still registered, and never
	// past its registration.
	expiry, ok := s.registered(req.PublicKey, claims, time.Now().Add(s.cfg.LeaseTTL))
	if !ok {
		writeErr(w, http.StatusForbidden, "key_not_registered", "this device's key is no longer registered with the identity provider")
		return
	}
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
