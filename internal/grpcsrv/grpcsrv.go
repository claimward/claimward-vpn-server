// Package grpcsrv serves the RouteService over gRPC: it streams a client's
// tenant routes and pushes updates from the tenant.Store.
package grpcsrv

import (
	"context"
	"strings"
	"time"

	"github.com/claimward/claimward-vpn-client/pkg/protocol"
	"github.com/claimward/claimward-vpn-client/pkg/routespb"
	"github.com/claimward/claimward-vpn-server/internal/auth"
	"github.com/claimward/claimward-vpn-server/internal/store"
	"github.com/claimward/claimward-vpn-server/internal/tenant"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type claimsKeyT struct{}

var claimsKey claimsKeyT

// Server implements routespb.RouteServiceServer backed by the tenant store.
type Server struct {
	routespb.UnimplementedRouteServiceServer
	tenants *tenant.Store

	beforeSubscribe func() // test seam, nil in production
	peers           *store.Store
	recheck         time.Duration // idle re-authorisation period; DefaultRecheck when zero
}

// New returns a RouteService server.
func New(ts *tenant.Store, peers *store.Store) *Server { return &Server{tenants: ts, peers: peers} }

// Watch streams the caller's tenant routes (current + updates) until they leave.
//
// ⛔ The tenant is the one the device enrolled into -- a person in several
// chooses per session -- found by the device's key, which must be theirs:
// naming another person's key must not stream that person's routes.
func (s *Server) Watch(req *routespb.WatchRequest, stream routespb.RouteService_WatchServer) error {
	claims, _ := stream.Context().Value(claimsKey).(*auth.Claims)
	if claims == nil {
		return status.Error(codes.Unauthenticated, "no identity")
	}
	p := s.peers.Get(req.GetPublicKey())
	if p == nil || p.Subject != claims.Subject {
		return status.Error(codes.NotFound, "no enrollment of yours for this key")
	}
	tenantID := p.Tenant
	if _, ok := s.tenants.Get(tenantID); !ok || !s.tenants.IsMember(tenantID, claims.Tenancy()) {
		return status.Error(codes.PermissionDenied, "you are not a member of the tenant this device enrolled into")
	}

	if s.beforeSubscribe != nil {
		s.beforeSubscribe() // test seam: the tenant may be deleted right here
	}
	id, ch, cur, err := s.tenants.Subscribe(tenantID)
	if err != nil {
		return status.Error(codes.NotFound, err.Error())
	}
	defer s.tenants.Unsubscribe(tenantID, id)

	// ⛔ The stream was authorised once, at its start, and used to be pushed
	// to for as long as it stayed open: after the peer was reaped or
	// deregistered, the person removed from the tenant, or the token expired,
	// it kept receiving the tenant's routes. It is now re-authorised before
	// every Send and on a timer, and ends with the token.
	var expired <-chan time.Time
	if !claims.Expires.IsZero() {
		d := time.Until(claims.Expires)
		if d <= 0 {
			return status.Error(codes.Unauthenticated, "token expired")
		}
		t := time.NewTimer(d)
		defer t.Stop()
		expired = t.C
	}
	tick := time.NewTicker(s.recheckEvery())
	defer tick.Stop()

	if err := stream.Send(toProto(cur)); err != nil {
		return err
	}
	for {
		select {
		case <-stream.Context().Done():
			return nil
		case <-expired:
			return status.Error(codes.Unauthenticated, "token expired")
		case <-tick.C:
			if err := s.stillAuthorised(req.GetPublicKey(), tenantID, claims); err != nil {
				return err
			}
		case set, ok := <-ch:
			if !ok {
				return nil
			}
			if err := s.stillAuthorised(req.GetPublicKey(), tenantID, claims); err != nil {
				return err
			}
			if err := stream.Send(toProto(set)); err != nil {
				return err
			}
		}
	}
}

// DefaultRecheck is how often an idle stream is re-authorised.
const DefaultRecheck = 15 * time.Second

func (s *Server) recheckEvery() time.Duration {
	if s.recheck > 0 {
		return s.recheck
	}
	return DefaultRecheck
}

// stillAuthorised is whether the device is still enrolled by the caller and
// the caller is still a member of the tenant it enrolled into.
func (s *Server) stillAuthorised(key, tenantID string, claims *auth.Claims) error {
	p := s.peers.Get(key)
	if p == nil || p.Subject != claims.Subject || p.Tenant != tenantID {
		return status.Error(codes.NotFound, "enrollment ended")
	}
	if _, ok := s.tenants.Get(tenantID); !ok || !s.tenants.IsMember(tenantID, claims.Tenancy()) {
		return status.Error(codes.PermissionDenied, "you are no longer a member of the tenant")
	}
	return nil
}

func toProto(s tenant.RouteSet) *routespb.RouteUpdate {
	return &routespb.RouteUpdate{AllowedIps: s.AllowedIPs, Dns: s.DNS, Serial: s.Serial}
}

// AuthStreamInterceptor verifies the bearer (gRPC metadata) and stashes the
// caller's claims in the stream context.
//
// The provider is named in the "claimward-provider" metadata
// (protocol.MetadataProvider), and the token is checked by that provider only.
func AuthStreamInterceptor(v auth.Authenticator) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		tok := bearerFromContext(ss.Context())
		if tok == "" {
			return status.Error(codes.Unauthenticated, "missing bearer token")
		}
		claims, err := v.Verify(ss.Context(), providerFromContext(ss.Context()), tok)
		if err != nil {
			return status.Error(codes.Unauthenticated, "invalid token: "+err.Error())
		}
		ctx := context.WithValue(ss.Context(), claimsKey, claims)
		return handler(srv, &wrappedStream{ServerStream: ss, ctx: ctx})
	}
}

type wrappedStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (w *wrappedStream) Context() context.Context { return w.ctx }

// providerFromContext is the provider id the caller named, "" when none (or
// when it named several: an ambiguous request names none).
func providerFromContext(ctx context.Context) string {
	// A context with no metadata gives a nil MD, whose Get answers nothing.
	md, _ := metadata.FromIncomingContext(ctx)
	v := md.Get(protocol.MetadataProvider)
	if len(v) != 1 {
		return ""
	}
	return v[0]
}

func bearerFromContext(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	for _, v := range md.Get("authorization") {
		if len(v) > 7 && strings.EqualFold(v[:7], "Bearer ") {
			return strings.TrimSpace(v[7:])
		}
	}
	return ""
}
