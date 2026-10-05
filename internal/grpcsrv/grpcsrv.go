// Package grpcsrv serves the RouteService over gRPC: it streams a client's
// tenant routes and pushes updates from the tenant.Store.
package grpcsrv

import (
	"context"
	"strings"

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
	peers   *store.Store
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

	id, ch, cur := s.tenants.Subscribe(tenantID)
	defer s.tenants.Unsubscribe(tenantID, id)

	if err := stream.Send(toProto(cur)); err != nil {
		return err
	}
	for {
		select {
		case <-stream.Context().Done():
			return nil
		case set, ok := <-ch:
			if !ok {
				return nil
			}
			if err := stream.Send(toProto(set)); err != nil {
				return err
			}
		}
	}
}

func toProto(s tenant.RouteSet) *routespb.RouteUpdate {
	return &routespb.RouteUpdate{AllowedIps: s.AllowedIPs, Dns: s.DNS, Serial: s.Serial}
}

// AuthStreamInterceptor verifies the bearer (gRPC metadata) and stashes the
// caller's claims in the stream context.
func AuthStreamInterceptor(v auth.Verifier) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		tok := bearerFromContext(ss.Context())
		if tok == "" {
			return status.Error(codes.Unauthenticated, "missing bearer token")
		}
		claims, err := v.Verify(ss.Context(), tok)
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
