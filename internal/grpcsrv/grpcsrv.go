// Package grpcsrv serves the RouteService over gRPC: it streams the current
// routes to authenticated clients and pushes updates from the routes.Manager.
package grpcsrv

import (
	"context"
	"strings"

	"github.com/claimward/claimward-vpn-client/pkg/routespb"
	"github.com/claimward/claimward-vpn-server/internal/auth"
	"github.com/claimward/claimward-vpn-server/internal/routes"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Server implements routespb.RouteServiceServer backed by a routes.Manager.
type Server struct {
	routespb.UnimplementedRouteServiceServer
	mgr *routes.Manager
}

// New returns a RouteService server.
func New(mgr *routes.Manager) *Server { return &Server{mgr: mgr} }

// Watch sends the current routes, then streams updates until the client leaves.
func (s *Server) Watch(_ *routespb.WatchRequest, stream routespb.RouteService_WatchServer) error {
	id, ch, cur := s.mgr.Subscribe()
	defer s.mgr.Unsubscribe(id)

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

func toProto(s routes.Set) *routespb.RouteUpdate {
	return &routespb.RouteUpdate{AllowedIps: s.AllowedIPs, Dns: s.DNS, Serial: s.Serial}
}

// AuthStreamInterceptor verifies the OIDC bearer (gRPC metadata) before any
// streaming RPC is served.
func AuthStreamInterceptor(v auth.Verifier) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		tok := bearerFromContext(ss.Context())
		if tok == "" {
			return status.Error(codes.Unauthenticated, "missing bearer token")
		}
		if _, err := v.Verify(ss.Context(), tok); err != nil {
			return status.Error(codes.Unauthenticated, "invalid token: "+err.Error())
		}
		return handler(srv, ss)
	}
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
