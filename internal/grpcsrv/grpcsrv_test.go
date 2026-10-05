package grpcsrv

import (
	"context"
	"testing"
	"time"

	"github.com/claimward/claimward-vpn-client/pkg/routespb"
	"github.com/claimward/claimward-vpn-server/internal/auth"
	"github.com/claimward/claimward-vpn-server/internal/store"
	"github.com/claimward/claimward-vpn-server/internal/tenant"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// stream is a Watch stream as the server sees one: a context carrying the
// caller's claims, and the updates it was sent.
type stream struct {
	grpc.ServerStream
	ctx  context.Context
	sent []*routespb.RouteUpdate
}

func (s *stream) Context() context.Context { return s.ctx }
func (s *stream) Send(u *routespb.RouteUpdate) error {
	s.sent = append(s.sent, u)
	return nil
}

func watch(t *testing.T, srv *Server, c *auth.Claims, key string) (*stream, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.WithValue(context.Background(), claimsKey, c), 100*time.Millisecond)
	defer cancel()
	st := &stream{ctx: ctx}
	return st, srv.Watch(&routespb.WatchRequest{PublicKey: key}, st)
}

// The routes streamed are the tenant the device enrolled into, for the
// device's owner only, and only while they are a member.
func TestWatchStreamsTheTenantOfTheSession(t *testing.T) {
	ts := tenant.New([]string{"10.80.0.0/24"}, nil)
	for _, in := range []tenant.Tenant{
		{ID: "chem", Groups: []string{"chem"}, AllowedIPs: []string{"10.1.0.0/16"}},
		{ID: "hpc", Groups: []string{"hpc"}, AllowedIPs: []string{"10.2.0.0/16"}},
	} {
		ts.Create(in)
	}
	peers := store.New()
	peers.Put(&store.Peer{PublicKey: "carols-laptop", Subject: "sub-carol", Tenant: "hpc"})
	srv := New(ts, peers)
	carol := &auth.Claims{Subject: "sub-carol", Groups: []string{"chem", "hpc"}}

	st, err := watch(t, srv, carol, "carols-laptop")
	if err != nil {
		t.Fatal(err)
	}
	if len(st.sent) == 0 || st.sent[0].AllowedIps[0] != "10.2.0.0/16" {
		t.Errorf("carol's laptop, enrolled into hpc, was sent %v", st.sent)
	}
	// Somebody else naming carol's key.
	if _, err := watch(t, srv, &auth.Claims{Subject: "sub-mallory", Groups: []string{"hpc"}}, "carols-laptop"); status.Code(err) != codes.NotFound {
		t.Errorf("another person's key: %v", err)
	}
	// Carol taken off hpc.
	if _, err := watch(t, srv, &auth.Claims{Subject: "sub-carol", Groups: []string{"chem"}}, "carols-laptop"); status.Code(err) != codes.PermissionDenied {
		t.Errorf("after leaving hpc: %v", err)
	}
	// No identity at all.
	if err := srv.Watch(&routespb.WatchRequest{PublicKey: "carols-laptop"}, &stream{ctx: context.Background()}); status.Code(err) != codes.Unauthenticated {
		t.Errorf("no claims: %v", err)
	}
}
