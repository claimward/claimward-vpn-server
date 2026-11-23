package grpcsrv

// An open Watch is re-authorised (2026-11-23 security audit): once the peer
// or the membership is gone, or the token has expired, the stream ends and is
// pushed nothing more.

import (
	"context"
	"testing"
	"time"

	"github.com/claimward/claimward-vpn-client/pkg/routespb"
	"github.com/claimward/claimward-vpn-server/internal/auth"
	"github.com/claimward/claimward-vpn-server/internal/store"
	"github.com/claimward/claimward-vpn-server/internal/tenant"
)

type chanStream struct {
	stream
	out chan *routespb.RouteUpdate
}

func (s *chanStream) Send(u *routespb.RouteUpdate) error { s.out <- u; return nil }

// open starts a Watch for carol on hpc and returns once the initial set is
// sent; done receives the Watch's result.
func open(t *testing.T, claims *auth.Claims, recheck time.Duration) (*tenant.Store, *store.Store, *chanStream, chan error) {
	t.Helper()
	ts := tenant.New([]string{"10.80.0.0/24"}, nil)
	ts.Create(tenant.Tenant{ID: "hpc", Groups: []string{"hpc"}, AllowedIPs: []string{"10.2.0.0/16"}})
	peers := store.New()
	peers.Put(&store.Peer{PublicKey: "k", Subject: "sub-carol", Tenant: "hpc"})
	srv := New(ts, peers)
	srv.recheck = recheck

	ctx, cancel := context.WithTimeout(context.WithValue(context.Background(), claimsKey, claims), 5*time.Second)
	t.Cleanup(cancel)
	st := &chanStream{stream: stream{ctx: ctx}, out: make(chan *routespb.RouteUpdate, 4)}
	done := make(chan error, 1)
	go func() { done <- srv.Watch(&routespb.WatchRequest{PublicKey: "k"}, st) }()
	select {
	case <-st.out:
	case <-time.After(2 * time.Second):
		t.Fatal("no initial route set")
	}
	return ts, peers, st, done
}

func carol() *auth.Claims { return &auth.Claims{Subject: "sub-carol", Groups: []string{"hpc"}} }

func TestWatchStopsWhenPeerAndMembershipAreGone(t *testing.T) {
	ts, peers, st, _ := open(t, carol(), time.Hour)
	peers.Delete("k")
	if _, err := ts.Update("hpc", tenant.Tenant{Groups: []string{"someone-else"}, AllowedIPs: []string{"10.2.0.0/16", "10.99.0.0/16"}}); err != nil {
		t.Fatal(err)
	}
	select {
	case u := <-st.out:
		t.Errorf("after the peer was deleted and carol left hpc, the stream was still pushed %v (serial %d)", u.AllowedIps, u.Serial)
	case <-time.After(300 * time.Millisecond):
	}
}

// A push after the peer is gone but the person is still a member is refused
// too: the device, not only the person, must still be enrolled.
func TestWatchPushesNothingToAReapedPeer(t *testing.T) {
	ts, peers, st, done := open(t, carol(), time.Hour)
	peers.Delete("k")
	if _, err := ts.Update("hpc", tenant.Tenant{Groups: []string{"hpc"}, AllowedIPs: []string{"10.2.0.0/16", "10.99.0.0/16"}}); err != nil {
		t.Fatal(err)
	}
	select {
	case u := <-st.out:
		t.Errorf("a reaped peer was pushed %v", u.AllowedIps)
	case <-done:
	case <-time.After(time.Second):
		t.Error("stream still open")
	}
}

// An idle stream ends on its own when the peer is reaped or deregistered.
func TestWatchEndsWhenPeerIsReapedWhileIdle(t *testing.T) {
	_, peers, _, done := open(t, carol(), 20*time.Millisecond)
	peers.Delete("k")
	select {
	case err := <-done:
		if err == nil {
			t.Error("Watch returned nil, want an error naming the ended enrollment")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("an idle stream outlived its peer")
	}
}

func TestWatchEndsWhenMembershipIsRemovedWhileIdle(t *testing.T) {
	ts, _, _, done := open(t, carol(), 20*time.Millisecond)
	if _, err := ts.Update("hpc", tenant.Tenant{Groups: []string{"someone-else"}, AllowedIPs: []string{"10.2.0.0/16"}}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("an idle stream outlived the person's membership")
	}
}

func TestWatchEndsAtTokenExpiry(t *testing.T) {
	c := carol()
	c.Expires = time.Now().Add(150 * time.Millisecond)
	_, _, _, done := open(t, c, time.Hour)
	select {
	case err := <-done:
		if err == nil {
			t.Error("Watch returned nil at token expiry")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the stream outlived its token")
	}
}

func TestWatchRefusesAnExpiredToken(t *testing.T) {
	c := carol()
	c.Expires = time.Now().Add(-time.Second)
	ts := tenant.New([]string{"10.80.0.0/24"}, nil)
	ts.Create(tenant.Tenant{ID: "hpc", Groups: []string{"hpc"}, AllowedIPs: []string{"10.2.0.0/16"}})
	peers := store.New()
	peers.Put(&store.Peer{PublicKey: "k", Subject: "sub-carol", Tenant: "hpc"})
	if _, err := watch(t, New(ts, peers), c, "k"); err == nil {
		t.Error("an expired token was streamed to")
	}
}
