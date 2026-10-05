package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
)

// tokens is a verifier whose bearer tokens are the people's names.
type tokens map[string]*auth.Claims

func (t tokens) Verify(_ context.Context, bearer string) (*auth.Claims, error) {
	if c, ok := t[bearer]; ok {
		return c, nil
	}
	return nil, errors.New("unknown token")
}

var people = tokens{
	"alice": {Subject: "sub-alice", Email: "alice@example.org"},
	"bob":   {Subject: "sub-bob", Email: "bob@example.org"},
}

func newServer(t *testing.T) (*Server, *store.Store) {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := &config.Config{VPNCIDR: "10.80.0.0/24", LeaseTTL: time.Hour, WGEndpoint: "vpn.example.org:51820"}
	alloc, err := ipam.New(cfg.VPNCIDR)
	if err != nil {
		t.Fatal(err)
	}
	st := store.New()
	ts := tenant.New([]string{cfg.VPNCIDR}, nil)
	return New(cfg, people, alloc, st, wg.NewDryRunGateway(log), ts, metrics.New(st, ts), "c2VydmVy", log), st
}

func call(t *testing.T, h http.Handler, path, bearer string, body any) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(body)
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(b)))
	r.Header.Set("Authorization", "Bearer "+bearer)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

const aliceKey = "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw="

// ⛔ A public key is public. Bob, who read Alice's key off a peer list, must
// not become its owner by enrolling it -- an owner may deregister it, and
// Alice's tunnel with it.
func TestAnEnrolledKeyStaysWithItsOwner(t *testing.T) {
	s, st := newServer(t)
	h := s.Handler()
	if w := call(t, h, protocol.PathEnroll, "alice", protocol.EnrollRequest{PublicKey: aliceKey}); w.Code != http.StatusOK {
		t.Fatalf("alice enrolling: %d %s", w.Code, w.Body)
	}
	if w := call(t, h, protocol.PathEnroll, "bob", protocol.EnrollRequest{PublicKey: aliceKey}); w.Code != http.StatusConflict {
		t.Errorf("bob enrolling alice's key: %d %s", w.Code, w.Body)
	}
	if p := st.Get(aliceKey); p == nil || p.Subject != "sub-alice" {
		t.Fatalf("the key now belongs to %+v", p)
	}
	if w := call(t, h, protocol.PathDeregister, "bob", protocol.DeregisterRequest{PublicKey: aliceKey}); w.Code != http.StatusForbidden {
		t.Errorf("bob deregistering alice's key: %d", w.Code)
	}
	// Alice enrolling again is a renewal, at the same address.
	ip := st.Get(aliceKey).IP.String()
	if w := call(t, h, protocol.PathEnroll, "alice", protocol.EnrollRequest{PublicKey: aliceKey}); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), ip+"/32") {
		t.Errorf("alice enrolling again: %d %s (was %s)", w.Code, w.Body, ip)
	}
	if w := call(t, h, protocol.PathHeartbeat, "alice", protocol.HeartbeatRequest{PublicKey: aliceKey}); w.Code != http.StatusOK {
		t.Errorf("alice's heartbeat: %d", w.Code)
	}
}

// fixed is a registry with a fixed list.
type fixed map[string]wireguard.Peer

func (f fixed) Lookup(key string) (wireguard.Peer, bool) {
	p, ok := f[key]
	return p, ok && time.Now().Before(p.Expires)
}

func (f fixed) allowed(key, sub string) bool {
	p, ok := f.Lookup(key)
	return ok && p.Subject == sub
}

func mustKey(t *testing.T, s string) wireguard.Key {
	t.Helper()
	k, err := wireguard.ParseKey(s)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// With a go-authn provider a valid token is not enough: the key must be one
// its owner registered there, and the lease never outlives the registration.
func TestOnlyARegisteredKeyIsEnrolled(t *testing.T) {
	s, st := newServer(t)
	h := s.Handler()
	until := time.Now().Add(20 * time.Minute).Truncate(time.Second)
	reg := fixed{aliceKey: {Key: mustKey(t, aliceKey), Subject: "sub-alice", Expires: until}}
	s.UsePeers(reg)

	const unregistered = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="
	if w := call(t, h, protocol.PathEnroll, "alice", protocol.EnrollRequest{PublicKey: unregistered}); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "key_not_registered") {
		t.Errorf("a key nobody registered: %d %s", w.Code, w.Body)
	}
	if w := call(t, h, protocol.PathEnroll, "bob", protocol.EnrollRequest{PublicKey: aliceKey}); w.Code != http.StatusForbidden {
		t.Errorf("bob enrolling the key alice registered: %d %s", w.Code, w.Body)
	}
	w := call(t, h, protocol.PathEnroll, "alice", protocol.EnrollRequest{PublicKey: aliceKey})
	if w.Code != http.StatusOK {
		t.Fatalf("alice enrolling her registered key: %d %s", w.Code, w.Body)
	}
	var resp protocol.EnrollResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if !resp.LeaseExpiresAt.Equal(until) {
		t.Errorf("the lease ends %v, want the registration's %v (LEASE_TTL is an hour)", resp.LeaseExpiresAt, until)
	}
	if p := st.Get(aliceKey); p == nil || !p.LeaseExpiry.Equal(until) {
		t.Errorf("the stored lease: %+v", p)
	}

	// The provider takes the key back: a heartbeat is refused, and the next
	// reconciliation drops the peer.
	delete(reg, aliceKey)
	if w := call(t, h, protocol.PathHeartbeat, "alice", protocol.HeartbeatRequest{PublicKey: aliceKey}); w.Code != http.StatusForbidden {
		t.Errorf("a heartbeat for a key taken back: %d", w.Code)
	}
	s.Reconcile(reg.allowed)
	if p := st.Get(aliceKey); p != nil {
		t.Errorf("the peer outlived its key: %+v", p)
	}
	// Its address is free again.
	reg[aliceKey] = wireguard.Peer{Key: mustKey(t, aliceKey), Subject: "sub-alice", Expires: until}
	if w := call(t, h, protocol.PathEnroll, "alice", protocol.EnrollRequest{PublicKey: aliceKey}); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), resp.AssignedIP) {
		t.Errorf("enrolling again: %d %s (the address was %s)", w.Code, w.Body, resp.AssignedIP)
	}
	// A reconciliation that allows everything keeps everything.
	s.Reconcile(func(string, string) bool { return true })
	if st.Get(aliceKey) == nil {
		t.Error("a reconciliation that allowed the peer dropped it")
	}
}
