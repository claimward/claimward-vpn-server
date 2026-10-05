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

// tenantServer is a server with three tenants, and people in zero, one or
// two of them.
func tenantServer(t *testing.T) (*Server, *store.Store, *tenant.Store) {
	t.Helper()
	s, st := newServer(t)
	for _, in := range []tenant.Tenant{
		{ID: "chem", Name: "Chemistry", Groups: []string{"chem"}, AllowedIPs: []string{"10.1.0.0/16"}},
		{ID: "hpc", Name: "HPC", Groups: []string{"hpc"}, AllowedIPs: []string{"10.2.0.0/16"}},
	} {
		if _, err := s.tenants.Create(in); err != nil {
			t.Fatal(err)
		}
	}
	people["carol"] = &auth.Claims{Subject: "sub-carol", Groups: []string{"chem", "hpc"}}
	people["dave"] = &auth.Claims{Subject: "sub-dave", Groups: []string{"hpc"}}
	t.Cleanup(func() { delete(people, "carol"); delete(people, "dave") })
	return s, st, s.tenants
}

func get(t *testing.T, h http.Handler, path, bearer string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, path, nil)
	r.Header.Set("Authorization", "Bearer "+bearer)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// A person in several tenants is offered them, must choose, and gets the
// routes of the one chosen; a person in one is connected to it without
// asking.
func TestAPersonInSeveralTenantsChooses(t *testing.T) {
	s, st, _ := tenantServer(t)
	h := s.Handler()
	w := get(t, h, protocol.PathTenants, "carol")
	var offered []protocol.TenantInfo
	json.Unmarshal(w.Body.Bytes(), &offered)
	if w.Code != http.StatusOK || len(offered) != 2 || offered[0].ID != "chem" || offered[1].Name != "HPC" {
		t.Fatalf("carol is offered %d %v", w.Code, offered)
	}
	if w := call(t, h, protocol.PathEnroll, "carol", protocol.EnrollRequest{PublicKey: aliceKey}); w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "tenant_required") {
		t.Errorf("carol choosing nothing: %d %s", w.Code, w.Body)
	}
	if w := call(t, h, protocol.PathEnroll, "carol", protocol.EnrollRequest{PublicKey: aliceKey, Tenant: "default"}); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "not_a_member") {
		t.Errorf("carol choosing a tenant not theirs: %d %s", w.Code, w.Body)
	}
	w = call(t, h, protocol.PathEnroll, "carol", protocol.EnrollRequest{PublicKey: aliceKey, Tenant: "hpc"})
	var resp protocol.EnrollResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if w.Code != http.StatusOK || len(resp.AllowedIPs) != 1 || resp.AllowedIPs[0] != "10.2.0.0/16" {
		t.Fatalf("carol choosing hpc: %d %s", w.Code, w.Body)
	}
	if p := st.Get(aliceKey); p == nil || p.Tenant != "hpc" {
		t.Errorf("the peer records %+v", p)
	}
	// A new session may choose the other one.
	w = call(t, h, protocol.PathEnroll, "carol", protocol.EnrollRequest{PublicKey: aliceKey, Tenant: "chem"})
	json.Unmarshal(w.Body.Bytes(), &resp)
	if w.Code != http.StatusOK || resp.AllowedIPs[0] != "10.1.0.0/16" || st.Get(aliceKey).Tenant != "chem" {
		t.Errorf("carol switching to chem: %d %s", w.Code, w.Body)
	}

	// Dave is in one: no choice to make.
	const daveKey = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="
	if w := call(t, h, protocol.PathEnroll, "dave", protocol.EnrollRequest{PublicKey: daveKey}); w.Code != http.StatusOK || st.Get(daveKey).Tenant != "hpc" {
		t.Errorf("dave: %d %s", w.Code, w.Body)
	}
	// Alice matches none: the default tenant, as before tenants were many.
	if w := get(t, h, protocol.PathTenants, "alice"); !strings.Contains(w.Body.String(), `"default"`) {
		t.Errorf("alice is offered %s", w.Body)
	}
}

// Taken off a tenant, a person's heartbeat in it is refused.
func TestLeavingATenantEndsTheLeaseThere(t *testing.T) {
	s, _, ts := tenantServer(t)
	h := s.Handler()
	if w := call(t, h, protocol.PathEnroll, "carol", protocol.EnrollRequest{PublicKey: aliceKey, Tenant: "hpc"}); w.Code != http.StatusOK {
		t.Fatal(w.Body)
	}
	if w := call(t, h, protocol.PathHeartbeat, "carol", protocol.HeartbeatRequest{PublicKey: aliceKey}); w.Code != http.StatusOK {
		t.Fatalf("heartbeat while a member: %d", w.Code)
	}
	if _, err := ts.Update("hpc", tenant.Tenant{Name: "HPC", Groups: []string{"someone-else"}, AllowedIPs: []string{"10.2.0.0/16"}}); err != nil {
		t.Fatal(err)
	}
	if w := call(t, h, protocol.PathHeartbeat, "carol", protocol.HeartbeatRequest{PublicKey: aliceKey}); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "not_a_member") {
		t.Errorf("heartbeat after leaving the tenant: %d %s", w.Code, w.Body)
	}
}
