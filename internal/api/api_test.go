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
