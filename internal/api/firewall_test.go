package api

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"reflect"
	"testing"

	"github.com/claimward/claimward-vpn-client/pkg/protocol"
	"github.com/claimward/claimward-vpn-server/internal/fw"
	"github.com/claimward/claimward-vpn-server/internal/policy"
	"github.com/claimward/claimward-vpn-server/internal/store"
	"github.com/claimward/claimward-vpn-server/internal/tenant"
)

// recorder is an Applier that keeps what was installed, and can be made to fail.
type recorder struct {
	last  fw.Ruleset
	fail  bool
	calls int
}

func (r *recorder) Apply(rs fw.Ruleset) error {
	r.calls++
	if r.fail {
		return errors.New("netlink: operation not permitted")
	}
	r.last = rs
	return nil
}

func firewallServer(t *testing.T) (*Server, *store.Store, *tenant.Store, *recorder) {
	t.Helper()
	s, st := newServer(t)
	ts := s.tenants
	rules, err := policy.Parse([]byte(`[
		{"cidr":"10.20.0.5/32","proto":"tcp","ports":[445,88]},
		{"cidr":"10.20.0.5/32","proto":"udp","ports":[88]}]`))
	if err != nil {
		t.Fatal(err)
	}
	if err := ts.Seed(tenant.Tenant{ID: tenant.DefaultID, Policy: rules}); err != nil {
		t.Fatal(err)
	}
	rec := &recorder{}
	m := fw.NewManager("wg0", rec, fw.FromStores(ts, st), slog.New(slog.NewTextHandler(io.Discard, nil)))
	s.UseFirewall(m.Sync)
	ts.SetOnChange(func() { _ = m.Sync() })
	return s, st, ts, rec
}

func TestEnrollmentPutsThePeerUnderItsTenantsPolicy(t *testing.T) {
	s, st, _, rec := firewallServer(t)
	w := call(t, s.Handler(), protocol.PathEnroll, "alice", protocol.EnrollRequest{PublicKey: aliceKey})
	if w.Code != http.StatusOK {
		t.Fatalf("enroll: %d %s", w.Code, w.Body)
	}

	// The routes the client is pushed come from the policy.
	var resp protocol.EnrollResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if want := []string{"10.20.0.5/32"}; !reflect.DeepEqual(resp.AllowedIPs, want) {
		t.Fatalf("pushed routes = %v, want %v", resp.AllowedIPs, want)
	}

	// The gateway's ruleset has the peer's /32 in the tenant's set.
	ip, _ := netip.AddrFromSlice(st.Get(aliceKey).IP.To4())
	if len(rec.last.Sets) != 1 || !reflect.DeepEqual(rec.last.Sets[0].Addrs, []netip.Addr{ip}) {
		t.Fatalf("sets = %+v, want only %v", rec.last.Sets, ip)
	}

	// Leaving removes it.
	if w := call(t, s.Handler(), protocol.PathDeregister, "alice", protocol.DeregisterRequest{PublicKey: aliceKey}); w.Code != http.StatusNoContent {
		t.Fatalf("deregister: %d", w.Code)
	}
	if len(rec.last.Sets) != 0 {
		t.Fatalf("a deregistered peer is still in %+v", rec.last.Sets)
	}
}

// ⛔ Fail closed: no ruleset, no peer.
func TestEnrollmentIsRefusedWhenTheFirewallCannotBeInstalled(t *testing.T) {
	s, st, _, rec := firewallServer(t)
	rec.fail = true
	w := call(t, s.Handler(), protocol.PathEnroll, "alice", protocol.EnrollRequest{PublicKey: aliceKey})
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("enroll with a broken firewall: %d %s", w.Code, w.Body)
	}
	if st.Get(aliceKey) != nil {
		t.Fatal("the peer stayed enrolled")
	}
	// And the address went back to the pool.
	rec.fail = false
	if w := call(t, s.Handler(), protocol.PathEnroll, "alice", protocol.EnrollRequest{PublicKey: aliceKey}); w.Code != http.StatusOK {
		t.Fatalf("enroll after recovery: %d %s", w.Code, w.Body)
	}
}

func TestNoFirewallIsNoSync(t *testing.T) {
	s, _ := newServer(t)
	if err := s.syncFirewall(); err != nil {
		t.Fatal(err)
	}
	s.UseFirewall(func() error { return errors.New("x") })
	if err := s.syncFirewall(); err == nil {
		t.Fatal("the failure was hidden")
	}
}

// A tenant's policy changing re-installs the table.
func TestPolicyChangeReinstalls(t *testing.T) {
	s, _, ts, rec := firewallServer(t)
	call(t, s.Handler(), protocol.PathEnroll, "alice", protocol.EnrollRequest{PublicKey: aliceKey})
	before := rec.calls
	narrow, _ := policy.Parse([]byte(`[{"cidr":"10.20.0.5/32","proto":"tcp","ports":[445]}]`))
	if _, err := ts.Update(tenant.DefaultID, tenant.Tenant{Policy: narrow}); err != nil {
		t.Fatal(err)
	}
	if rec.calls != before+1 {
		t.Fatalf("firewall applied %d times after the change, want 1", rec.calls-before)
	}
	for _, c := range rec.last.Chains {
		if c.Name == "t0" && len(c.Rules) != 1 {
			t.Fatalf("tenant chain still has %d rules", len(c.Rules))
		}
	}
	if _, err := ts.Update(tenant.DefaultID, tenant.Tenant{Policy: []policy.Rule{{CIDR: "10.0.0.0/8", Proto: "icmp"}}}); err == nil {
		t.Fatal("an invalid policy was accepted")
	}
}
