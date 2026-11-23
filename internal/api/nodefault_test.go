package api

import (
	"net/http"
	"testing"

	"github.com/claimward/claimward-vpn-client/pkg/protocol"
	"github.com/claimward/claimward-vpn-server/internal/tenant"
)

// ⛔ A tenant deleted between the membership check and the route lookup is an
// error: the routes of the default tenant are not served in its place.
func TestEnrollRefusesATenantDeletedUnderIt(t *testing.T) {
	s, st := newServer(t)
	if _, err := s.tenants.Create(tenant.Tenant{ID: "lab", Domains: []string{"example.org"}, AllowedIPs: []string{"10.2.0.0/16"}}); err != nil {
		t.Fatal(err)
	}
	s.afterChoose = func() { _ = s.tenants.Delete("lab") }
	w := call(t, s.Handler(), protocol.PathEnroll, "alice", protocol.EnrollRequest{PublicKey: aliceKey, Tenant: "lab"})
	if w.Code != http.StatusForbidden {
		t.Errorf("enroll into a vanished tenant: %d %s", w.Code, w.Body)
	}
	if st.Get(aliceKey) != nil {
		t.Error("a device was enrolled into a vanished tenant")
	}
}

// ⛔ Frank is authenticated but matches no tenant. He used to be put in the
// default one; he is now refused, on the tenant list and on enrollment.
func TestAPersonMatchingNoTenantGets403(t *testing.T) {
	s, st := newServer(t)
	h := s.Handler()
	if w := get(t, h, protocol.PathTenants, "frank"); w.Code != http.StatusForbidden {
		t.Errorf("tenants: %d %s", w.Code, w.Body)
	}
	for _, asked := range []string{"", "default"} {
		w := call(t, h, protocol.PathEnroll, "frank", protocol.EnrollRequest{PublicKey: aliceKey, Tenant: asked})
		if w.Code != http.StatusForbidden {
			t.Errorf("enroll (tenant %q): %d %s", asked, w.Code, w.Body)
		}
	}
	if st.Get(aliceKey) != nil {
		t.Error("a person matching no tenant was enrolled")
	}
}
