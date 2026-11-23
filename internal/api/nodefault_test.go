package api

import (
	"net/http"
	"testing"

	"github.com/claimward/claimward-vpn-client/pkg/protocol"
)

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
