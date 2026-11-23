package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/claimward/claimward-vpn-client/pkg/protocol"
)

// The enroll response carries the tunnel MTU the gateway runs at, as the
// integer `mtu` (omitted when none is configured, which clients read as their
// default).
func TestEnrollResponseCarriesTheTunnelMTU(t *testing.T) {
	for _, mtu := range []int{0, 1390} {
		s, _ := newServer(t)
		s.cfg.TunnelMTU = mtu
		w := call(t, s.Handler(), protocol.PathEnroll, "alice", protocol.EnrollRequest{PublicKey: aliceKey})
		if w.Code != http.StatusOK {
			t.Fatalf("enroll: %d %s", w.Code, w.Body)
		}
		var resp protocol.EnrollResponse
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		if resp.MTU != mtu {
			t.Errorf("TunnelMTU %d: response mtu = %d", mtu, resp.MTU)
		}
		if got := strings.Contains(w.Body.String(), `"mtu":1390`); got != (mtu == 1390) {
			t.Errorf("TunnelMTU %d: body %s", mtu, w.Body)
		}
	}
}
