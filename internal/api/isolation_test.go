package api

import (
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"testing"

	"github.com/claimward/claimward-vpn-client/pkg/protocol"
	"github.com/claimward/claimward-vpn-server/internal/auth"
	"github.com/claimward/claimward-vpn-server/internal/fw"
)

// permits evaluates a Ruleset the way nftables does for a packet arriving on
// iface from src to dst (any protocol): rules in order, a jump runs the target
// chain and RETURNS when nothing in it decides, the hooked chain's last rule
// is the verdict. Ports are not looked at: this asks only whether the address
// is reachable at all.
func permits(rs fw.Ruleset, hook, iface string, src, dst netip.Addr) bool {
	chains := map[string]fw.Chain{}
	sets := map[string][]netip.Addr{}
	for _, c := range rs.Chains {
		chains[c.Name] = c
	}
	for _, s := range rs.Sets {
		sets[s.Name] = s.Addrs
	}
	inSet := func(name string) bool {
		for _, a := range sets[name] {
			if a == src {
				return true
			}
		}
		return false
	}
	var run func(c fw.Chain) (verdict string, decided bool)
	run = func(c fw.Chain) (string, bool) {
		for _, r := range c.Rules {
			if r.Iface != "" && r.Iface != iface {
				continue
			}
			if r.SrcSet != "" && !inSet(r.SrcSet) {
				continue
			}
			if r.Dst.IsValid() && !r.Dst.Contains(dst) {
				continue
			}
			if r.Jump != "" {
				if v, ok := run(chains[r.Jump]); ok {
					return v, true
				}
				continue
			}
			if r.Final != "" {
				return r.Final, true
			}
		}
		return "", false
	}
	for _, c := range rs.Chains {
		if c.Hook == hook {
			v, _ := run(c)
			return v == fw.Accept
		}
	}
	return false
}

// ⛔ Audit 2026-11-23 (claim 8): the Gateway only ever received (key, ip), so
// nothing on the server stopped a peer from using networks outside its tenant
// (the client's own routes are advice). The gateway's firewall now does: a
// peer of one tenant is accepted only towards that tenant's destinations,
// whatever AllowedIPs it puts in its own WireGuard config, and everything else
// arriving on the wg interface is dropped -- through the real enroll path.
func TestAPeerReachesOnlyItsOwnTenantsNetworks(t *testing.T) {
	s, st, ts := tenantServer(t)
	people["erin"] = &auth.Claims{Subject: "sub-erin", Groups: []string{"chem"}}
	t.Cleanup(func() { delete(people, "erin") })
	rec := &recorder{}
	m := fw.NewManager("wg0", rec, fw.FromStores(ts, st), slog.New(slog.NewTextHandler(io.Discard, nil)))
	s.UseFirewall(m.Sync)
	h := s.Handler()

	dave, erin := newKey(t), newKey(t)
	for who, key := range map[string]string{"dave": dave, "erin": erin} {
		if w := call(t, h, protocol.PathEnroll, who, protocol.EnrollRequest{PublicKey: key}); w.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", who, w.Code, w.Body)
		}
	}
	addr := func(key string) netip.Addr {
		a, _ := netip.AddrFromSlice(st.Get(key).IP.To4())
		return a
	}
	hpcHost := netip.MustParseAddr("10.2.3.4")  // in hpc's 10.2.0.0/16
	chemHost := netip.MustParseAddr("10.1.3.4") // in chem's 10.1.0.0/16
	elsewhere := netip.MustParseAddr("192.168.1.1")

	for _, hook := range []string{fw.HookForward, fw.HookInput} {
		for _, c := range []struct {
			who  string
			src  netip.Addr
			dst  netip.Addr
			want bool
		}{
			{"dave to hpc", addr(dave), hpcHost, true},
			{"dave to chem", addr(dave), chemHost, false},
			{"dave to elsewhere", addr(dave), elsewhere, false},
			{"erin to chem", addr(erin), chemHost, true},
			{"erin to hpc", addr(erin), hpcHost, false},
			// A source the gateway never enrolled is nobody.
			{"stranger to hpc", netip.MustParseAddr("10.80.0.200"), hpcHost, false},
		} {
			if got := permits(rec.last, hook, "wg0", c.src, c.dst); got != c.want {
				t.Errorf("%s, %s: permitted = %v, want %v", hook, c.who, got, c.want)
			}
		}
	}
}
