package fw

import (
	"io"
	"log/slog"
	"reflect"
	"testing"

	"github.com/claimward/claimward-vpn-server/internal/policy"
)

func TestMSSFor(t *testing.T) {
	for _, c := range []struct {
		mtu  int
		v6   bool
		want int
	}{
		{1390, false, 1350},
		{1390, true, 1330},
		{1420, false, 1380},
		{1280, true, 1220},
	} {
		if got := MSSFor(c.mtu, c.v6); got != c.want {
			t.Errorf("MSSFor(%d, v6=%v) = %d, want %d", c.mtu, c.v6, got, c.want)
		}
	}
}

// The clamp covers, for IPv4 and IPv6, SYNs arriving from a peer and SYNs
// leaving to one on the forward hook, and SYNs arriving on the input hook.
func TestWithMSSClampBuildsBothDirections(t *testing.T) {
	rs := WithMSSClamp(Ruleset{Table: TableName}, "wg0", 1390)
	tcp := policy.ProtoTCP
	wantFwd := []Rule{
		{Iface: "wg0", IPv4: true, Proto: tcp, ClampMSS: 1350},
		{OIface: "wg0", IPv4: true, Proto: tcp, ClampMSS: 1350},
		{Iface: "wg0", IPv6: true, Proto: tcp, ClampMSS: 1330},
		{OIface: "wg0", IPv6: true, Proto: tcp, ClampMSS: 1330},
	}
	wantIn := []Rule{
		{Iface: "wg0", IPv4: true, Proto: tcp, ClampMSS: 1350},
		{Iface: "wg0", IPv6: true, Proto: tcp, ClampMSS: 1330},
	}
	f, ok := chain(rs, mssChainForward)
	if !ok || f.Hook != HookForward || !f.Mangle {
		t.Fatalf("forward clamp chain = %+v (found %v)", f, ok)
	}
	i, ok := chain(rs, mssChainInput)
	if !ok || i.Hook != HookInput || !i.Mangle {
		t.Fatalf("input clamp chain = %+v (found %v)", i, ok)
	}
	if !reflect.DeepEqual(sortedByFamily(f.Rules), sortedByFamily(wantFwd)) {
		t.Errorf("forward rules = %+v", f.Rules)
	}
	if !reflect.DeepEqual(sortedByFamily(i.Rules), sortedByFamily(wantIn)) {
		t.Errorf("input rules = %+v", i.Rules)
	}
	for _, r := range append(f.Rules, i.Rules...) {
		if r.Final != "" || r.Jump != "" {
			t.Errorf("clamp rule %+v ends in a verdict", r)
		}
	}
}

// sortedByFamily orders rules by (IPv6, OIface) so the comparison does not
// depend on construction order.
func sortedByFamily(in []Rule) []Rule {
	out := append([]Rule(nil), in...)
	key := func(r Rule) int {
		k := 0
		if r.IPv6 {
			k += 2
		}
		if r.OIface != "" {
			k++
		}
		return k
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && key(out[j]) < key(out[j-1]); j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// An MTU below IPv6's minimum is never advertised, so it clamps nothing.
func TestWithMSSClampBelowTheFloorAddsNothing(t *testing.T) {
	base := Ruleset{Table: TableName}
	for _, mtu := range []int{0, -1, 1279} {
		if got := WithMSSClamp(base, "wg0", mtu); !reflect.DeepEqual(got, base) {
			t.Errorf("mtu %d changed the ruleset: %+v", mtu, got)
		}
	}
	if got := WithMSSClamp(base, "wg0", 1280); len(got.Chains) != 2 {
		t.Errorf("mtu 1280 gave %d chains, want 2", len(got.Chains))
	}
}

// The clamp is part of every ruleset the Manager installs, the deny-all
// fallback included, and the policy chains are untouched by it.
func TestManagerClampsEveryRuleset(t *testing.T) {
	ap := &failing{failOn: 1}
	m := NewManager("wg0", ap, func() []Tenant {
		return []Tenant{{ID: "a", Peers: addrs("10.80.0.2")}}
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	m.ClampMSS(1390)
	if err := m.Sync(); err == nil {
		t.Fatal("Sync hid the failure")
	}
	if len(ap.applied) != 2 {
		t.Fatalf("applied %d rulesets", len(ap.applied))
	}
	for n, rs := range ap.applied {
		if _, ok := chain(rs, mssChainForward); !ok {
			t.Errorf("ruleset %d has no forward clamp", n)
		}
		if _, ok := chain(rs, mssChainInput); !ok {
			t.Errorf("ruleset %d has no input clamp", n)
		}
	}
	if want := WithMSSClamp(Build("wg0", nil), "wg0", 1390); !reflect.DeepEqual(ap.applied[1], want) {
		t.Fatalf("fallback = %+v", ap.applied[1])
	}
	// Without an MTU the ruleset is exactly the policy's.
	ap2 := &failing{}
	m2 := NewManager("wg0", ap2, func() []Tenant { return nil }, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := m2.Sync(); err != nil || !reflect.DeepEqual(ap2.applied[0], Build("wg0", nil)) {
		t.Fatalf("err=%v applied=%+v", err, ap2.applied)
	}
}
