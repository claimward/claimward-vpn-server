package fw

import (
	"net/netip"
	"reflect"
	"testing"

	"github.com/claimward/claimward-vpn-server/internal/policy"
)

func addrs(s ...string) []netip.Addr {
	var out []netip.Addr
	for _, x := range s {
		out = append(out, netip.MustParseAddr(x))
	}
	return out
}

func rules(t *testing.T, js string) []policy.Rule {
	t.Helper()
	r, err := policy.Parse([]byte(js))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func chain(rs Ruleset, name string) (Chain, bool) {
	for _, c := range rs.Chains {
		if c.Name == name {
			return c, true
		}
	}
	return Chain{}, false
}

// The mesocentre case: the file server on tcp/445 and Kerberos on tcp+udp/88.
func TestBuildMesocentre(t *testing.T) {
	ten := Tenant{
		ID:    "meso",
		Peers: addrs("10.80.0.3", "10.80.0.2", "10.80.0.3"),
		Rules: rules(t, `[
			{"cidr":"10.20.0.5/32","proto":"tcp","ports":[445,88]},
			{"cidr":"10.20.0.5/32","proto":"udp","ports":[88]}]`),
	}
	rs := Build("wg0", []Tenant{ten})

	if len(rs.Sets) != 1 || !reflect.DeepEqual(rs.Sets[0].Addrs, addrs("10.80.0.2", "10.80.0.3")) {
		t.Fatalf("sets = %+v (want the two peers, sorted, once each)", rs.Sets)
	}
	tc, ok := chain(rs, "t0")
	if !ok {
		t.Fatal("no tenant chain")
	}
	dst := netip.MustParsePrefix("10.20.0.5/32")
	want := []Rule{
		{Dst: dst, Proto: "tcp", Ports: []policy.Port{{Lo: 445, Hi: 445}}, Final: Accept},
		{Dst: dst, Proto: "tcp", Ports: []policy.Port{{Lo: 88, Hi: 88}}, Final: Accept},
		{Dst: dst, Proto: "udp", Ports: []policy.Port{{Lo: 88, Hi: 88}}, Final: Accept},
	}
	if !reflect.DeepEqual(tc.Rules, want) {
		t.Fatalf("tenant chain = %+v\nwant %+v", tc.Rules, want)
	}

	// Both forward AND input: a peer aiming at the gateway host is judged too.
	for _, hook := range []string{HookForward, HookInput} {
		c, ok := chain(rs, hook)
		if !ok || c.Hook != hook {
			t.Fatalf("no %s base chain", hook)
		}
		wantRules := []Rule{
			{Iface: "wg0", IPv4: true, SrcSet: "t0_src", Jump: "t0"},
			{Iface: "wg0", Final: Drop},
		}
		if !reflect.DeepEqual(c.Rules, wantRules) {
			t.Fatalf("%s = %+v", hook, c.Rules)
		}
	}
}

// Regular chains come before the base chains that jump to them.
func TestBuildJumpTargetsFirst(t *testing.T) {
	rs := Build("wg0", []Tenant{{ID: "a", Peers: addrs("10.80.0.2")}, {ID: "b", Peers: addrs("10.80.0.3")}})
	seen := map[string]bool{}
	for _, c := range rs.Chains {
		for _, r := range c.Rules {
			if r.Jump != "" && !seen[r.Jump] {
				t.Fatalf("chain %s jumps to %s before it is defined", c.Name, r.Jump)
			}
		}
		seen[c.Name] = true
	}
}

// No tenant, no peers: still default deny on the interface.
func TestBuildDenyAll(t *testing.T) {
	for _, in := range [][]Tenant{nil, {{ID: "empty", Rules: rules(t, `[{"cidr":"10.0.0.0/8","proto":"tcp","ports":[1]}]`)}}} {
		rs := Build("wg0", in)
		if len(rs.Sets) != 0 {
			t.Fatalf("sets = %+v", rs.Sets)
		}
		for _, hook := range []string{HookForward, HookInput} {
			c, _ := chain(rs, hook)
			if !reflect.DeepEqual(c.Rules, []Rule{{Iface: "wg0", Final: Drop}}) {
				t.Fatalf("%s = %+v", hook, c.Rules)
			}
		}
	}
}

// A tenant with a peer and no rules reaches nothing; legacy routes reach all
// protocols; IPv6 and malformed rules enforce nothing (deny, never allow).
func TestBuildLegacyAndUnenforceable(t *testing.T) {
	rs := Build("wg0", []Tenant{{
		ID: "x", Peers: addrs("10.80.0.2"),
		Rules: append(policy.Legacy([]string{"10.1.0.0/16", "fd00::/8", "nonsense"}),
			policy.Rule{CIDR: "10.2.0.0/24", Proto: "icmp"},
			policy.Rule{CIDR: "10.3.0.0/24", Proto: "tcp", Ports: []policy.Port{{Lo: 0, Hi: 5}}}),
	}})
	c, _ := chain(rs, "t0")
	want := []Rule{{Dst: netip.MustParsePrefix("10.1.0.0/16"), Final: Accept}}
	if !reflect.DeepEqual(c.Rules, want) {
		t.Fatalf("got %+v", c.Rules)
	}
}

func TestBuildMasksAndIgnoresV6Peers(t *testing.T) {
	rs := Build("wg0", []Tenant{{
		ID: "x", Peers: addrs("fd00::1", "10.80.0.9"),
		Rules: []policy.Rule{{CIDR: "10.1.2.3/24", Proto: "udp", Ports: []policy.Port{{Lo: 53, Hi: 53}}}},
	}})
	if !reflect.DeepEqual(rs.Sets[0].Addrs, addrs("10.80.0.9")) {
		t.Fatalf("sets = %+v", rs.Sets)
	}
	c, _ := chain(rs, "t0")
	if c.Rules[0].Dst != netip.MustParsePrefix("10.1.2.0/24") {
		t.Fatalf("not masked: %v", c.Rules[0].Dst)
	}
}

func TestBuildDeterministic(t *testing.T) {
	a := []Tenant{{ID: "b", Peers: addrs("10.80.0.3")}, {ID: "a", Peers: addrs("10.80.0.2")}}
	b := []Tenant{a[1], a[0]}
	if !reflect.DeepEqual(Build("wg0", a), Build("wg0", b)) {
		t.Fatal("tenant order changes the ruleset")
	}
}
