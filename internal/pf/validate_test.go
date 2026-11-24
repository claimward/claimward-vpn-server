package pf

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/claimward/claimward-vpn-server/internal/fw"
	"github.com/claimward/claimward-vpn-server/internal/policy"
)

func goodPass() Spec {
	return Spec{Action: Pass, Quick: true, Iface: "wg0", AF: 4, Proto: protoTCP, SynOnly: true,
		SrcTable: "tbl", Dst: netip.MustParsePrefix("10.1.0.0/16"), PortLo: 80, PortHi: 90}
}

func goodMatch() Spec {
	return Spec{Action: Match, Iface: "wg0", AF: 6, Proto: protoTCP, MaxMSS: 1300}
}

func TestValidateEachDefect(t *testing.T) {
	tables := []Table{{Name: "tbl"}}
	mut := func(f func(*Spec)) Spec { s := goodPass(); f(&s); return s }
	mutM := func(f func(*Spec)) Spec { s := goodMatch(); f(&s); return s }
	cases := map[string]Spec{
		"not quick":         mut(func(s *Spec) { s.Quick = false }),
		"mss on pass":       mut(func(s *Spec) { s.MaxMSS = 1 }),
		"quick match":       mutM(func(s *Spec) { s.Quick = true }),
		"match without mss": mutM(func(s *Spec) { s.MaxMSS = 0 }),
		"match udp":         mutM(func(s *Spec) { s.Proto = protoUDP }),
		"match with table":  mutM(func(s *Spec) { s.SrcTable = "tbl" }),
		"match with dst":    mutM(func(s *Spec) { s.Dst = netip.MustParsePrefix("10.0.0.0/8") }),
		"unknown action":    mut(func(s *Spec) { s.Action = 9 }),
		"empty iface":       mut(func(s *Spec) { s.Iface = "" }),
		"long iface":        mut(func(s *Spec) { s.Iface = strings.Repeat("a", 16) }),
		"iface with space":  mut(func(s *Spec) { s.Iface = "wg 0" }),
		"family 5":          mut(func(s *Spec) { s.AF = 5 }),
		"protocol 1":        mut(func(s *Spec) { s.Proto, s.SynOnly, s.PortLo, s.PortHi = 1, false, 0, 0 }),
		"undefined table":   mut(func(s *Spec) { s.SrcTable = "nope" }),
		"table with inet6":  mut(func(s *Spec) { s.AF = 6; s.Dst = netip.Prefix{} }),
		"table with any af": mut(func(s *Spec) { s.AF = 0; s.Dst = netip.Prefix{} }),
		"ipv6 dst":          mut(func(s *Spec) { s.Dst = netip.MustParsePrefix("fd00::/8") }),
		"unmasked dst":      mut(func(s *Spec) { s.Dst = netip.MustParsePrefix("10.1.2.3/16") }),
		"dst with any af":   mut(func(s *Spec) { s.AF = 0; s.SrcTable = "" }),
		"ports w/o proto":   mut(func(s *Spec) { s.Proto = 0; s.SynOnly = false }),
		"port 0":            mut(func(s *Spec) { s.PortLo = 0 }),
		"reversed ports":    mut(func(s *Spec) { s.PortLo, s.PortHi = 9, 3 }),
		"syn-only udp":      mut(func(s *Spec) { s.Proto = protoUDP }),
	}
	for name, s := range cases {
		t.Run(name, func(t *testing.T) {
			if err := (Plan{Tables: tables, Rules: []Spec{s}}).Validate(); err == nil {
				t.Fatalf("%+v accepted", s)
			}
		})
	}
	// The controls: the good specs are accepted, with the neighbours of each
	// defect above (a single port, udp without SYN, no ports at all).
	ok := []Spec{goodPass(), goodMatch(),
		mut(func(s *Spec) { s.PortLo, s.PortHi = 80, 80 }),
		mut(func(s *Spec) { s.Proto, s.SynOnly = protoUDP, false }),
		mut(func(s *Spec) { s.Proto, s.SynOnly, s.PortLo, s.PortHi = 0, false, 0, 0 }),
		{Action: Block, Quick: true, Iface: "wg0"},
	}
	for i, s := range ok {
		if err := (Plan{Tables: tables, Rules: []Spec{s}}).Validate(); err != nil {
			t.Errorf("good spec %d: %v", i, err)
		}
	}
}

func TestValidateTablesAndCounts(t *testing.T) {
	for _, n := range []string{"", strings.Repeat("a", 32), "a b", "a-b", "a;b"} {
		if err := (Plan{Tables: []Table{{Name: n}}}).Validate(); err == nil {
			t.Errorf("table name %q accepted", n)
		}
	}
	if err := (Plan{Tables: []Table{{Name: strings.Repeat("a", 31)}}}).Validate(); err != nil {
		t.Errorf("31-byte name refused: %v", err)
	}
	blocks := make([]Spec, MaxRules+1)
	for i := range blocks {
		blocks[i] = Spec{Action: Block, Quick: true, Iface: "wg0"}
	}
	if err := (Plan{Rules: blocks}).Validate(); err == nil {
		t.Error("MaxRules+1 rules accepted")
	}
	if err := (Plan{Rules: blocks[:MaxRules]}).Validate(); err != nil {
		t.Errorf("MaxRules rules refused: %v", err)
	}
	tabs := make([]Table, MaxTables+1)
	for i := range tabs {
		tabs[i].Name = "t" + itoa(i)
	}
	if err := (Plan{Tables: tabs}).Validate(); err == nil {
		t.Error("MaxTables+1 tables accepted")
	}
	if err := (Plan{Tables: tabs[:MaxTables]}).Validate(); err != nil {
		t.Errorf("MaxTables tables refused: %v", err)
	}
}

func okRuleset() fw.Ruleset {
	drop := fw.Rule{Iface: "wg0", Final: fw.Drop}
	jump := fw.Rule{Iface: "wg0", IPv4: true, SrcSet: "t0_src", Jump: "t0"}
	accept := fw.Rule{Dst: netip.MustParsePrefix("10.1.0.0/16"), Proto: policy.ProtoTCP, Ports: []policy.Port{{Lo: 1, Hi: 2}}, Final: fw.Accept}
	return fw.Ruleset{
		Sets: []fw.Set{{Name: "t0_src", Addrs: []netip.Addr{netip.MustParseAddr("10.0.0.2")}}},
		Chains: []fw.Chain{
			{Name: "t0", Rules: []fw.Rule{accept}},
			{Name: "forward", Hook: "forward", Rules: []fw.Rule{jump, drop}},
		},
	}
}

func TestOKRulesetIsAccepted(t *testing.T) {
	if _, err := NewPlan(okRuleset(), 1); err != nil {
		t.Fatal(err)
	}
}

func TestNewPlanRefusals(t *testing.T) {
	setTenant := func(f func(*fw.Rule)) func(*fw.Ruleset) {
		return func(rs *fw.Ruleset) { f(&rs.Chains[0].Rules[0]) }
	}
	setJump := func(f func(*fw.Rule)) func(*fw.Ruleset) {
		return func(rs *fw.Ruleset) { f(&rs.Chains[1].Rules[0]) }
	}
	cases := map[string]struct {
		mutate func(*fw.Ruleset)
		want   string
	}{
		"duplicate set": {func(rs *fw.Ruleset) { rs.Sets = append(rs.Sets, rs.Sets[0]) }, "twice"},
		"long table name": {func(rs *fw.Ruleset) {
			rs.Sets[0].Name = strings.Repeat("a", 30)
			rs.Chains[1].Rules[0].SrcSet = rs.Sets[0].Name
		}, "table name"},
		"unspecified addr": {func(rs *fw.Ruleset) { rs.Sets[0].Addrs = []netip.Addr{netip.IPv4Unspecified()} }, "host address"},
		"too many addrs": {func(rs *fw.Ruleset) {
			a := make([]netip.Addr, MaxAddrs+1)
			for i := range a {
				a[i] = netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
			}
			rs.Sets[0].Addrs = a
		}, "addresses exceed"},
		"too many tables": {func(rs *fw.Ruleset) {
			for i := 0; i < MaxTables; i++ {
				rs.Sets = append(rs.Sets, fw.Set{Name: "s" + itoa(i)})
			}
		}, "tables exceed"},
		"too many rules": {func(rs *fw.Ruleset) {
			r := rs.Chains[0].Rules[0]
			rs.Chains[0].Rules = make([]fw.Rule, MaxRules)
			for i := range rs.Chains[0].Rules {
				rs.Chains[0].Rules[i] = r
			}
		}, "rules exceed"},
		"mss out of range": {func(rs *fw.Ruleset) {
			rs.Chains = append(rs.Chains, fw.Chain{Name: "m", Hook: "forward", Mangle: true,
				Rules: []fw.Rule{{Iface: "wg0", IPv4: true, Proto: policy.ProtoTCP, ClampMSS: 70000}}})
		}, "MSS"},
		"malformed mangle rule": {func(rs *fw.Ruleset) {
			rs.Chains = append(rs.Chains, fw.Chain{Name: "m", Hook: "forward", Mangle: true,
				Rules: []fw.Rule{{Iface: "wg0", IPv4: true, Proto: policy.ProtoTCP, ClampMSS: 1300, Final: fw.Accept}}})
		}, "MSS clamp"},
		"rule after final": {func(rs *fw.Ruleset) {
			r := rs.Chains[1].Rules
			rs.Chains[1].Rules = append(r, r[0])
		}, "follows the final"},
		"jump without set":      {setJump(func(r *fw.Rule) { r.SrcSet = "" }), "jump"},
		"jump not ipv4":         {setJump(func(r *fw.Rule) { r.IPv4 = false }), "jump"},
		"jump without iface":    {setJump(func(r *fw.Rule) { r.Iface = "" }), "jump"},
		"jump from unknown set": {setJump(func(r *fw.Rule) { r.SrcSet = "zz" }), "unknown set"},
		"jump to unknown chain": {setJump(func(r *fw.Rule) { r.Jump = "zz" }), "unknown chain"},
		"tenant drop":           {setTenant(func(r *fw.Rule) { r.Final = fw.Drop }), "accept"},
		"tenant no dst":         {setTenant(func(r *fw.Rule) { r.Dst = netip.Prefix{} }), "accept"},
		"tenant with src set":   {setTenant(func(r *fw.Rule) { r.SrcSet = "x" }), "accept"},
		"tenant ipv6":           {setTenant(func(r *fw.Rule) { r.IPv6 = true }), "accept"},
		"tenant with mss":       {setTenant(func(r *fw.Rule) { r.ClampMSS = 1 }), "accept"},
		"ports without proto":   {setTenant(func(r *fw.Rule) { r.Proto = "" }), "without a protocol"},
		"two port ranges": {setTenant(func(r *fw.Rule) {
			r.Ports = []policy.Port{{Lo: 1, Hi: 1}, {Lo: 2, Hi: 2}}
		}), "exactly one"},
		"no port range":    {setTenant(func(r *fw.Rule) { r.Ports = nil }), "exactly one"},
		"unknown protocol": {setTenant(func(r *fw.Rule) { r.Proto = "icmp" }), "unknown protocol"},
		"no hooked chain":  {func(rs *fw.Ruleset) { rs.Chains = rs.Chains[:1] }, "no policy chain"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			rs := okRuleset()
			c.mutate(&rs)
			_, err := NewPlan(rs, 1)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want one containing %q", err, c.want)
			}
		})
	}
}
