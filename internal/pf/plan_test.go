package pf

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/claimward/claimward-vpn-server/internal/fw"
	"github.com/claimward/claimward-vpn-server/internal/policy"
)

func sampleRuleset(t *testing.T, mtu int) fw.Ruleset {
	t.Helper()
	rs := fw.Build("wg0", []fw.Tenant{
		{ID: "a", Peers: []netip.Addr{netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("10.0.0.3")}, Rules: []policy.Rule{
			{CIDR: "192.168.1.0/24", Proto: policy.ProtoTCP, Ports: []policy.Port{{Lo: 443, Hi: 443}, {Lo: 8000, Hi: 8010}}},
			{CIDR: "192.168.2.5/32", Proto: policy.ProtoUDP, Ports: []policy.Port{{Lo: 53, Hi: 53}}},
			{CIDR: "10.9.0.0/16", Proto: policy.ProtoAny},
		}},
		{ID: "b", Peers: []netip.Addr{netip.MustParseAddr("10.0.0.4")}, Rules: []policy.Rule{
			{CIDR: "192.168.9.0/24", Proto: policy.ProtoTCP, Ports: []policy.Port{{Lo: 22, Hi: 22}}},
		}},
	})
	if mtu > 0 {
		rs = fw.WithMSSClamp(rs, "wg0", mtu)
	}
	return rs
}

func TestPlanShape(t *testing.T) {
	p, err := NewPlan(sampleRuleset(t, 1390), 0xdeadbeef)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Tables) != 2 || p.Tables[0].Name != "t0_src_gdeadbeef" || len(p.Tables[0].Addrs) != 2 {
		t.Fatalf("tables = %+v", p.Tables)
	}
	want := []Spec{
		{Action: Match, Iface: "wg0", AF: 4, Proto: protoTCP, MaxMSS: 1350},
		{Action: Match, Iface: "wg0", AF: 6, Proto: protoTCP, MaxMSS: 1330},
		{Action: Pass, Quick: true, Iface: "wg0", AF: 4, Proto: protoTCP, SynOnly: true, SrcTable: "t0_src_gdeadbeef", Dst: netip.MustParsePrefix("192.168.1.0/24"), PortLo: 443, PortHi: 443},
		{Action: Pass, Quick: true, Iface: "wg0", AF: 4, Proto: protoTCP, SynOnly: true, SrcTable: "t0_src_gdeadbeef", Dst: netip.MustParsePrefix("192.168.1.0/24"), PortLo: 8000, PortHi: 8010},
		{Action: Pass, Quick: true, Iface: "wg0", AF: 4, Proto: protoUDP, SrcTable: "t0_src_gdeadbeef", Dst: netip.MustParsePrefix("192.168.2.5/32"), PortLo: 53, PortHi: 53},
		{Action: Pass, Quick: true, Iface: "wg0", AF: 4, SrcTable: "t0_src_gdeadbeef", Dst: netip.MustParsePrefix("10.9.0.0/16")},
		{Action: Pass, Quick: true, Iface: "wg0", AF: 4, Proto: protoTCP, SynOnly: true, SrcTable: "t1_src_gdeadbeef", Dst: netip.MustParsePrefix("192.168.9.0/24"), PortLo: 22, PortHi: 22},
		{Action: Block, Quick: true, Iface: "wg0"},
	}
	if len(p.Rules) != len(want) {
		t.Fatalf("%d rules, want %d: %+v", len(p.Rules), len(want), p.Rules)
	}
	for i := range want {
		if p.Rules[i] != want[i] {
			t.Errorf("rule %d = %+v\nwant     %+v", i, p.Rules[i], want[i])
		}
	}
}

// Without MSS clamping there are no match rules; the policy still ends in a
// drop, and IPv6 is only ever dropped (the final block has no family).
func TestPlanWithoutMSS(t *testing.T) {
	p, err := NewPlan(sampleRuleset(t, 0), 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.Rules[0].Action == Match {
		t.Fatal("a match rule without MSS clamping")
	}
	last := p.Rules[len(p.Rules)-1]
	if last.Action != Block || last.AF != 0 || !last.Quick {
		t.Fatalf("last rule = %+v", last)
	}
}

// Two loads never share a table name, so a rule of one load cannot read the
// table of another.
func TestGenerationSeparatesLoads(t *testing.T) {
	a, _ := NewPlan(sampleRuleset(t, 0), 1)
	b, _ := NewPlan(sampleRuleset(t, 0), 2)
	for _, ta := range a.Tables {
		for _, tb := range b.Tables {
			if ta.Name == tb.Name {
				t.Fatalf("table %s in both generations", ta.Name)
			}
		}
	}
}

func TestPlanRefusesWhatPFCannotSay(t *testing.T) {
	cases := map[string]func(*fw.Ruleset){
		"no final drop": func(rs *fw.Ruleset) {
			for i, c := range rs.Chains {
				if c.Hook != "" && !c.Mangle {
					rs.Chains[i].Rules = c.Rules[:len(c.Rules)-1]
				}
			}
		},
		"input differs from forward": func(rs *fw.Ruleset) {
			for i, c := range rs.Chains {
				if c.Name == fw.HookInput {
					rs.Chains[i].Rules = []fw.Rule{{Iface: "wg0", Final: fw.Drop}}
				}
			}
		},
		"ipv6 set member": func(rs *fw.Ruleset) {
			rs.Sets[0].Addrs = []netip.Addr{netip.MustParseAddr("fd00::1")}
		},
		"unknown chain": func(rs *fw.Ruleset) {
			rs.Chains = rs.Chains[len(rs.Chains)-2:]
		},
		"bad interface": func(rs *fw.Ruleset) {
			for i := range rs.Chains {
				for j := range rs.Chains[i].Rules {
					rs.Chains[i].Rules[j].Iface = "wg0; pass all"
				}
			}
		},
		"unmasked prefix": func(rs *fw.Ruleset) {
			for i := range rs.Chains {
				for j := range rs.Chains[i].Rules {
					if rs.Chains[i].Rules[j].Dst.IsValid() {
						rs.Chains[i].Rules[j].Dst = netip.MustParsePrefix("192.168.1.7/24")
					}
				}
			}
		},
		"port range reversed": func(rs *fw.Ruleset) {
			for i := range rs.Chains {
				for j := range rs.Chains[i].Rules {
					if len(rs.Chains[i].Rules[j].Ports) == 1 {
						rs.Chains[i].Rules[j].Ports = []policy.Port{{Lo: 9, Hi: 3}}
					}
				}
			}
		},
		"accept at the hook": func(rs *fw.Ruleset) {
			for i, c := range rs.Chains {
				if c.Hook != "" && !c.Mangle {
					rs.Chains[i].Rules = append([]fw.Rule{{Iface: "wg0", Final: fw.Accept}}, c.Rules...)
				}
			}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			rs := sampleRuleset(t, 1390)
			// Deep enough copy: Build returns fresh slices each call.
			mutate(&rs)
			if _, err := NewPlan(rs, 1); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestBounds(t *testing.T) {
	var rs fw.Ruleset
	rs.Table = fw.TableName
	for i := 0; i <= MaxTables; i++ {
		rs.Sets = append(rs.Sets, fw.Set{Name: "t" + strings.Repeat("x", 1) + string(rune('a'+i%26)) + itoa(i), Addrs: []netip.Addr{netip.MustParseAddr("10.0.0.1")}})
	}
	rs.Chains = []fw.Chain{{Name: fw.HookForward, Hook: fw.HookForward, Rules: []fw.Rule{{Iface: "wg0", Final: fw.Drop}}}}
	if _, err := NewPlan(rs, 1); err == nil || !strings.Contains(err.Error(), "tables") {
		t.Fatalf("too many tables: %v", err)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for ; i > 0; i /= 10 {
		b = append([]byte{byte('0' + i%10)}, b...)
	}
	return string(b)
}

func TestBlockAll(t *testing.T) {
	p, err := BlockAll("wg0")
	if err != nil || len(p.Rules) != 1 || p.Rules[0].Action != Block {
		t.Fatalf("%+v %v", p, err)
	}
	if _, err := BlockAll(""); err == nil {
		t.Fatal("empty interface accepted")
	}
}

func FuzzNewPlan(f *testing.F) {
	f.Add("wg0", "192.168.1.0/24", "tcp", uint16(1), uint16(2), 1390)
	f.Fuzz(func(t *testing.T, iface, cidr, proto string, lo, hi uint16, mtu int) {
		rs := fw.Build(iface, []fw.Tenant{{ID: "a", Peers: []netip.Addr{netip.MustParseAddr("10.0.0.2")},
			Rules: []policy.Rule{{CIDR: cidr, Proto: proto, Ports: []policy.Port{{Lo: lo, Hi: hi}}}}}})
		rs = fw.WithMSSClamp(rs, iface, mtu)
		p, err := NewPlan(rs, 7)
		if err != nil {
			return
		}
		// Whatever is accepted must validate and end in a block.
		if err := p.Validate(); err != nil {
			t.Fatalf("accepted plan fails Validate: %v", err)
		}
		if p.Rules[len(p.Rules)-1].Action != Block {
			t.Fatal("plan does not end in a block")
		}
	})
}
