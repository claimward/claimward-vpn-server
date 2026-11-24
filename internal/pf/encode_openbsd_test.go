//go:build openbsd

package pf

import (
	"net/netip"
	"testing"
)

// encoderCorpus exercises every branch of encodeRule.
func encoderCorpus() []Spec {
	return []Spec{
		{Action: Block, Quick: true, Iface: "wg0"},
		{Action: Pass, Quick: true, Iface: "wg0", AF: 4, Proto: 6, SrcTable: "t0_g00000001", Dst: netip.MustParsePrefix("10.1.2.0/24"), PortLo: 443, PortHi: 443, SynOnly: true},
		{Action: Pass, Quick: true, Iface: "wg12", AF: 4, Proto: 17, SrcTable: "t1_g00000001", Dst: netip.MustParsePrefix("192.0.2.7/32"), PortLo: 1000, PortHi: 2000},
		{Action: Pass, Quick: true, Iface: "wg0", AF: 4, SrcTable: "t2_g00000001", Dst: netip.MustParsePrefix("0.0.0.0/0")},
		{Action: Match, Iface: "wg0", AF: 6, Proto: 6, SynOnly: true, MaxMSS: 1240},
		{Action: Match, Iface: "wg0", AF: 4, Proto: 6, SynOnly: true, MaxMSS: 1260},
	}
}

// TestEncoderWritesOnlyTableMembers proves the encoder touches nothing that
// the layout table (compared with C by TestLayoutAgainstC) does not name: every
// member it reports is in allMembers, and every non-zero byte of the buffers
// it builds lies inside a reported pf_rule or pfioc_rule member.
func TestEncoderWritesOnlyTableMembers(t *testing.T) {
	known := map[member]bool{}
	for _, m := range allMembers {
		known[m] = true
	}
	for i, s := range encoderCorpus() {
		var rec []member
		b, err := encodeRule(s, AnchorName, 0x01020304, func(m member) { rec = append(rec, m) })
		if err != nil {
			t.Fatalf("rule %d: %v", i, err)
		}
		covered := make([]bool, len(b))
		for _, m := range rec {
			if !known[m] {
				t.Errorf("rule %d: the encoder wrote %s.%s, which is not in allMembers", i, m.Struct, m.Field)
			}
			if m.Struct != "pf_rule" && m.Struct != "pfioc_rule" {
				continue // a member of pf_rule_addr: inside src or dst, which are recorded too
			}
			base := 0
			if m.Struct == "pf_rule" {
				base = OffIocRule
			}
			for o := base + m.Off; o < base+m.Off+m.Size; o++ {
				covered[o] = true
			}
		}
		for o, x := range b {
			if x != 0 && !covered[o] {
				t.Errorf("rule %d: byte %#x is %#x and no recorded member covers it", i, o, x)
			}
		}
	}
}

// TestEncoderRoundTripsThroughTheDecoder decodes what the encoder built (the
// decoder reads through the member table, not through the encoder's code), for
// the whole corpus.
func TestEncoderRoundTripsThroughTheDecoder(t *testing.T) {
	for i, s := range encoderCorpus() {
		b, err := encodeRule(s, AnchorName, 7, nil)
		if err != nil {
			t.Fatal(err)
		}
		d, err := decodeRule(b)
		if err != nil {
			t.Fatalf("rule %d: %v", i, err)
		}
		if err := checkRule(d, s); err != nil {
			t.Errorf("rule %d: %v", i, err)
		}
	}
}

func TestEncoderRefusesWhatDoesNotFit(t *testing.T) {
	bad := []Spec{
		{Action: Pass, Iface: "wgxxxxxxxxxxxxxxx"},                                   // 17 bytes, no room for the NUL
		{Action: Pass, Iface: "wg0", SrcTable: "0123456789012345678901234567890123"}, // table name too long
		{Action: Pass, Iface: "wg0", Dst: netip.MustParsePrefix("2001:db8::/32")},    // IPv6 destination
		{Action: Pass, Iface: "wg0", PortLo: 20, PortHi: 10},                         // reversed range
		{Action: 0, Iface: "wg0"},
		{Action: Pass, Iface: "wg0", AF: 5},
	}
	for i, s := range bad {
		if _, err := encodeRule(s, AnchorName, 1, nil); err == nil {
			t.Errorf("spec %d (%+v) was accepted", i, s)
		}
	}
}
