//go:build openbsd

package pf

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// oracleAnchor is a scratch anchor: pfctl loads the reference rule there, and
// the kernel hands back its own copy.
const oracleAnchor = "claimward-oracle"

// pfctlLine is the pf.conf rule that stands for s: what an administrator would
// write, and what pfctl (the reference implementation of the encoding) turns
// into a struct pf_rule.
func pfctlLine(s Spec) string {
	var b strings.Builder
	switch s.Action {
	case Pass:
		b.WriteString("pass in")
	case Block:
		b.WriteString("block drop in")
	case Match:
		b.WriteString("match in")
	}
	if s.Quick {
		b.WriteString(" quick")
	}
	fmt.Fprintf(&b, " on %s", s.Iface)
	switch s.AF {
	case 4:
		b.WriteString(" inet")
	case 6:
		b.WriteString(" inet6")
	}
	switch s.Proto {
	case protoTCP:
		b.WriteString(" proto tcp")
	case protoUDP:
		b.WriteString(" proto udp")
	}
	src, dst := "any", "any"
	if s.SrcTable != "" {
		src = "<" + s.SrcTable + ">"
	}
	if s.Dst.IsValid() {
		dst = s.Dst.String()
	}
	if s.SrcTable == "" && !s.Dst.IsValid() && s.PortLo == 0 {
		if s.Action == Block && s.AF == 0 && s.Proto == 0 {
			b.WriteString(" all")
		}
	} else {
		fmt.Fprintf(&b, " from %s to %s", src, dst)
	}
	if s.PortLo != 0 {
		if s.PortLo == s.PortHi {
			fmt.Fprintf(&b, " port %d", s.PortLo)
		} else {
			fmt.Fprintf(&b, " port %d:%d", s.PortLo, s.PortHi)
		}
	}
	if s.SynOnly {
		b.WriteString(" flags S/SA")
	} else if s.Action == Pass && (s.Proto == 0 || s.Proto == protoTCP) {
		// pfctl adds "flags S/SA" to such a rule on its own; the Spec means no
		// flag test, so say so.
		b.WriteString(" flags any")
	}
	if s.MaxMSS != 0 {
		fmt.Fprintf(&b, " scrub (max-mss %d)", s.MaxMSS)
	}
	return b.String()
}

// kernelOwned are the byte ranges of a struct pf_rule (offsets from its start)
// that the kernel fills in or rewrites on its own, so that a comparison with
// the encoder's bytes ignores them. Everything else is compared.
func kernelOwned() [][2]int {
	r := [][2]int{
		{OffRuleNr, OffRuleNr + 4},
		{OffRuleCuid, OffRuleCuid + 4},
		{OffRuleCpid, OffRuleCpid + 4},
		// skip[]: the kernel recomputes the skip steps (0xffffffff = none) on
		// every ruleset change; userland never sets them. Measured 7.9 and 8.0.
		{OffRuleSkip, OffRuleSkip + 0x88},
		// Measured, identical on 7.9 and 8.0 for every rule of the corpus: pfctl
		// writes 30 in the 4 bytes before `evaluations` (pktrate.seconds).
		// pktrate.limit is 0, so no packet rate applies and it is never read.
		//
		// The 7 pfctl writes at the start of each of the three pf_pool (nat,
		// rdr, route) is PF_ADDR_NONE, NOT kernel-owned: this list used to mask
		// it, the encoder wrote 0 (PF_ADDR_ADDRMASK), and the kernel then read a
		// "nat-to any rdr-to any" in every rule (pfctl -sr printed it) and the
		// packet proof's allowed traffic never arrived. They are compared now.
		{OffRuleEvaluations - 4, OffRuleEvaluations},
	}
	for _, base := range []int{OffRuleSrc, OffRuleDst} {
		r = append(r, [2]int{base + 32, base + 40}) // pf_addr_wrap.p: table entry count
		r = append(r, [2]int{base + 41, base + 42}) // pf_addr_wrap.iflags
	}
	return r
}

type namedOff struct {
	off  int
	name string
}

func ruleOffsetNames() []namedOff {
	n := []namedOff{
		{OffRuleSrc, "src"}, {OffRuleDst, "dst"}, {OffRuleSkip, "skip"}, {OffRuleIfname, "ifname"},
		{OffRuleRcvIfname, "rcv_ifname"}, {OffRuleRtableid, "rtableid"}, {OffRuleOnrdomain, "onrdomain"},
		{OffRuleTimeout, "timeout"}, {OffRulePktrate, "pktrate"}, {OffRuleEvaluations, "evaluations"},
		{OffRuleEntries, "entries"}, {OffRuleNr, "nr"}, {OffRuleCuid, "cuid"}, {OffRuleCpid, "cpid"},
		{OffRuleMaxMSS, "max_mss"}, {OffRuleScrubFlags, "scrub_flags"}, {OffRuleAction, "action"},
		{OffRuleDirection, "direction"}, {OffRuleQuick, "quick"}, {OffRuleKeepState, "keep_state"},
		{OffRuleAf, "af"}, {OffRuleProto, "proto"}, {OffRuleFlags, "flags"}, {OffRuleFlagset, "flagset"},
		{OffRuleExptime, "exptime"}, {OffRulePrio, "prio"}, {OffRuleSetPrio, "set_prio"},
		{OffRuleNaf, "naf"}, {OffRuleLog, "log"}, {OffRuleRuleFlag, "rule_flag"},
	}
	sort.Slice(n, func(i, j int) bool { return n[i].off < n[j].off })
	return n
}

func nameOf(off int) string {
	best := "?"
	for _, n := range ruleOffsetNames() {
		if n.off <= off {
			best = n.name
		}
	}
	return best
}

// diffRules lists every byte of the pf_rule part that differs, outside the
// kernel-owned ranges, as "<member>+<n> (pf_rule+0x..): ours .. kernel ..".
func diffRules(ours, kernel []byte) []string {
	skip := make([]bool, SizeofPfRule)
	for _, r := range kernelOwned() {
		for o := r[0]; o < r[1]; o++ {
			skip[o] = true
		}
	}
	var out []string
	for o := 0; o < SizeofPfRule; o++ {
		a, k := ours[OffIocRule+o], kernel[OffIocRule+o]
		if skip[o] || a == k {
			continue
		}
		out = append(out, fmt.Sprintf("%s (pf_rule+%#x): ours %#02x kernel %#02x", nameOf(o), o, a, k))
	}
	return out
}

// TestEncoderMatchesPfctl loads each rule of the corpus with pfctl, the
// reference encoder, into a scratch anchor, reads the kernel's own copy back
// with our DIOCGETRULE, and compares it with the bytes encodeRule built, apart
// from the fields the kernel owns. pfctl is an ORACLE here: the server never
// runs it.
func TestEncoderMatchesPfctl(t *testing.T) {
	pfHost(t)
	fd, err := unix.Open(devPF, unix.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	t.Cleanup(func() { flushAnchor(oracleAnchor) })

	specs := append(encoderCorpus(), []Spec{
		{Action: Match, Iface: "wg0", AF: 4, Proto: protoTCP, MaxMSS: 1350},
		{Action: Match, Iface: "wg0", AF: 6, Proto: protoTCP, MaxMSS: 1330},
		{Action: Pass, Quick: true, Iface: "wg0", AF: 4, Proto: protoTCP, SynOnly: true, SrcTable: "t0_g00000001", Dst: netip.MustParsePrefix("192.168.1.0/24"), PortLo: 8000, PortHi: 8010},
		{Action: Pass, Quick: true, Iface: "wg0", AF: 4, SrcTable: "t0_g00000001", Dst: netip.MustParsePrefix("10.9.0.0/16")},
	}...)
	for i, s := range specs {
		t.Run(strconv.Itoa(i)+" "+pfctlLine(s), func(t *testing.T) {
			conf := "table <t0_g00000001> { 10.0.0.2 }\ntable <t1_g00000001> { 10.0.0.3 }\ntable <t2_g00000001> { 10.0.0.4 }\n" + pfctlLine(s) + "\n"
			flushAnchor(oracleAnchor)
			pfctl(t, conf, "-a", oracleAnchor, "-f", "-")
			raw, err := readRules(fd, oracleAnchor)
			if err != nil {
				t.Fatal(err)
			}
			if len(raw) != 1 {
				t.Fatalf("pfctl loaded %d rules from\n%s", len(raw), conf)
			}
			ours, err := encodeRule(s, oracleAnchor, 0, nil)
			if err != nil {
				t.Fatal(err)
			}
			if d := diffRules(ours, raw[0]); len(d) > 0 {
				t.Errorf("the encoder and pfctl disagree on %d bytes for\n%s\n%s", len(d), pfctlLine(s), strings.Join(d, "\n"))
			}
			// The kernel's rule must decode back to the Spec as well.
			dec, err := decodeRule(raw[0])
			if err != nil {
				t.Fatalf("decoding pfctl's rule: %v", err)
			}
			want := s
			if want.Dst.IsValid() && want.Dst.Bits() == 0 {
				want.Dst = netip.Prefix{}
			}
			if dec.Spec != want {
				t.Errorf("pfctl's rule decodes to %+v, want %+v", dec.Spec, want)
			}
		})
	}
}
