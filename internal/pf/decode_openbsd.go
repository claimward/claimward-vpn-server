//go:build openbsd

package pf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/bits"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/unix"
)

// decodedRule is what a struct pfioc_rule read back from the kernel says.
type decodedRule struct {
	Spec
	Direction  uint8
	KeepState  uint8
	ScrubFlags uint16
	AnchorCall string
}

func cstring(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

// rd is the bytes of m in a pfioc_rule buffer.
func rd(b []byte, m member) []byte {
	base := 0
	if m.Struct == "pf_rule" {
		base = OffIocRule
	}
	return b[base+m.Off : base+m.Off+m.Size]
}

func readRuleAddr(b []byte, m member) PfRuleAddr {
	var ra PfRuleAddr
	copy(unsafe.Slice((*byte)(unsafe.Pointer(&ra)), SizeofPfRuleAddr), rd(b, m))
	return ra
}

// decodeRule reads the fields of a struct pfioc_rule that Spec stands for. It
// is the other direction of encodeRule but shares no code with it beyond the
// verified member table: an encoder bug does not cancel here, because what is
// decoded is the kernel's copy of the rule, not the encoder's own bytes. A
// field this package never writes is refused when it is set, not ignored: a
// rule with a log, a negation or a state option that we did not ask for is a
// rule that is not ours.
func decodeRule(b []byte) (decodedRule, error) {
	if len(b) != SizeofPfiocRule {
		return decodedRule{}, fmt.Errorf("pf: a pfioc_rule of %d bytes, want %d", len(b), SizeofPfiocRule)
	}
	var d decodedRule
	d.AnchorCall = cstring(rd(b, mIocCall))
	switch rd(b, mAction)[0] {
	case PF_PASS:
		d.Action = Pass
	case PF_DROP:
		d.Action = Block
	case PF_MATCH:
		d.Action = Match
	default:
		return decodedRule{}, fmt.Errorf("pf: rule action %d", rd(b, mAction)[0])
	}
	d.Direction = rd(b, mDirection)[0]
	d.Quick = rd(b, mQuick)[0] != 0
	d.KeepState = rd(b, mKeepState)[0]
	d.Iface = cstring(rd(b, mIfname))
	if !allZero(rd(b, mRcvIfname)) {
		return decodedRule{}, fmt.Errorf("pf: rule has a receive interface")
	}
	switch rd(b, mAf)[0] {
	case 0:
	case unix.AF_INET:
		d.AF = 4
	case unix.AF_INET6:
		d.AF = 6
	default:
		return decodedRule{}, fmt.Errorf("pf: rule address family %d", rd(b, mAf)[0])
	}
	d.Proto = rd(b, mProto)[0]
	fl, fs := rd(b, mFlags)[0], rd(b, mFlagset)[0]
	switch {
	case fl == 0 && fs == 0:
	case fl == TH_SYN && fs == TH_SYN|TH_ACK:
		d.SynOnly = true
	default:
		return decodedRule{}, fmt.Errorf("pf: TCP flags %#x/%#x", fl, fs)
	}
	d.MaxMSS = binary.NativeEndian.Uint16(rd(b, mMaxMSS))
	d.ScrubFlags = binary.NativeEndian.Uint16(rd(b, mScrubFlags))

	src := readRuleAddr(b, mSrc)
	dst := readRuleAddr(b, mDst)
	if src.Neg != 0 || dst.Neg != 0 {
		return decodedRule{}, fmt.Errorf("pf: a negated address")
	}
	if src.Port != [2]uint16{} || src.Op != 0 {
		return decodedRule{}, fmt.Errorf("pf: a source port")
	}
	switch src.Addr.Type {
	case PF_ADDR_TABLE:
		d.SrcTable = cstring(src.Addr.V[:])
	case PF_ADDR_ADDRMASK:
		if !allZero(src.Addr.V[:]) {
			return decodedRule{}, fmt.Errorf("pf: a source address")
		}
	default:
		return decodedRule{}, fmt.Errorf("pf: source address type %d", src.Addr.Type)
	}
	if dst.Addr.Type != PF_ADDR_ADDRMASK {
		return decodedRule{}, fmt.Errorf("pf: destination address type %d", dst.Addr.Type)
	}
	v := dst.Addr.V
	if !allZero(v[4:16]) || !allZero(v[20:32]) {
		return decodedRule{}, fmt.Errorf("pf: a destination that is not an IPv4 prefix")
	}
	if !allZero(v[0:4]) || !allZero(v[16:20]) {
		mask := binary.BigEndian.Uint32(v[16:20])
		ones := bits.OnesCount32(mask)
		if mask != 0 && mask != ^uint32(0)<<(32-ones) {
			return decodedRule{}, fmt.Errorf("pf: destination mask %#x is not a prefix", mask)
		}
		a, _ := netip.AddrFromSlice(v[0:4])
		d.Dst = netip.PrefixFrom(a, ones)
	}
	switch dst.Op {
	case 0:
		if dst.Port != [2]uint16{} {
			return decodedRule{}, fmt.Errorf("pf: ports without an operator")
		}
	case PF_OP_EQ:
		d.PortLo = ntohs(dst.Port[0])
		d.PortHi = d.PortLo
	case PF_OP_RRG:
		d.PortLo, d.PortHi = ntohs(dst.Port[0]), ntohs(dst.Port[1])
	default:
		return decodedRule{}, fmt.Errorf("pf: port operator %d", dst.Op)
	}
	return d, nil
}
