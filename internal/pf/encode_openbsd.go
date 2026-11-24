//go:build openbsd

package pf

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/unix"
)

// This file turns a Spec into the bytes of a struct pfioc_rule, the argument of
// DIOCADDRULE. struct pf_rule has unions, pointers and anonymous structs that
// cgo -godefs cannot spell, so the rule is a byte buffer and every write goes
// through ruleBuf with a member from layout_openbsd.go.

// ruleBuf is a struct pfioc_rule under construction. rec, when set, is told
// about every member written, which is how the test proves that the encoder
// touches nothing outside the table that TestLayoutAgainstC verified.
type ruleBuf struct {
	b   []byte
	rec func(member)
}

func newRuleBuf(rec func(member)) *ruleBuf {
	return &ruleBuf{b: make([]byte, SizeofPfiocRule), rec: rec}
}

// at is the bytes of m inside the buffer.
func (w *ruleBuf) at(m member) []byte {
	base := 0
	if m.Struct == "pf_rule" {
		base = OffIocRule
	}
	if w.rec != nil {
		w.rec(m)
	}
	return w.b[base+m.Off : base+m.Off+m.Size]
}

func (w *ruleBuf) put8(m member, v uint8) { w.at(m)[0] = v }

func (w *ruleBuf) put16(m member, v uint16) { binary.NativeEndian.PutUint16(w.at(m), v) }

func (w *ruleBuf) put32(m member, v uint32) { binary.NativeEndian.PutUint32(w.at(m), v) }

// putStr writes a NUL-terminated string: it must leave room for the NUL.
func (w *ruleBuf) putStr(m member, s string) error {
	if len(s) >= m.Size {
		return fmt.Errorf("pf: %q does not fit %s.%s (%d bytes with its NUL)", s, m.Struct, m.Field, m.Size)
	}
	copy(w.at(m), s)
	return nil
}

// putBytes writes b into the member, which it must fit exactly.
func (w *ruleBuf) putBytes(m member, b []byte) {
	if len(b) != m.Size {
		panic(fmt.Sprintf("pf: internal error: %d bytes for %s.%s of %d", len(b), m.Struct, m.Field, m.Size))
	}
	copy(w.at(m), b)
}

// htons is a port in network byte order, as pf_rule_addr.port holds it, read
// back as the host's uint16 so a plain struct store writes the right bytes.
func htons(p uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], p)
	return binary.NativeEndian.Uint16(b[:])
}

func ntohs(p uint16) uint16 {
	var b [2]byte
	binary.NativeEndian.PutUint16(b[:], p)
	return binary.BigEndian.Uint16(b[:])
}

func afOf(af int) (uint8, error) {
	switch af {
	case 0:
		return 0, nil
	case 4:
		return unix.AF_INET, nil
	case 6:
		return unix.AF_INET6, nil
	}
	return 0, fmt.Errorf("pf: address family %d", af)
}

// keepStateFor is what pfctl writes in keep_state for each action: a pass rule
// keeps state, a block and a match rule do not (verified against pfctl's own
// bytes by TestEncoderMatchesPfctl).
func keepStateFor(a Action) uint8 {
	if a == Pass {
		return PF_STATE_NORMAL
	}
	return 0
}

func ruleAddrBytes(ra *PfRuleAddr) []byte {
	return unsafe.Slice((*byte)(unsafe.Pointer(ra)), SizeofPfRuleAddr)
}

// encodeRule is the pfioc_rule that DIOCADDRULE takes for s, in anchor, with
// the ruleset ticket the transaction gave. Every field is range-checked here
// as well as by Plan.Validate: the kernel gets nothing this function did not
// build from validated values.
func encodeRule(s Spec, anchor string, ticket uint32, rec func(member)) ([]byte, error) {
	w := newRuleBuf(rec)
	if err := w.putStr(mIocAnchor, anchor); err != nil {
		return nil, err
	}
	w.put32(mIocTicket, ticket)

	switch s.Action {
	case Pass:
		w.put8(mAction, PF_PASS)
	case Block:
		w.put8(mAction, PF_DROP)
	case Match:
		w.put8(mAction, PF_MATCH)
	default:
		return nil, fmt.Errorf("pf: action %d", s.Action)
	}
	w.put8(mDirection, PF_IN)
	if s.Quick {
		w.put8(mQuick, 1)
	}
	w.put8(mKeepState, keepStateFor(s.Action))
	if err := w.putStr(mIfname, s.Iface); err != nil {
		return nil, err
	}
	af, err := afOf(s.AF)
	if err != nil {
		return nil, err
	}
	w.put8(mAf, af)
	w.put8(mProto, s.Proto)
	if s.SynOnly {
		w.put8(mFlags, TH_SYN)
		w.put8(mFlagset, TH_SYN|TH_ACK)
	}
	w.put32(mRtableid, 0xffffffff) // -1: any routing table, as pfctl writes it
	w.put32(mOnrdomain, 0xffffffff)
	if s.MaxMSS != 0 {
		w.put16(mMaxMSS, s.MaxMSS)
		w.put16(mScrubFlags, PFSTATE_SCRUB_TCP)
	}

	var src, dst PfRuleAddr
	if s.SrcTable != "" {
		if len(s.SrcTable) >= PF_TABLE_NAME_SIZE {
			return nil, fmt.Errorf("pf: table name %q", s.SrcTable)
		}
		src.Addr.Type = PF_ADDR_TABLE
		copy(src.Addr.V[:], s.SrcTable)
		if rec != nil {
			rec(mAddrWrapType)
			rec(mAddrWrapV)
		}
	}
	if s.Dst.IsValid() {
		a := s.Dst.Addr()
		if !a.Is4() {
			return nil, fmt.Errorf("pf: destination %s is not IPv4", s.Dst)
		}
		dst.Addr.Type = PF_ADDR_ADDRMASK
		a4 := a.As4()
		copy(dst.Addr.V[0:4], a4[:])
		var mask [4]byte
		if b := s.Dst.Bits(); b > 0 { // a /0 is the all-zero mask
			binary.BigEndian.PutUint32(mask[:], ^uint32(0)<<(32-b))
		}
		copy(dst.Addr.V[16:20], mask[:])
		if rec != nil {
			rec(mAddrWrapType)
			rec(mAddrWrapV)
		}
	}
	if s.PortLo != 0 {
		if s.PortHi < s.PortLo {
			return nil, fmt.Errorf("pf: ports %d:%d", s.PortLo, s.PortHi)
		}
		dst.Port[0] = htons(s.PortLo)
		if s.PortLo == s.PortHi {
			dst.Op = PF_OP_EQ
		} else {
			dst.Port[1] = htons(s.PortHi)
			dst.Op = PF_OP_RRG
		}
		if rec != nil {
			rec(mRAPort)
			rec(mRAPortOp)
		}
	}
	if rec != nil {
		rec(mRAAddr)
	}
	w.putBytes(mSrc, ruleAddrBytes(&src))
	w.putBytes(mDst, ruleAddrBytes(&dst))
	return w.b, nil
}

// addrOf is the pfr_addr of one host address of a table.
func addrOf(a netip.Addr) (PfrAddr, error) {
	if !a.Is4() {
		return PfrAddr{}, fmt.Errorf("pf: table address %s is not IPv4", a)
	}
	var e PfrAddr
	a4 := a.As4()
	copy(e.U[:4], a4[:])
	e.Af = unix.AF_INET
	e.Net = 32
	return e, nil
}
