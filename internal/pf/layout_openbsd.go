//go:build openbsd

package pf

import "unsafe"

// A member is one field of a kernel structure that this package reads or
// writes. Off comes from the generated ztypes file (C's own offsetof, run on
// the VM by the pfabi lane) or from the generated Go struct; Size is written
// by hand. TestLayoutAgainstC compiles a C program against the release's own
// <net/pfvar.h> and compares Off AND Size of EVERY member below, so a typo in
// either is a red test on the VM and not a mis-encoded rule.
type member struct {
	Struct string // C struct name without "struct "
	Field  string // C member designator (may be nested: "src.addr.type")
	Off    int
	Size   int
}

// The members of struct pf_rule the encoder and decoder touch. This table is
// the ONLY place those offsets are named: the encoder writes through
// ruleBuf.put*, which records the member, and TestEncoderWritesOnlyTableMembers
// fails for a write outside the table.
var (
	mAction      = member{"pf_rule", "action", OffRuleAction, 1}
	mDirection   = member{"pf_rule", "direction", OffRuleDirection, 1}
	mQuick       = member{"pf_rule", "quick", OffRuleQuick, 1}
	mKeepState   = member{"pf_rule", "keep_state", OffRuleKeepState, 1}
	mAf          = member{"pf_rule", "af", OffRuleAf, 1}
	mProto       = member{"pf_rule", "proto", OffRuleProto, 1}
	mFlags       = member{"pf_rule", "flags", OffRuleFlags, 1}
	mFlagset     = member{"pf_rule", "flagset", OffRuleFlagset, 1}
	mIfname      = member{"pf_rule", "ifname", OffRuleIfname, 16}
	mRcvIfname   = member{"pf_rule", "rcv_ifname", OffRuleRcvIfname, 16}
	mMaxMSS      = member{"pf_rule", "max_mss", OffRuleMaxMSS, 2}
	mScrubFlags  = member{"pf_rule", "scrub_flags", OffRuleScrubFlags, 2}
	mRtableid    = member{"pf_rule", "rtableid", OffRuleRtableid, 4}
	mOnrdomain   = member{"pf_rule", "onrdomain", OffRuleOnrdomain, 4}
	mSrc         = member{"pf_rule", "src", OffRuleSrc, SizeofPfRuleAddr}
	mDst         = member{"pf_rule", "dst", OffRuleDst, SizeofPfRuleAddr}
	mIocAction   = member{"pfioc_rule", "action", OffIocAction, 4}
	mIocTicket   = member{"pfioc_rule", "ticket", OffIocTicket, 4}
	mIocNr       = member{"pfioc_rule", "nr", OffIocNr, 4}
	mIocAnchor   = member{"pfioc_rule", "anchor", OffIocAnchor, 1024}
	mIocCall     = member{"pfioc_rule", "anchor_call", OffIocCall, 1024}
	mIocRule     = member{"pfioc_rule", "rule", OffIocRule, SizeofPfRule}
	mRuleNr      = member{"pf_rule", "nr", OffRuleNr, 4}
	mRulePrio    = member{"pf_rule", "prio", OffRulePrio, 1}
	mRuleSetPrio = member{"pf_rule", "set_prio", OffRuleSetPrio, 2}
	mRuleNaf     = member{"pf_rule", "naf", OffRuleNaf, 1}
	mRuleLog     = member{"pf_rule", "log", OffRuleLog, 1}

	// The address type of the three pools of a rule (nat-to, rdr-to, route-to).
	// A pool whose type is not PF_ADDR_NONE is a nat/rdr/route the kernel acts
	// on, so these MUST be written PF_ADDR_NONE. The offsets are the amd64/arm64
	// ones (8-byte pointers); TestLayoutAgainstC compares them with C's offsetof.
	mNatAddrType   = member{"pf_rule", "nat.addr.type", 0x270, 1}
	mRdrAddrType   = member{"pf_rule", "rdr.addr.type", 0x2f8, 1}
	mRouteAddrType = member{"pf_rule", "route.addr.type", 0x380, 1}
)

// Members of the structures the Go side declares from the generated types
// (their offsets are Go's layout of the generated fields, compared with C's).
var (
	mAddrWrapV    = member{"pf_addr_wrap", "v", int(unsafe.Offsetof(PfAddrWrap{}.V)), 32}
	mAddrWrapType = member{"pf_addr_wrap", "type", int(unsafe.Offsetof(PfAddrWrap{}.Type)), 1}
	mRAAddr       = member{"pf_rule_addr", "addr", int(unsafe.Offsetof(PfRuleAddr{}.Addr)), SizeofPfAddrWrap}
	mRAPort       = member{"pf_rule_addr", "port", int(unsafe.Offsetof(PfRuleAddr{}.Port)), 4}
	mRANeg        = member{"pf_rule_addr", "neg", int(unsafe.Offsetof(PfRuleAddr{}.Neg)), 1}
	mRAPortOp     = member{"pf_rule_addr", "port_op", int(unsafe.Offsetof(PfRuleAddr{}.Op)), 1}
	mTblAnchor    = member{"pfr_table", "pfrt_anchor", int(unsafe.Offsetof(PfrTable{}.Anchor)), 1024}
	mTblName      = member{"pfr_table", "pfrt_name", int(unsafe.Offsetof(PfrTable{}.Name)), 32}
	mTblFlags     = member{"pfr_table", "pfrt_flags", int(unsafe.Offsetof(PfrTable{}.Flags)), 4}
	mAddrU        = member{"pfr_addr", "pfra_u", int(unsafe.Offsetof(PfrAddr{}.U)), 16}
	mAddrAf       = member{"pfr_addr", "pfra_af", int(unsafe.Offsetof(PfrAddr{}.Af)), 1}
	mAddrNet      = member{"pfr_addr", "pfra_net", int(unsafe.Offsetof(PfrAddr{}.Net)), 1}
	mAddrNot      = member{"pfr_addr", "pfra_not", int(unsafe.Offsetof(PfrAddr{}.Not)), 1}
	mTioTable     = member{"pfioc_table", "pfrio_table", int(unsafe.Offsetof(PfiocTable{}.Table)), SizeofPfrTable}
	mTioBuffer    = member{"pfioc_table", "pfrio_buffer", int(unsafe.Offsetof(PfiocTable{}.Buffer)), int(unsafe.Sizeof(uintptr(0)))}
	mTioEsize     = member{"pfioc_table", "pfrio_esize", int(unsafe.Offsetof(PfiocTable{}.Esize)), 4}
	mTioSize      = member{"pfioc_table", "pfrio_size", int(unsafe.Offsetof(PfiocTable{}.Size)), 4}
	mTioNadd      = member{"pfioc_table", "pfrio_nadd", int(unsafe.Offsetof(PfiocTable{}.Nadd)), 4}
	mTioFlags     = member{"pfioc_table", "pfrio_flags", int(unsafe.Offsetof(PfiocTable{}.Flags)), 4}
	mTioTicket    = member{"pfioc_table", "pfrio_ticket", int(unsafe.Offsetof(PfiocTable{}.Ticket)), 4}
	mTrSize       = member{"pfioc_trans", "size", int(unsafe.Offsetof(PfiocTrans{}.Size)), 4}
	mTrEsize      = member{"pfioc_trans", "esize", int(unsafe.Offsetof(PfiocTrans{}.Esize)), 4}
	mTrArray      = member{"pfioc_trans", "array", int(unsafe.Offsetof(PfiocTrans{}.Array)), int(unsafe.Sizeof(uintptr(0)))}
	mTeType       = member{"pfioc_trans_e", "type", int(unsafe.Offsetof(PfiocTransE{}.Type)), 4}
	mTeAnchor     = member{"pfioc_trans_e", "anchor", int(unsafe.Offsetof(PfiocTransE{}.Anchor)), 1024}
	mTeTicket     = member{"pfioc_trans_e", "ticket", int(unsafe.Offsetof(PfiocTransE{}.Ticket)), 4}
	mStRunning    = member{"pf_status", "running", int(unsafe.Offsetof(PfStatus{}.Running)), 4}
	mIfaceName    = member{"pfioc_iface", "pfiio_name", int(unsafe.Offsetof(PfiocIface{}.Name)), 16}
	mIfaceBuffer  = member{"pfioc_iface", "pfiio_buffer", int(unsafe.Offsetof(PfiocIface{}.Buffer)), int(unsafe.Sizeof(uintptr(0)))}
	mIfaceEsize   = member{"pfioc_iface", "pfiio_esize", int(unsafe.Offsetof(PfiocIface{}.Esize)), 4}
	mIfaceSize    = member{"pfioc_iface", "pfiio_size", int(unsafe.Offsetof(PfiocIface{}.Size)), 4}
	mKifName      = member{"pfi_kif", "pfik_name", OffKifName, 16}
	mKifFlags     = member{"pfi_kif", "pfik_flags", OffKifFlags, 4}
)

// allMembers is what TestLayoutAgainstC checks against C, and what the
// encoder is allowed to write.
var allMembers = []member{
	mAction, mDirection, mQuick, mKeepState, mAf, mProto, mFlags, mFlagset,
	mIfname, mRcvIfname, mMaxMSS, mScrubFlags, mRtableid, mOnrdomain, mSrc, mDst,
	mIocAction, mIocTicket, mIocNr, mIocAnchor, mIocCall, mIocRule,
	mRuleNr, mRulePrio, mRuleSetPrio, mRuleNaf, mRuleLog,
	mNatAddrType, mRdrAddrType, mRouteAddrType,
	mAddrWrapV, mAddrWrapType, mRAAddr, mRAPort, mRANeg, mRAPortOp,
	mTblAnchor, mTblName, mTblFlags, mAddrU, mAddrAf, mAddrNet, mAddrNot,
	mTioTable, mTioBuffer, mTioEsize, mTioSize, mTioNadd, mTioFlags, mTioTicket,
	mTrSize, mTrEsize, mTrArray, mTeType, mTeAnchor, mTeTicket, mStRunning,
	mIfaceName, mIfaceBuffer, mIfaceEsize, mIfaceSize, mKifName, mKifFlags,
}
