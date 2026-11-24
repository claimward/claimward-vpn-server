//go:build ignore

// Input of `go tool cgo -godefs`: the pf structures and ioctl numbers the
// server uses, taken from the running OpenBSD's own <net/pfvar.h>. Run through
// gen.go on an OpenBSD host; the output is committed as ztypes_openbsd_*.go.

package pf

/*
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <net/pfvar.h>
#include <stddef.h>

// struct pf_rule holds unions, pointers and anonymous structs that cgo -godefs
// cannot spell as Go types, so the rule is NOT generated as a struct: the
// encoder writes into a [SizeofPfRule]byte at these offsets, which C computes.
#define PFR_OFF(f) offsetof(struct pf_rule, f)
#define PFI_OFF(f) offsetof(struct pfioc_rule, f)
enum {
	OffRuleSrc        = PFR_OFF(src),
	OffRuleDst        = PFR_OFF(dst),
	OffRuleSkip       = PFR_OFF(skip),
	OffRuleIfname     = PFR_OFF(ifname),
	OffRuleRcvIfname  = PFR_OFF(rcv_ifname),
	OffRuleRtableid   = PFR_OFF(rtableid),
	OffRuleOnrdomain  = PFR_OFF(onrdomain),
	OffRuleNr         = PFR_OFF(nr),
	OffRuleCuid       = PFR_OFF(cuid),
	OffRuleCpid       = PFR_OFF(cpid),
	OffRuleMaxMSS     = PFR_OFF(max_mss),
	OffRuleScrubFlags = PFR_OFF(scrub_flags),
	OffRuleAction     = PFR_OFF(action),
	OffRuleDirection  = PFR_OFF(direction),
	OffRuleQuick      = PFR_OFF(quick),
	OffRuleKeepState  = PFR_OFF(keep_state),
	OffRuleAf         = PFR_OFF(af),
	OffRuleProto      = PFR_OFF(proto),
	OffRuleFlags      = PFR_OFF(flags),
	OffRuleFlagset    = PFR_OFF(flagset),
	OffRuleTimeout    = PFR_OFF(timeout),
	OffRuleExptime    = PFR_OFF(exptime),
	OffRuleEvaluations = PFR_OFF(evaluations),
	OffRulePktrate    = PFR_OFF(pktrate),
	OffRuleEntries    = PFR_OFF(entries),
	OffRulePrio       = PFR_OFF(prio),
	OffRuleSetPrio    = PFR_OFF(set_prio),
	OffRuleNaf        = PFR_OFF(naf),
	OffRuleLog        = PFR_OFF(log),
	OffRuleRuleFlag   = PFR_OFF(rule_flag),
	OffRuleAnchorRelative = PFR_OFF(anchor_relative),
	OffRuleAnchorWildcard = PFR_OFF(anchor_wildcard),
	OffRuleFlush      = PFR_OFF(flush),
	OffIocAction      = PFI_OFF(action),
	OffIocTicket      = PFI_OFF(ticket),
	OffIocNr          = PFI_OFF(nr),
	OffIocAnchor      = PFI_OFF(anchor),
	OffIocCall        = PFI_OFF(anchor_call),
	OffIocRule        = PFI_OFF(rule),
	OffKifName        = offsetof(struct pfi_kif, pfik_name),
	OffKifFlags       = offsetof(struct pfi_kif, pfik_flags),
};
*/
import "C"

const (
	SizeofPfRule      = C.sizeof_struct_pf_rule
	SizeofPfiocRule   = C.sizeof_struct_pfioc_rule
	SizeofPfiocTable  = C.sizeof_struct_pfioc_table
	SizeofPfrTable    = C.sizeof_struct_pfr_table
	SizeofPfrAddr     = C.sizeof_struct_pfr_addr
	SizeofPfiocTrans  = C.sizeof_struct_pfioc_trans
	SizeofPfiocTransE = C.sizeof_struct_pfioc_trans_e
	SizeofPfStatus    = C.sizeof_struct_pf_status
	SizeofPfRuleAddr  = C.sizeof_struct_pf_rule_addr
	SizeofPfAddrWrap  = C.sizeof_struct_pf_addr_wrap
	SizeofPfAddr      = C.sizeof_struct_pf_addr
)

const (
	DIOCSTART          = C.DIOCSTART
	DIOCSTOP           = C.DIOCSTOP
	DIOCADDRULE        = C.DIOCADDRULE
	DIOCGETRULES       = C.DIOCGETRULES
	DIOCGETRULE        = C.DIOCGETRULE
	DIOCGETSTATUS      = C.DIOCGETSTATUS
	DIOCXBEGIN         = C.DIOCXBEGIN
	DIOCXCOMMIT        = C.DIOCXCOMMIT
	DIOCXROLLBACK      = C.DIOCXROLLBACK
	DIOCXEND           = C.DIOCXEND
	DIOCRINADEFINE     = C.DIOCRINADEFINE
	DIOCRGETADDRS      = C.DIOCRGETADDRS
	DIOCRGETTABLES     = C.DIOCRGETTABLES
	PF_TRANS_RULESET   = C.PF_TRANS_RULESET
	PF_TRANS_TABLE     = C.PF_TRANS_TABLE
	PFR_FLAG_ADDRSTOO  = C.PFR_FLAG_ADDRSTOO
	PF_TABLE_NAME_SIZE = C.PF_TABLE_NAME_SIZE
	PF_PASS            = C.PF_PASS
	PF_DROP            = C.PF_DROP
	PF_MATCH           = C.PF_MATCH
	PF_IN              = C.PF_IN
	PF_OP_EQ           = C.PF_OP_EQ
	PF_OP_RRG          = C.PF_OP_RRG
	PF_ADDR_ADDRMASK   = C.PF_ADDR_ADDRMASK
	PF_ADDR_TABLE      = C.PF_ADDR_TABLE
	PF_ADDR_NONE       = C.PF_ADDR_NONE
	PF_STATE_NORMAL    = C.PF_STATE_NORMAL
	PFSTATE_SCRUB_TCP  = C.PFSTATE_SCRUB_TCP
	PF_PRIO_ZERO       = C.PF_PRIO_ZERO
	TH_SYN             = C.TH_SYN
	TH_ACK             = C.TH_ACK
)

const (
	OffRuleSrc            = C.OffRuleSrc
	OffRuleDst            = C.OffRuleDst
	OffRuleSkip           = C.OffRuleSkip
	OffRuleIfname         = C.OffRuleIfname
	OffRuleRcvIfname      = C.OffRuleRcvIfname
	OffRuleRtableid       = C.OffRuleRtableid
	OffRuleOnrdomain      = C.OffRuleOnrdomain
	OffRuleNr             = C.OffRuleNr
	OffRuleCuid           = C.OffRuleCuid
	OffRuleCpid           = C.OffRuleCpid
	OffRuleMaxMSS         = C.OffRuleMaxMSS
	OffRuleScrubFlags     = C.OffRuleScrubFlags
	OffRuleAction         = C.OffRuleAction
	OffRuleDirection      = C.OffRuleDirection
	OffRuleQuick          = C.OffRuleQuick
	OffRuleKeepState      = C.OffRuleKeepState
	OffRuleAf             = C.OffRuleAf
	OffRuleProto          = C.OffRuleProto
	OffRuleFlags          = C.OffRuleFlags
	OffRuleFlagset        = C.OffRuleFlagset
	OffRuleTimeout        = C.OffRuleTimeout
	OffRuleExptime        = C.OffRuleExptime
	OffRuleEvaluations    = C.OffRuleEvaluations
	OffRulePktrate        = C.OffRulePktrate
	OffRuleEntries        = C.OffRuleEntries
	OffRulePrio           = C.OffRulePrio
	OffRuleSetPrio        = C.OffRuleSetPrio
	OffRuleNaf            = C.OffRuleNaf
	OffRuleLog            = C.OffRuleLog
	OffRuleRuleFlag       = C.OffRuleRuleFlag
	OffRuleAnchorRelative = C.OffRuleAnchorRelative
	OffRuleAnchorWildcard = C.OffRuleAnchorWildcard
	OffRuleFlush          = C.OffRuleFlush
	OffIocAction          = C.OffIocAction
	OffIocTicket          = C.OffIocTicket
	OffIocNr              = C.OffIocNr
	OffIocAnchor          = C.OffIocAnchor
	OffIocCall            = C.OffIocCall
	OffIocRule            = C.OffIocRule
	OffKifName            = C.OffKifName
	OffKifFlags           = C.OffKifFlags
	SizeofPfiKif          = C.sizeof_struct_pfi_kif
	DIOCIGETIFACES        = C.DIOCIGETIFACES
	PFI_IFLAG_SKIP        = C.PFI_IFLAG_SKIP
)

type PfAddr C.struct_pf_addr
type PfAddrWrap C.struct_pf_addr_wrap
type PfRuleAddr C.struct_pf_rule_addr
type PfrTable C.struct_pfr_table
type PfrAddr C.struct_pfr_addr
type PfiocTable C.struct_pfioc_table
type PfiocTransE C.struct_pfioc_trans_e
type PfiocTrans C.struct_pfioc_trans
type PfStatus C.struct_pf_status
type PfiocIface C.struct_pfioc_iface
