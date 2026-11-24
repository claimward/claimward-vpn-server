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
	DIOCSTART       = C.DIOCSTART
	DIOCSTOP        = C.DIOCSTOP
	DIOCADDRULE     = C.DIOCADDRULE
	DIOCGETRULES    = C.DIOCGETRULES
	DIOCGETRULE     = C.DIOCGETRULE
	DIOCGETSTATUS   = C.DIOCGETSTATUS
	DIOCXBEGIN      = C.DIOCXBEGIN
	DIOCXCOMMIT     = C.DIOCXCOMMIT
	DIOCXROLLBACK   = C.DIOCXROLLBACK
	DIOCXEND        = C.DIOCXEND
	DIOCRINADEFINE  = C.DIOCRINADEFINE
	DIOCRGETADDRS   = C.DIOCRGETADDRS
	DIOCRGETTABLES  = C.DIOCRGETTABLES
	PF_TRANS_RULESET = C.PF_TRANS_RULESET
	PF_TRANS_TABLE   = C.PF_TRANS_TABLE
	PFR_FLAG_ADDRSTOO = C.PFR_FLAG_ADDRSTOO
	PF_TABLE_NAME_SIZE  = C.PF_TABLE_NAME_SIZE
)

type PfAddr C.struct_pf_addr
type PfAddrWrap C.struct_pf_addr_wrap
type PfRuleAddr C.struct_pf_rule_addr
type PfRule C.struct_pf_rule
type PfiocRule C.struct_pfioc_rule
type PfrTable C.struct_pfr_table
type PfrAddr C.struct_pfr_addr
type PfiocTable C.struct_pfioc_table
type PfiocTransE C.struct_pfioc_trans_e
type PfiocTrans C.struct_pfioc_trans
type PfStatus C.struct_pf_status
