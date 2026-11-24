package wg

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

// This file builds the argument of OpenBSD's SIOCSWG ioctl, which is how
// ifconfig(8) and wg(8) program a wg(4) interface. wgctrl's OpenBSD driver can
// only read (ConfigureDevice returns "driver is read-only"), so without this no
// peer could be added there and every enrolment ended in a gateway error.
//
// Source read: OpenBSD sys/net/if_wg.h (v1.7, 2025/07/10), the structures
// wg_data_io, wg_interface_io, wg_peer_io and wg_aip_io; and sys/net/if_wg.c,
// wg_ioctl_set (lines 2303-2463 of that revision), the kernel half:
//
//   - it copies in one struct wg_interface_io (sizeof, flexible array excluded),
//     then, for each of i_peers_count peers, one struct wg_peer_io and then
//     p_aips_count struct wg_aip_io, all laid back to back in user memory;
//   - it NEVER reads wgd_size: nothing in the kernel bounds the buffer, so every
//     count written here is bounded by this encoder, before the ioctl;
//   - a peer without WG_PEER_HAS_PUBLIC is skipped; WG_PEER_REMOVE destroys the
//     peer (and does not create an absent one); WG_PEER_REPLACE_AIPS drops the
//     peer's addresses before adding those given;
//   - wg_aip_add refuses a family other than AF_INET/AF_INET6 and a prefix longer
//     than the family's width.
//
// The offsets are not typed here: on OpenBSD they come from zwg_openbsd_<arch>.go,
// generated from the release's own header (internal/wg/abigen), and
// TestWGLayoutAgainstC compares them with a C compiler's answer.

// Bounds on what one call may ask of the kernel.
const (
	// maxPeerOps is how many peers one SIOCSWG call may carry. The gateway
	// sends one; the bound exists so that no caller can send an unbounded list.
	maxPeerOps = 8
	// maxPeerAIPs is how many allowed addresses one peer may carry.
	maxPeerAIPs = 16
)

// ioLayout is the byte layout of the four structures.
type ioLayout struct {
	IfaceSize       int // sizeof(struct wg_interface_io), also the offset of i_peers
	IfaceFlags      int
	IfacePeersCount int
	PeerSize        int // sizeof(struct wg_peer_io), also the offset of p_aips
	PeerFlags       int
	PeerProto       int
	PeerPublic      int
	PeerAipsCount   int
	AipSize         int // sizeof(struct wg_aip_io)
	AipAf           int
	AipCidr         int
	AipAddr         int
}

// layout64 is the table for the 64-bit OpenBSD ports (amd64, arm64), worked out
// from if_wg.h and checked three ways: against the generated file, against a C
// program on the release (TestWGLayoutAgainstC), and by the encoder tests that
// run on every host.
var layout64 = ioLayout{
	IfaceSize: 80, IfaceFlags: 0, IfacePeersCount: 72,
	PeerSize: 208, PeerFlags: 0, PeerProto: 4, PeerPublic: 8, PeerAipsCount: 200,
	AipSize: 24, AipAf: 0, AipCidr: 4, AipAddr: 8,
}

// Constants of the interface, <net/if_wg.h>; the OpenBSD build checks them
// against the generated ones.
const (
	wgKeyLen          = 32
	wgPeerHasPublic   = 1 << 0
	wgPeerReplaceAIPs = 1 << 4
	wgPeerRemove      = 1 << 5
	afInet            = 2
)

// peerOp is one peer to add (with its IPv4 allowed addresses) or to remove.
type peerOp struct {
	Public [wgKeyLen]byte
	Remove bool
	AIPs   []netip.Prefix
}

// encodeSet is the buffer wgd_interface points at: an interface header with no
// flag (neither key, port nor REPLACE_PEERS: nothing of the interface changes),
// then the peers. It validates every count before writing a byte.
func encodeSet(l ioLayout, ops []peerOp) ([]byte, error) {
	if len(ops) == 0 {
		return nil, errors.New("wg: no peer to configure")
	}
	if len(ops) > maxPeerOps {
		return nil, fmt.Errorf("wg: %d peers in one call exceed the limit of %d", len(ops), maxPeerOps)
	}
	size := l.IfaceSize
	for i, op := range ops {
		if len(op.AIPs) > maxPeerAIPs {
			return nil, fmt.Errorf("wg: peer %d has %d allowed addresses, more than %d", i, len(op.AIPs), maxPeerAIPs)
		}
		if op.Remove && len(op.AIPs) != 0 {
			return nil, fmt.Errorf("wg: peer %d is removed and also given addresses", i)
		}
		for _, p := range op.AIPs {
			// The address is the Addr's four bytes, so a 4in6 address would be
			// taken for an IPv4 one by the kernel: refuse everything but Is4.
			// IsValid is the prefix length: PrefixFrom keeps the address of a
			// length outside 0..32 and only reports it invalid.
			if !p.IsValid() || !p.Addr().Is4() {
				return nil, fmt.Errorf("wg: peer %d: allowed address %v is not an IPv4 prefix", i, p)
			}
		}
		size += l.PeerSize + len(op.AIPs)*l.AipSize
	}

	buf := make([]byte, size)
	binary.NativeEndian.PutUint64(buf[l.IfacePeersCount:], uint64(len(ops)))
	off := l.IfaceSize
	for _, op := range ops {
		peer := buf[off : off+l.PeerSize]
		flags := uint32(wgPeerHasPublic)
		if op.Remove {
			flags |= wgPeerRemove
		} else {
			flags |= wgPeerReplaceAIPs
		}
		binary.NativeEndian.PutUint32(peer[l.PeerFlags:], flags)
		copy(peer[l.PeerPublic:l.PeerPublic+wgKeyLen], op.Public[:])
		binary.NativeEndian.PutUint64(peer[l.PeerAipsCount:], uint64(len(op.AIPs)))
		off += l.PeerSize
		for _, p := range op.AIPs {
			aip := buf[off : off+l.AipSize]
			aip[l.AipAf] = afInet
			binary.NativeEndian.PutUint32(aip[l.AipCidr:], uint32(p.Bits()))
			a := p.Addr().AsSlice() // not As4: a missing guard must fail an assertion, not panic
			copy(aip[l.AipAddr:l.AipAddr+4], a)
			off += l.AipSize
		}
	}
	return buf, nil
}
