//go:build ignore

// Input of `go tool cgo -godefs`: the WireGuard ioctl structures of the running
// OpenBSD's own <net/if_wg.h> (SIOCSWG / SIOCGWG, struct wg_data_io,
// wg_interface_io, wg_peer_io, wg_aip_io). Run through gen.go on an OpenBSD
// host; the output is committed as zwg_openbsd_<arch>.go.
//
// Every number is an enum computed by the C compiler, not a Go type derived by
// cgo: wg_interface_io and wg_peer_io end in flexible array members, which the
// encoder lays out itself (the kernel reads the peers and their addresses back
// to back after the header, if_wg.c wg_ioctl_set).

package wg

/*
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <net/if.h>
#include <netinet/in.h>
#include <net/if_wg.h>
#include <stddef.h>

enum {
	SzDataIO           = sizeof(struct wg_data_io),
	SzIfaceIO          = sizeof(struct wg_interface_io),
	SzPeerIO           = sizeof(struct wg_peer_io),
	SzAipIO            = sizeof(struct wg_aip_io),
	OffDataName        = offsetof(struct wg_data_io, wgd_name),
	OffDataSize        = offsetof(struct wg_data_io, wgd_size),
	OffDataIface       = offsetof(struct wg_data_io, wgd_interface),
	OffIfaceFlags      = offsetof(struct wg_interface_io, i_flags),
	OffIfacePeersCount = offsetof(struct wg_interface_io, i_peers_count),
	OffIfacePeers      = offsetof(struct wg_interface_io, i_peers),
	OffPeerFlags       = offsetof(struct wg_peer_io, p_flags),
	OffPeerProto       = offsetof(struct wg_peer_io, p_protocol_version),
	OffPeerPublic      = offsetof(struct wg_peer_io, p_public),
	OffPeerAipsCount   = offsetof(struct wg_peer_io, p_aips_count),
	OffPeerAips        = offsetof(struct wg_peer_io, p_aips),
	OffAipAf           = offsetof(struct wg_aip_io, a_af),
	OffAipCidr         = offsetof(struct wg_aip_io, a_cidr),
	OffAipAddr         = offsetof(struct wg_aip_io, a_addr),
};
*/
import "C"

const (
	SizeofWgDataIO  = C.SzDataIO
	SizeofWgIfaceIO = C.SzIfaceIO
	SizeofWgPeerIO  = C.SzPeerIO
	SizeofWgAipIO   = C.SzAipIO
)

const (
	SIOCSWG           = C.SIOCSWG
	SIOCGWG           = C.SIOCGWG
	WGKeyLen          = C.WG_KEY_LEN
	WGPeerHasPublic   = C.WG_PEER_HAS_PUBLIC
	WGPeerReplaceAIPs = C.WG_PEER_REPLACE_AIPS
	WGPeerRemove      = C.WG_PEER_REMOVE
	WGAfInet          = C.AF_INET
	WGIfNameSize      = C.IFNAMSIZ
)

const (
	OffDataName        = C.OffDataName
	OffDataSize        = C.OffDataSize
	OffDataIface       = C.OffDataIface
	OffIfaceFlags      = C.OffIfaceFlags
	OffIfacePeersCount = C.OffIfacePeersCount
	OffIfacePeers      = C.OffIfacePeers
	OffPeerFlags       = C.OffPeerFlags
	OffPeerProto       = C.OffPeerProto
	OffPeerPublic      = C.OffPeerPublic
	OffPeerAipsCount   = C.OffPeerAipsCount
	OffPeerAips        = C.OffPeerAips
	OffAipAf           = C.OffAipAf
	OffAipCidr         = C.OffAipCidr
	OffAipAddr         = C.OffAipAddr
)
