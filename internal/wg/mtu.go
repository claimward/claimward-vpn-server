package wg

import (
	"net/netip"

	"github.com/claimward/claimward-vpn-client/pkg/pathmtu"
)

// Public addresses only used to ask the kernel which interface the default
// route leaves by: no packet is sent to them.
var probes = []netip.AddrPort{
	netip.MustParseAddrPort("9.9.9.9:53"),
	netip.MustParseAddrPort("[2620:fe::fe]:53"),
}

// UplinkMTU is the MTU of the interface the gateway reaches the Internet
// through: the smallest of its IPv4 and IPv6 default routes' interfaces,
// 0 when it cannot be told (no default route).
func UplinkMTU() int {
	return uplinkMTU(pathmtu.LinkMTU)
}

func uplinkMTU(link func(netip.AddrPort) int) int {
	best := 0
	for _, p := range probes {
		if m := link(p); m > 0 && (best == 0 || m < best) {
			best = m
		}
	}
	return best
}
