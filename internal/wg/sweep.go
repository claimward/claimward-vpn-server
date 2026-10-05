package wg

import (
	"fmt"
	"net"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Peer is a peer as the device holds it.
type Peer struct {
	PublicKey  wgtypes.Key
	AllowedIPs []net.IPNet
}

// Lister is a Gateway that can say which peers the device holds.
type Lister interface {
	Peers() ([]Peer, error)
}

// Sweep removes the peers a previous run of this server left on the device:
// those whose only allowed IP is one /32 inside pool, which is the shape
// AddPeer gives every peer it adds. Any other peer -- configured by hand,
// a site-to-site link -- is not this server's and is left alone.
//
// ⛔ Leases are held in memory. Without this, a restart forgot every
// enrollment and left its peer on the device: never reaped, never
// reconciled against the provider's list, so a person disabled before the
// restart kept a working tunnel. And the pool, starting afresh, handed the
// same addresses to new devices.
//
// A device swept here finds itself unknown at its next lease renewal and
// enrolls again (claimward-vpn-client v0.3.0).
func Sweep(g Gateway, pool *net.IPNet) (removed int, err error) {
	l, ok := g.(Lister)
	if !ok {
		return 0, nil
	}
	peers, err := l.Peers()
	if err != nil {
		return 0, fmt.Errorf("list peers: %w", err)
	}
	for _, p := range peers {
		if !ours(p, pool) {
			continue
		}
		if err := g.RemovePeer(p.PublicKey); err != nil {
			return removed, err
		}
		removed++
	}
	return removed, nil
}

func ours(p Peer, pool *net.IPNet) bool {
	if len(p.AllowedIPs) != 1 {
		return false
	}
	a := p.AllowedIPs[0]
	ones, bits := a.Mask.Size()
	return bits == 32 && ones == 32 && pool.Contains(a.IP)
}

func (g *wgctrlGateway) Peers() ([]Peer, error) {
	d, err := g.client.Device(g.device)
	if err != nil {
		return nil, err
	}
	out := make([]Peer, 0, len(d.Peers))
	for _, p := range d.Peers {
		out = append(out, Peer{PublicKey: p.PublicKey, AllowedIPs: p.AllowedIPs})
	}
	return out, nil
}
