package main

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/claimward/claimward-vpn-server/internal/config"
	"github.com/claimward/claimward-vpn-server/internal/fw"
	"github.com/claimward/claimward-vpn-server/internal/privsep"
	"github.com/claimward/claimward-vpn-server/internal/wg"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// privilegedBackend is what the root parent does for the child, once the
// privsep server has judged a request allowed: the WireGuard device, the
// tunnel MTU and the firewall, and nothing else. It holds no credential.
type privilegedBackend struct {
	gw     wg.Gateway
	ap     fw.Applier
	iface  string
	pool   netip.Prefix
	uplink func() int
	setMTU func(iface string, mtu int) error
}

var _ privsep.Backend = (*privilegedBackend)(nil)

func (b *privilegedBackend) AddPeer(key [privsep.KeySize]byte, ip netip.Addr) error {
	return b.gw.AddPeer(wgtypes.Key(key), net.IP(ip.AsSlice()))
}

func (b *privilegedBackend) RemovePeer(key [privsep.KeySize]byte) error {
	return b.gw.RemovePeer(wgtypes.Key(key))
}

func (b *privilegedBackend) Sweep() (int, error) {
	pool := &net.IPNet{IP: net.IP(b.pool.Addr().AsSlice()), Mask: net.CIDRMask(b.pool.Bits(), 32)}
	return wg.Sweep(b.gw, pool)
}

func (b *privilegedBackend) SetTunnelMTU(mtu int) (int, error) {
	if mtu == 0 {
		mtu = config.AutoTunnelMTU(b.uplink())
	}
	if err := b.setMTU(b.iface, mtu); err != nil {
		return 0, fmt.Errorf("set the MTU of %s: %w", b.iface, err)
	}
	return mtu, nil
}

// ApplyTenants builds the ruleset from the tenants alone: the interface and the
// MTU are the parent's own, so a child cannot name a rule.
func (b *privilegedBackend) ApplyTenants(ts []fw.Tenant, mtu int) error {
	return b.ap.Apply(fw.WithMSSClamp(fw.Build(b.iface, ts), b.iface, mtu))
}
