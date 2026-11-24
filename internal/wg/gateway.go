// Package wg manages the WireGuard gateway: adding and removing peers on the
// kernel interface (e.g. wg0) via wgctrl.
//
// The server only manages *peers*. The interface itself (its private key and
// listen port) is expected to already exist, created by wg-quick/systemd-networkd
// at boot. This keeps the privileged interface setup out of the long-running
// service.
package wg

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Gateway adds and removes WireGuard peers.
type Gateway interface {
	// AddPeer adds (or replaces) a peer whose only allowed IP is the given /32.
	AddPeer(pub wgtypes.Key, ip net.IP) error
	// RemovePeer removes a peer by public key.
	RemovePeer(pub wgtypes.Key) error
	io.Closer
}

// wgctrlGateway is the real implementation backed by wgctrl.
type wgctrlGateway struct {
	client *wgctrl.Client
	device string
	// w writes the peers. Reads (Peers) go through wgctrl everywhere, but
	// OpenBSD's wgctrl driver cannot configure a device, so there w is the
	// SIOCSWG writer (wgwrite_openbsd.go); elsewhere it is wgctrl itself.
	w peerWriter
}

// wgctrlWriter configures the device through wgctrl.
type wgctrlWriter struct {
	client *wgctrl.Client
	device string
}

func (w wgctrlWriter) setPeers(ops []peerOp) error {
	cfg := wgtypes.Config{Peers: make([]wgtypes.PeerConfig, 0, len(ops))}
	for _, op := range ops {
		pc := wgtypes.PeerConfig{PublicKey: op.Public, Remove: op.Remove}
		if !op.Remove {
			pc.ReplaceAllowedIPs = true
			for _, p := range op.AIPs {
				pc.AllowedIPs = append(pc.AllowedIPs, net.IPNet{IP: p.Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), 32)})
			}
		}
		cfg.Peers = append(cfg.Peers, pc)
	}
	return w.client.ConfigureDevice(w.device, cfg)
}

// peerWriter applies peer changes to the device the gateway manages.
type peerWriter interface {
	setPeers(ops []peerOp) error
}

// NewGateway opens a wgctrl client and verifies the device exists.
func NewGateway(device string) (Gateway, error) {
	c, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("open wgctrl: %w", err)
	}
	if _, err := c.Device(device); err != nil {
		c.Close()
		return nil, fmt.Errorf("wireguard device %q not found (create it with wg-quick first): %w", device, err)
	}
	return &wgctrlGateway{client: c, device: device, w: newPeerWriter(c, device)}, nil
}

func (g *wgctrlGateway) AddPeer(pub wgtypes.Key, ip net.IP) error {
	a, ok := netip.AddrFromSlice(ip)
	if !ok || !a.Unmap().Is4() {
		return fmt.Errorf("add peer: %v is not an IPv4 address", ip)
	}
	if err := g.w.setPeers([]peerOp{{Public: pub, AIPs: []netip.Prefix{netip.PrefixFrom(a.Unmap(), 32)}}}); err != nil {
		return fmt.Errorf("add peer: %w", err)
	}
	return nil
}

func (g *wgctrlGateway) RemovePeer(pub wgtypes.Key) error {
	if err := g.w.setPeers([]peerOp{{Public: pub, Remove: true}}); err != nil {
		return fmt.Errorf("remove peer: %w", err)
	}
	return nil
}

func (g *wgctrlGateway) Close() error { return g.client.Close() }

// dryRunGateway logs peer operations without touching any device. Used for local
// development on machines without a WireGuard interface (e.g. macOS dev box).
type dryRunGateway struct{ log *slog.Logger }

// NewDryRunGateway returns a Gateway that only logs.
func NewDryRunGateway(log *slog.Logger) Gateway { return &dryRunGateway{log: log} }

func (g *dryRunGateway) AddPeer(pub wgtypes.Key, ip net.IP) error {
	g.log.Info("dry-run add peer", "public_key", pub.String(), "allowed_ip", ip.String()+"/32")
	return nil
}

func (g *dryRunGateway) RemovePeer(pub wgtypes.Key) error {
	g.log.Info("dry-run remove peer", "public_key", pub.String())
	return nil
}

func (g *dryRunGateway) Close() error { return nil }
