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
	return &wgctrlGateway{client: c, device: device}, nil
}

func (g *wgctrlGateway) AddPeer(pub wgtypes.Key, ip net.IP) error {
	allowed := net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
	cfg := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{{
			PublicKey:         pub,
			ReplaceAllowedIPs: true,
			AllowedIPs:        []net.IPNet{allowed},
		}},
	}
	if err := g.client.ConfigureDevice(g.device, cfg); err != nil {
		return fmt.Errorf("add peer: %w", err)
	}
	return nil
}

func (g *wgctrlGateway) RemovePeer(pub wgtypes.Key) error {
	cfg := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{{PublicKey: pub, Remove: true}},
	}
	if err := g.client.ConfigureDevice(g.device, cfg); err != nil {
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
