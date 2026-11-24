//go:build !openbsd

package wg

import "golang.zx2c4.com/wireguard/wgctrl"

// newPeerWriter: only OpenBSD needs its own writer (wgctrl's driver there is
// read-only); everywhere else wgctrl configures the device.
func newPeerWriter(c *wgctrl.Client, device string) peerWriter {
	return wgctrlWriter{client: c, device: device}
}
