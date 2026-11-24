//go:build !openbsd

package wg

// newPeerWriter: only OpenBSD needs its own writer (wgctrl's driver there is
// read-only); everywhere else wgctrl configures the device.
func newPeerWriter(string) peerWriter { return nil }
