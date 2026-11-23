//go:build !linux

package fw

import "errors"

// NFT is nftables, which exists on Linux only.
type NFT struct{ NetNSFd int }

// NewNFT returns an Applier that always fails: with no firewall to install,
// the gateway must not bring peers up (set WG_DRYRUN=true for development).
func NewNFT() *NFT { return &NFT{} }

// Apply always fails off Linux.
func (*NFT) Apply(Ruleset) error { return errors.New("nftables is available on Linux only") }
