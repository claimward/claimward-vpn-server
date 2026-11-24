//go:build !openbsd

package main

import "github.com/claimward/claimward-vpn-server/internal/fw"

// platformApplier is nftables (Linux), or an Applier that refuses elsewhere.
func platformApplier() fw.Applier { return fw.NewNFT() }
