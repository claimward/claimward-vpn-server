//go:build openbsd

package main

import (
	"github.com/claimward/claimward-vpn-server/internal/fw"
	"github.com/claimward/claimward-vpn-server/internal/pf"
)

// platformApplier is OpenBSD's pf, driven through /dev/pf ioctls.
func platformApplier() fw.Applier { return pf.NewApplier() }
