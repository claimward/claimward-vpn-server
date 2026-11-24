//go:build !openbsd

package main

import (
	"errors"
	"log/slog"
	"os"

	"github.com/claimward/claimward-vpn-server/internal/config"
)

// privsepMain: privilege separation is OpenBSD's. Elsewhere one process runs,
// except that the hidden child role is refused rather than run unsupervised.
func privsepMain(*slog.Logger) (bool, error) {
	if len(os.Args) > 1 && os.Args[1] == childRole {
		return true, errors.New("the " + childRole + " role exists on OpenBSD only")
	}
	return false, nil
}

func lockdown(*config.Config, *slog.Logger) error {
	return errors.New("pledge and unveil exist on OpenBSD only")
}
