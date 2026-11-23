package main

import (
	"fmt"
	"log/slog"

	"github.com/claimward/claimward-vpn-server/internal/config"
)

// applyTunnelMTU settles the tunnel MTU and puts it on the gateway's own
// interface, so that the server and the clients it advertises it to agree.
//
// TUNNEL_MTU wins; without it the MTU is derived from the uplink's (see
// config.AutoTunnelMTU). cfg.TunnelMTU is left holding the value in force,
// which the enroll response carries. A failure to set it stops the start:
// a gateway at a different MTU than the one it advertises stalls TCP.
// A dry run touches no interface.
func applyTunnelMTU(cfg *config.Config, uplink func() int, set func(string, int) error, log *slog.Logger) error {
	source := "TUNNEL_MTU"
	if cfg.TunnelMTU == 0 {
		up := uplink()
		cfg.TunnelMTU = config.AutoTunnelMTU(up)
		source = fmt.Sprintf("uplink MTU %d", up)
	}
	if cfg.DryRun {
		log.Info("dry-run: tunnel MTU not applied", "mtu", cfg.TunnelMTU, "source", source)
		return nil
	}
	if err := set(cfg.WGInterface, cfg.TunnelMTU); err != nil {
		return err
	}
	log.Info("tunnel MTU", "interface", cfg.WGInterface, "mtu", cfg.TunnelMTU, "source", source)
	return nil
}
