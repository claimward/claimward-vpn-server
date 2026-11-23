package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/claimward/claimward-vpn-server/internal/fw"
	"github.com/claimward/claimward-vpn-server/internal/store"
	"github.com/claimward/claimward-vpn-server/internal/tenant"
)

// newApplier is the kernel's nftables, or a logger under WG_DRYRUN. A variable
// so a test can make the installation fail.
var newApplier = func(dryRun bool, log *slog.Logger) fw.Applier {
	if dryRun {
		return fw.Discard{Log: log}
	}
	return fw.NewNFT()
}

// loadTenants seeds ts from the tenants file, if one is configured.
func loadTenants(ts *tenant.Store, path string, log *slog.Logger) error {
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read TENANTS_FILE: %w", err)
	}
	tenants, err := tenant.ParseFile(data)
	if err != nil {
		return err
	}
	for _, t := range tenants {
		if err := ts.Seed(t); err != nil {
			return err
		}
	}
	log.Info("tenants loaded", "file", path, "tenants", len(tenants))
	return nil
}

// startFirewall installs the gateway's ruleset and keeps it following the
// tenants (and, through the returned Manager, the peers). An error means the
// server must not start: it would forward without enforcing anything.
func startFirewall(iface string, ap fw.Applier, ts *tenant.Store, st *store.Store, log *slog.Logger) (*fw.Manager, error) {
	m := fw.NewManager(iface, ap, fw.FromStores(ts, st), log)
	if err := m.Sync(); err != nil {
		return nil, fmt.Errorf("install the gateway firewall (needs Linux and CAP_NET_ADMIN; WG_DRYRUN=true for development): %w", err)
	}
	ts.SetOnChange(func() {
		if err := m.Sync(); err != nil {
			log.Error("firewall sync after a tenant change failed; deny-all installed", "err", err)
		}
	})
	return m, nil
}
