package main

import (
	"fmt"
	"strings"

	"github.com/claimward/claimward-vpn-client/pkg/protocol"
	"github.com/claimward/claimward-vpn-server/internal/config"
	"github.com/claimward/claimward-vpn-server/internal/tenant"
)

// checkEntryGate refuses to start a server with a GitHub provider that would
// admit every GitHub account: EACH github provider needs an allowed
// organisation, or at least one tenant naming members. There is no opt-out.
// Other kinds have their own gates (issuer, audience, domains).
func checkEntryGate(cfg *config.Config, ts *tenant.Store) error {
	for _, p := range cfg.Providers {
		if p.Kind != protocol.KindGitHub {
			continue
		}
		open := true
		for _, o := range p.AllowedOrgs {
			if strings.TrimSpace(o) != "" {
				open = false
			}
		}
		if open && !ts.HasNamedMembers() {
			return fmt.Errorf("provider %q (github) requires allowed_orgs or at least one tenant with members: without either any GitHub account could enroll", p.ID)
		}
	}
	return nil
}
