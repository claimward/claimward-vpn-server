package main

import (
	"errors"
	"strings"

	"github.com/claimward/claimward-vpn-server/internal/config"
	"github.com/claimward/claimward-vpn-server/internal/tenant"
)

// checkEntryGate refuses to start a GitHub-authenticated server that would
// admit every GitHub account: it needs an allowed organisation, or at least one
// tenant naming members. There is no opt-out. Other providers have their own
// gates (issuer, audience, domains).
func checkEntryGate(cfg *config.Config, ts *tenant.Store) error {
	if cfg.AuthProvider != "" && cfg.AuthProvider != "github" {
		return nil
	}
	for _, o := range cfg.GitHubAllowedOrgs {
		if strings.TrimSpace(o) != "" {
			return nil
		}
	}
	if ts.HasNamedMembers() {
		return nil
	}
	return errors.New("AUTH_PROVIDER=github requires GITHUB_ALLOWED_ORGS or at least one tenant with members: without either any GitHub account could enroll")
}
