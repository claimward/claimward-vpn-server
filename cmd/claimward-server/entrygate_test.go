package main

import (
	"context"
	"testing"

	"github.com/claimward/claimward-vpn-server/internal/config"
	"github.com/claimward/claimward-vpn-server/internal/tenant"
)

// ⛔ With neither an org allowlist nor a tenant naming members, every GitHub
// account would be admitted: the server does not start. No opt-out.
func TestEntryGateRefusesNoOrgsAndNoMembers(t *testing.T) {
	ts := tenant.New(nil, nil)
	for _, orgs := range [][]string{nil, {}, {" ", ""}} {
		if err := checkEntryGate(&config.Config{AuthProvider: "github", GitHubAllowedOrgs: orgs}, ts); err == nil {
			t.Errorf("orgs %q: started with an open gate", orgs)
		}
		if err := checkEntryGate(&config.Config{GitHubAllowedOrgs: orgs}, ts); err == nil {
			t.Errorf("orgs %q, default provider: started with an open gate", orgs)
		}
	}
}

func TestEntryGateAcceptsOrgsOrMembers(t *testing.T) {
	ts := tenant.New(nil, nil)
	if err := checkEntryGate(&config.Config{AuthProvider: "github", GitHubAllowedOrgs: []string{"acme"}}, ts); err != nil {
		t.Error(err)
	}
	ts.SetResolver(func(context.Context, string) (int64, error) { return 1, nil })
	if _, err := ts.Create(tenant.Tenant{ID: "lab", Members: []string{"alice"}}); err != nil {
		t.Fatal(err)
	}
	if err := checkEntryGate(&config.Config{AuthProvider: "github"}, ts); err != nil {
		t.Errorf("a tenant with members: %v", err)
	}
	// Other providers have their own gates.
	if err := checkEntryGate(&config.Config{AuthProvider: "oidc"}, tenant.New(nil, nil)); err != nil {
		t.Error(err)
	}
}
