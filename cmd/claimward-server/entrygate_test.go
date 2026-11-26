package main

import (
	"context"
	"testing"

	"github.com/claimward/claimward-vpn-server/internal/config"
	"github.com/claimward/claimward-vpn-server/internal/tenant"
)

func gh(id string, orgs ...string) config.Provider {
	return config.Provider{ID: id, Kind: "github", AllowedOrgs: orgs}
}

// ⛔ With neither an org allowlist nor a tenant naming members, every GitHub
// account would be admitted: the server does not start. No opt-out. EACH
// github provider is judged, not only the first.
func TestEntryGateRefusesNoOrgsAndNoMembers(t *testing.T) {
	ts := tenant.New(nil, nil)
	for _, orgs := range [][]string{nil, {}, {" ", ""}} {
		if err := checkEntryGate(&config.Config{Providers: []config.Provider{gh("hub", orgs...)}}, ts); err == nil {
			t.Errorf("orgs %q: started with an open gate", orgs)
		}
		// A closed provider beside an open one does not close the open one.
		cfg := &config.Config{Providers: []config.Provider{gh("a", "acme"), gh("b", orgs...)}}
		if err := checkEntryGate(cfg, ts); err == nil {
			t.Errorf("orgs %q on the second provider: started with an open gate", orgs)
		}
	}
}

func TestEntryGateAcceptsOrgsOrMembers(t *testing.T) {
	ts := tenant.New(nil, nil)
	if err := checkEntryGate(&config.Config{Providers: []config.Provider{gh("hub", "acme")}}, ts); err != nil {
		t.Error(err)
	}
	ts.SetResolver(func(context.Context, string) (int64, error) { return 1, nil })
	if _, err := ts.Create(tenant.Tenant{ID: "lab", Members: []string{"alice"}}); err != nil {
		t.Fatal(err)
	}
	if err := checkEntryGate(&config.Config{Providers: []config.Provider{gh("hub")}}, ts); err != nil {
		t.Errorf("a tenant with members: %v", err)
	}
	// Other providers have their own gates.
	oidc := config.Provider{ID: "campus", Kind: "oidc"}
	if err := checkEntryGate(&config.Config{Providers: []config.Provider{oidc}}, tenant.New(nil, nil)); err != nil {
		t.Error(err)
	}
}
