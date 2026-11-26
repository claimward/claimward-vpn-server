package main

import (
	"context"
	"strings"
	"testing"

	"github.com/claimward/claimward-vpn-client/pkg/protocol"
	"github.com/claimward/claimward-vpn-server/internal/config"
)

func ghApp(id string) config.Provider {
	return config.Provider{ID: id, Kind: protocol.KindGitHub, GitHubClientID: "app", ClientSecret: "s", AllowedOrgs: []string{"org"}}
}

func TestBuildProvidersKeepsTheOrderAndTheGitHubOnes(t *testing.T) {
	set, ids, githubs, goauthn, err := buildProviders(context.Background(), []config.Provider{ghApp("b"), ghApp("a")})
	if err != nil {
		t.Fatal(err)
	}
	if set == nil || strings.Join(ids, ",") != "b,a" || len(githubs) != 2 || goauthn != nil {
		t.Errorf("set=%v ids=%v githubs=%d goauthn=%v", set, ids, len(githubs), goauthn)
	}
}

// ⛔ A provider that cannot be built stops the start, and the error names it.
func TestBuildProvidersRefusesAProviderItCannotBuild(t *testing.T) {
	bad := ghApp("broken")
	bad.Kind = "nope"
	_, _, _, _, err := buildProviders(context.Background(), []config.Provider{ghApp("ok"), bad})
	if err == nil || !strings.Contains(err.Error(), `provider "broken"`) {
		t.Errorf("a provider of an unknown kind: %v", err)
	}
}

// ⛔ Two providers under one id would let one answer for the other.
func TestBuildProvidersRefusesADuplicateID(t *testing.T) {
	_, _, _, _, err := buildProviders(context.Background(), []config.Provider{ghApp("same"), ghApp("same")})
	if err == nil {
		t.Error("two providers named alike were accepted")
	}
}
