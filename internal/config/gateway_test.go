package config

import (
	"net/netip"
	"testing"
)

func TestLoadGatewayDefaultsAreLoadsDefaults(t *testing.T) {
	t.Setenv("WG_INTERFACE", "")
	t.Setenv("VPN_CIDR", "")
	t.Setenv("WG_DRYRUN", "")
	g, err := LoadGateway()
	if err != nil {
		t.Fatal(err)
	}
	if g.Interface != "wg0" || g.Pool != netip.MustParsePrefix("10.80.0.0/24") || g.DryRun {
		t.Fatalf("%+v", g)
	}
}

func TestLoadGatewayReadsTheVariablesLoadReads(t *testing.T) {
	t.Setenv("WG_INTERFACE", "wg7")
	t.Setenv("VPN_CIDR", "10.9.8.77/16") // masked: the pool is the network
	t.Setenv("WG_DRYRUN", "true")
	g, err := LoadGateway()
	if err != nil {
		t.Fatal(err)
	}
	if g.Interface != "wg7" || g.Pool != netip.MustParsePrefix("10.9.0.0/16") || !g.DryRun {
		t.Fatalf("%+v", g)
	}
}

func TestLoadGatewayRefusesABadPool(t *testing.T) {
	for _, bad := range []string{"nonsense", "fd00::/64", "10.0.0.0/33"} {
		t.Setenv("VPN_CIDR", bad)
		if _, err := LoadGateway(); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
