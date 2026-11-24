package main

import (
	"net"
	"net/netip"
	"reflect"
	"testing"

	"github.com/claimward/claimward-vpn-server/internal/config"
	"github.com/claimward/claimward-vpn-server/internal/fw"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type gwRec struct{ added, removed []string }

func (g *gwRec) AddPeer(k wgtypes.Key, ip net.IP) error {
	g.added = append(g.added, ip.String())
	return nil
}
func (g *gwRec) RemovePeer(k wgtypes.Key) error {
	g.removed = append(g.removed, k.String())
	return nil
}
func (g *gwRec) Close() error { return nil }

type apRec struct{ got []fw.Ruleset }

func (a *apRec) Apply(rs fw.Ruleset) error { a.got = append(a.got, rs); return nil }

func newBackend(g *gwRec, a *apRec, set func(string, int) error) *privilegedBackend {
	return &privilegedBackend{gw: g, ap: a, iface: "wg9", pool: netip.MustParsePrefix("10.80.0.0/24"),
		uplink: func() int { return 1500 }, setMTU: set}
}

func TestTheBackendAddsAPeerAtTheAddressItWasGiven(t *testing.T) {
	g := &gwRec{}
	b := newBackend(g, &apRec{}, nil)
	if err := b.AddPeer([32]byte{1}, netip.MustParseAddr("10.80.0.7")); err != nil {
		t.Fatal(err)
	}
	if len(g.added) != 1 || g.added[0] != "10.80.0.7" {
		t.Fatalf("added %v", g.added)
	}
}

func TestTheBackendDerivesTheMTUFromTheUplinkWhenAskedTo(t *testing.T) {
	var gotIface string
	var gotMTU int
	b := newBackend(&gwRec{}, &apRec{}, func(i string, m int) error { gotIface, gotMTU = i, m; return nil })
	got, err := b.SetTunnelMTU(0)
	if err != nil || got != config.AutoTunnelMTU(1500) || gotMTU != got || gotIface != "wg9" {
		t.Fatalf("got %d %v; set %q %d", got, err, gotIface, gotMTU)
	}
	if got, _ := b.SetTunnelMTU(1400); got != 1400 || gotMTU != 1400 {
		t.Fatalf("explicit MTU: %d %d", got, gotMTU)
	}
}

func TestTheBackendBuildsTheRulesetOnTheParentsInterface(t *testing.T) {
	a := &apRec{}
	b := newBackend(&gwRec{}, a, nil)
	if err := b.ApplyTenants(nil, 1380); err != nil {
		t.Fatal(err)
	}
	want := fw.WithMSSClamp(fw.Build("wg9", nil), "wg9", 1380)
	if len(a.got) != 1 || !reflect.DeepEqual(a.got[0], want) {
		t.Fatalf("applied %+v, want %+v", a.got, want)
	}
}
