package wg

import (
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// A device wgctrl cannot read is an error from the wgctrl-backed reader, not a
// nil dereference.
func TestWgctrlWriterReportsAMissingDevice(t *testing.T) {
	c, err := wgctrl.New()
	if err != nil {
		t.Skipf("no wgctrl client here: %v", err)
	}
	defer c.Close()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("peers panicked: %v", r)
		}
	}()
	ps, err := wgctrlWriter{client: c, device: "cwnosuchdev0"}.peers()
	if err == nil || ps != nil {
		t.Errorf("peers of a missing device = %v, %v; want an error", ps, err)
	}
}

type fakeWriter struct {
	calls [][]peerOp
	err   error
}

func (f *fakeWriter) peers() ([]Peer, error) { return nil, f.err }

func (f *fakeWriter) setPeers(ops []peerOp) error {
	f.calls = append(f.calls, ops)
	return f.err
}

// The gateway that writes through a peerWriter (OpenBSD's) asks for exactly one
// peer, with exactly one /32, or for its removal.
func TestWriterGatewayAddAndRemove(t *testing.T) {
	f := &fakeWriter{}
	g := &wgctrlGateway{w: f}
	k, _ := wgtypes.GeneratePrivateKey()
	pub := k.PublicKey()

	if err := g.AddPeer(pub, net.ParseIP("10.80.0.7")); err != nil {
		t.Fatal(err)
	}
	// The 16-byte form of an IPv4 address (what net.ParseIP returns) is the same address.
	want := []peerOp{{Public: pub, AIPs: []netip.Prefix{netip.MustParsePrefix("10.80.0.7/32")}}}
	if len(f.calls) != 1 || len(f.calls[0]) != 1 || f.calls[0][0].Remove ||
		f.calls[0][0].Public != want[0].Public || len(f.calls[0][0].AIPs) != 1 || f.calls[0][0].AIPs[0] != want[0].AIPs[0] {
		t.Fatalf("AddPeer asked for %+v, want %+v", f.calls, want)
	}
	if err := g.AddPeer(pub, net.IP(netip.MustParseAddr("10.80.0.8").AsSlice())); err != nil {
		t.Fatalf("4-byte address: %v", err)
	}

	if err := g.RemovePeer(pub); err != nil {
		t.Fatal(err)
	}
	last := f.calls[len(f.calls)-1]
	if len(last) != 1 || !last[0].Remove || last[0].Public != pub || len(last[0].AIPs) != 0 {
		t.Fatalf("RemovePeer asked for %+v", last)
	}
}

func TestWriterGatewayRefusals(t *testing.T) {
	f := &fakeWriter{}
	g := &wgctrlGateway{w: f}
	var pub wgtypes.Key
	for _, ip := range []net.IP{nil, net.ParseIP("fd00::1"), net.IP{1, 2, 3}} {
		err := g.AddPeer(pub, ip)
		if err == nil || !strings.Contains(err.Error(), "not an IPv4 address") {
			t.Errorf("AddPeer(%v) = %v, want a refusal", ip, err)
		}
	}
	if len(f.calls) != 0 {
		t.Fatalf("a refused address reached the writer: %+v", f.calls)
	}

	boom := errors.New("boom")
	f.err = boom
	if err := g.AddPeer(pub, net.ParseIP("10.0.0.1")); !errors.Is(err, boom) || !strings.HasPrefix(err.Error(), "add peer: ") {
		t.Errorf("AddPeer error = %v", err)
	}
	if err := g.RemovePeer(pub); !errors.Is(err, boom) || !strings.HasPrefix(err.Error(), "remove peer: ") {
		t.Errorf("RemovePeer error = %v", err)
	}
}
