package wg

import (
	"errors"
	"net"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type fakeDevice struct {
	peers   []Peer
	removed []wgtypes.Key
	listErr error
	rmErr   error
}

func (f *fakeDevice) AddPeer(wgtypes.Key, net.IP) error { return nil }
func (f *fakeDevice) RemovePeer(k wgtypes.Key) error {
	if f.rmErr != nil {
		return f.rmErr
	}
	f.removed = append(f.removed, k)
	return nil
}
func (f *fakeDevice) Close() error           { return nil }
func (f *fakeDevice) Peers() ([]Peer, error) { return f.peers, f.listErr }

func cidr(t *testing.T, s string) net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatal(err)
	}
	return *n
}

func newKey(t *testing.T) wgtypes.Key {
	t.Helper()
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k.PublicKey()
}

// What a previous run added goes; what it could not have added stays.
func TestSweepRemovesOnlyThisServersPeers(t *testing.T) {
	pool := cidr(t, "10.80.0.0/24")
	left := newKey(t)
	keep := map[string]Peer{
		"outside the pool":  {PublicKey: newKey(t), AllowedIPs: []net.IPNet{cidr(t, "10.81.0.5/32")}},
		"not a /32":         {PublicKey: newKey(t), AllowedIPs: []net.IPNet{cidr(t, "10.80.0.0/28")}},
		"two allowed IPs":   {PublicKey: newKey(t), AllowedIPs: []net.IPNet{cidr(t, "10.80.0.9/32"), cidr(t, "192.168.1.0/24")}},
		"no allowed IP":     {PublicKey: newKey(t)},
		"site-to-site link": {PublicKey: newKey(t), AllowedIPs: []net.IPNet{cidr(t, "0.0.0.0/0")}},
	}
	dev := &fakeDevice{peers: []Peer{{PublicKey: left, AllowedIPs: []net.IPNet{cidr(t, "10.80.0.7/32")}}}}
	for _, p := range keep {
		dev.peers = append(dev.peers, p)
	}
	n, err := Sweep(dev, &pool)
	if err != nil || n != 1 || len(dev.removed) != 1 || dev.removed[0] != left {
		t.Fatalf("swept %d %v: %v", n, dev.removed, err)
	}
}

func TestSweepErrors(t *testing.T) {
	pool := cidr(t, "10.80.0.0/24")
	if _, err := Sweep(&fakeDevice{listErr: errors.New("no device")}, &pool); err == nil {
		t.Error("a device that cannot be listed swept nothing, silently")
	}
	dev := &fakeDevice{rmErr: errors.New("busy"), peers: []Peer{{PublicKey: newKey(t), AllowedIPs: []net.IPNet{cidr(t, "10.80.0.7/32")}}}}
	if _, err := Sweep(dev, &pool); err == nil {
		t.Error("a peer that could not be removed was not reported")
	}
	// The dry-run gateway holds no peers to list.
	if n, err := Sweep(NewDryRunGateway(nil), &pool); n != 0 || err != nil {
		t.Errorf("dry run: %d %v", n, err)
	}
}
