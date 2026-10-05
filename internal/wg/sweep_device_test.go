package wg

import (
	"net"
	"os"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// On a real WireGuard device (root, Linux): CLAIMWARD_TEST_WG_DEVICE names
// an interface the test may change, e.g. one made with
// `ip link add cwtest0 type wireguard`.
func TestSweepOnARealDevice(t *testing.T) {
	dev := os.Getenv("CLAIMWARD_TEST_WG_DEVICE")
	if dev == "" {
		t.Skip("CLAIMWARD_TEST_WG_DEVICE not set")
	}
	g, err := NewGateway(dev)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	pool := cidr(t, "10.80.0.0/24")
	ours, theirs := newKey(t), newKey(t)
	if err := g.AddPeer(ours, net.ParseIP("10.80.0.7")); err != nil {
		t.Fatal(err)
	}
	c, err := wgctrl.New()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.ConfigureDevice(dev, wgtypes.Config{Peers: []wgtypes.PeerConfig{{PublicKey: theirs, AllowedIPs: []net.IPNet{cidr(t, "192.168.50.0/24")}}}}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { g.RemovePeer(theirs) })
	n, err := Sweep(g, &pool)
	if err != nil || n != 1 {
		t.Fatalf("swept %d: %v", n, err)
	}
	d, err := c.Device(dev)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Peers) != 1 || d.Peers[0].PublicKey != theirs {
		t.Errorf("left on the device: %+v", d.Peers)
	}
}
