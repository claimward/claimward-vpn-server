package wg

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"unsafe"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		return
	}
	if os.Getenv("CW_REQUIRE_OPENBSD") == "1" {
		t.Fatal("CW_REQUIRE_OPENBSD=1 but not root")
	}
	t.Skip("needs root")
}

// The table the encoder tests ran against on every host is the one the
// generator read from this release's header.
func TestWGLayoutTableIsTheGeneratedOne(t *testing.T) {
	if hostLayout != layout64 {
		t.Fatalf("generated layout %+v differs from the table %+v", hostLayout, layout64)
	}
	if wgKeyLen != WGKeyLen || wgPeerHasPublic != WGPeerHasPublic || wgPeerReplaceAIPs != WGPeerReplaceAIPs ||
		wgPeerRemove != WGPeerRemove || afInet != WGAfInet || WGIfNameSize != 16 {
		t.Fatal("a constant of wgio.go differs from the generated one")
	}
	// Number of SIOCSWG: _IOWR('i', 210, struct wg_data_io): in and out (0xc0),
	// the structure's size, group 'i', number 210.
	if want := uint32(0xc0000000 | SizeofWgDataIO<<16 | 'i'<<8 | 210); SIOCSWG != want {
		t.Fatalf("SIOCSWG = %#x, want %#x", uint32(SIOCSWG), want)
	}
	if SIOCGWG != SIOCSWG+1 {
		t.Fatalf("SIOCGWG = %#x", uint32(SIOCGWG))
	}
	var d dataIO
	if unsafe.Sizeof(d) != SizeofWgDataIO || unsafe.Offsetof(d.Name) != OffDataName ||
		unsafe.Offsetof(d.Size) != OffDataSize || unsafe.Offsetof(d.Iface) != OffDataIface {
		t.Fatalf("dataIO is %d bytes (size at %d, pointer at %d), the kernel's is %d (%d, %d)",
			unsafe.Sizeof(d), unsafe.Offsetof(d.Size), unsafe.Offsetof(d.Iface), SizeofWgDataIO, OffDataSize, OffDataIface)
	}
}

// TestWGLayoutAgainstC compiles a C program against THIS release's
// <net/if_wg.h> and compares every size and offset the encoder uses.
func TestWGLayoutAgainstC(t *testing.T) {
	cc, err := exec.LookPath("cc")
	if err != nil {
		if os.Getenv("CW_REQUIRE_OPENBSD") == "1" {
			t.Fatal("CW_REQUIRE_OPENBSD=1 but no C compiler")
		}
		t.Skip("no C compiler")
	}
	type item struct {
		expr string
		want uintptr
	}
	items := []item{
		{"sizeof(struct wg_data_io)", SizeofWgDataIO}, {"offsetof(struct wg_data_io, wgd_name)", OffDataName},
		{"offsetof(struct wg_data_io, wgd_size)", OffDataSize}, {"offsetof(struct wg_data_io, wgd_interface)", OffDataIface},
		{"sizeof(struct wg_interface_io)", SizeofWgIfaceIO}, {"offsetof(struct wg_interface_io, i_flags)", OffIfaceFlags},
		{"offsetof(struct wg_interface_io, i_peers_count)", OffIfacePeersCount}, {"offsetof(struct wg_interface_io, i_peers)", OffIfacePeers},
		{"sizeof(struct wg_peer_io)", SizeofWgPeerIO}, {"offsetof(struct wg_peer_io, p_flags)", OffPeerFlags},
		{"offsetof(struct wg_peer_io, p_protocol_version)", OffPeerProto}, {"offsetof(struct wg_peer_io, p_public)", OffPeerPublic},
		{"offsetof(struct wg_peer_io, p_aips_count)", OffPeerAipsCount}, {"offsetof(struct wg_peer_io, p_aips)", OffPeerAips},
		{"sizeof(struct wg_aip_io)", SizeofWgAipIO}, {"offsetof(struct wg_aip_io, a_af)", OffAipAf},
		{"offsetof(struct wg_aip_io, a_cidr)", OffAipCidr}, {"offsetof(struct wg_aip_io, a_addr)", OffAipAddr},
		{"sizeof(((struct wg_aip_io *)0)->a_af)", 1}, {"sizeof(((struct wg_aip_io *)0)->a_cidr)", 4},
		{"sizeof(((struct wg_peer_io *)0)->p_flags)", 4}, {"sizeof(((struct wg_peer_io *)0)->p_aips_count)", 8},
		{"sizeof(((struct wg_interface_io *)0)->i_peers_count)", 8},
		{"WG_PEER_HAS_PUBLIC", WGPeerHasPublic}, {"WG_PEER_REPLACE_AIPS", WGPeerReplaceAIPs},
		{"WG_PEER_REMOVE", WGPeerRemove}, {"WG_KEY_LEN", WGKeyLen}, {"AF_INET", WGAfInet},
	}
	var src strings.Builder
	src.WriteString("#include <sys/types.h>\n#include <sys/ioctl.h>\n#include <sys/socket.h>\n#include <sys/time.h>\n" +
		"#include <net/if.h>\n#include <netinet/in.h>\n#include <net/if_wg.h>\n#include <stddef.h>\n#include <stdio.h>\n" +
		"int main(void) {\n")
	for _, it := range items {
		fmt.Fprintf(&src, "printf(\"%%zu\\n\", (size_t)(%s));\n", it.expr)
	}
	src.WriteString("printf(\"%lu\\n\", (unsigned long)SIOCSWG);\nprintf(\"%lu\\n\", (unsigned long)SIOCGWG);\nreturn 0;\n}\n")
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/l.c", []byte(src.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(cc, "-o", dir+"/l", dir+"/l.c").CombinedOutput(); err != nil {
		t.Fatalf("cc: %v\n%s", err, out)
	}
	out, err := exec.Command(dir + "/l").Output()
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Fields(string(out))
	if len(got) != len(items)+2 {
		t.Fatalf("the C program printed %d numbers, want %d", len(got), len(items)+2)
	}
	for i, it := range items {
		n, _ := strconv.ParseUint(got[i], 10, 64)
		if uintptr(n) != it.want {
			t.Errorf("%s: C says %d, Go says %d", it.expr, n, it.want)
		}
	}
	for i, want := range []uint32{SIOCSWG, SIOCGWG} {
		n, _ := strconv.ParseUint(got[len(items)+i], 10, 64)
		if uint32(n) != want {
			t.Errorf("ioctl number %d: C says %#x, Go says %#x", i, n, want)
		}
	}
}

// TestPeersOnARealWireGuardInterface: add, replace and remove a peer on a real
// wg(4) created for the test, and read each state back from the kernel -- by
// wgctrl (SIOCGWG) and by ifconfig(8), which are independent of the writer.
func TestPeersOnARealWireGuardInterface(t *testing.T) {
	requireRoot(t)
	const dev = "wg9"
	if out, err := exec.Command("ifconfig", dev, "create").CombinedOutput(); err != nil {
		t.Fatalf("ifconfig %s create: %v\n%s", dev, err, out)
	}
	t.Cleanup(func() { exec.Command("ifconfig", dev, "destroy").Run() })

	g, err := NewGateway(dev)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	l := g.(Lister)
	k1, _ := wgtypes.GeneratePrivateKey()
	k2, _ := wgtypes.GeneratePrivateKey()
	p1, p2 := k1.PublicKey(), k2.PublicKey()

	if err := g.AddPeer(p1, net.ParseIP("10.80.0.5")); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	if err := g.AddPeer(p2, net.ParseIP("10.80.0.6")); err != nil {
		t.Fatalf("AddPeer 2: %v", err)
	}
	has := func(k wgtypes.Key, ip string) bool {
		t.Helper()
		ps, err := l.Peers()
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range ps {
			if p.PublicKey == k {
				return len(p.AllowedIPs) == 1 && p.AllowedIPs[0].String() == ip+"/32"
			}
		}
		return false
	}
	if !has(p1, "10.80.0.5") || !has(p2, "10.80.0.6") {
		t.Fatal("a peer added is not on the device with its address")
	}
	if out, _ := exec.Command("ifconfig", dev).CombinedOutput(); !strings.Contains(string(out), "10.80.0.5/32") ||
		!strings.Contains(string(out), p1.String()) {
		t.Errorf("ifconfig does not show the peer:\n%s", out)
	}
	// Replace: the same key with another address leaves one address.
	if err := g.AddPeer(p1, net.ParseIP("10.80.0.9")); err != nil {
		t.Fatal(err)
	}
	if !has(p1, "10.80.0.9") {
		t.Error("an added peer did not replace its address")
	}
	// Remove: p1 goes, p2 stays; removing an absent peer is not an error.
	if err := g.RemovePeer(p1); err != nil {
		t.Fatal(err)
	}
	if has(p1, "10.80.0.9") {
		t.Error("a removed peer is still on the device")
	}
	if !has(p2, "10.80.0.6") {
		t.Error("removing one peer removed another")
	}
	if err := g.RemovePeer(p1); err != nil {
		t.Errorf("removing an absent peer: %v", err)
	}
	// The sweep, which reads with wgctrl and removes with the writer.
	_, pool, _ := net.ParseCIDR("10.80.0.0/24")
	if n, err := Sweep(g, pool); err != nil || n != 1 {
		t.Errorf("Sweep removed %d (%v), want 1", n, err)
	}
	if has(p2, "10.80.0.6") {
		t.Error("the sweep left a peer of the pool")
	}
	// A device that is not there is an error, not a silent success.
	bad := ioctlWriter{device: "wg98"}
	if err := bad.setPeers([]peerOp{{Public: key(1), Remove: true}}); err == nil {
		t.Error("SIOCSWG on a missing interface succeeded")
	}
}
