//go:build linux

package fw

import (
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"testing"
	"time"

	"github.com/google/nftables"
	"golang.org/x/sys/unix"

	"github.com/claimward/claimward-vpn-server/internal/policy"
)

// maxseg is the TCP_MAXSEG of a connection: the segment size it settled on,
// which the MSS option of the peer's SYN (or SYN/ACK) bounds.
func maxseg(t *testing.T, c net.Conn) int {
	t.Helper()
	// Called from goroutines too: report with Errorf, never Fatal.
	rc, err := c.(*net.TCPConn).SyscallConn()
	if err != nil {
		t.Errorf("SyscallConn: %v", err)
		return 0
	}
	mss := 0
	var gerr error
	if err := rc.Control(func(fd uintptr) {
		mss, gerr = unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_MAXSEG)
	}); err != nil || gerr != nil {
		t.Errorf("TCP_MAXSEG: %v %v", err, gerr)
		return 0
	}
	return mss
}

// mssSeen has the peer namespace connect to addr, where a listener in
// namespace ns (the host when "") accepts, and returns the MSS each end
// settled on: what the server saw of the peer's SYN, and what the peer saw of
// the server's SYN/ACK.
func mssSeen(t *testing.T, ns, addr string) (server, client int) {
	t.Helper()
	got := make(chan int, 1)
	listen := func() {
		l, err := net.Listen("tcp", addr)
		if err != nil {
			t.Error(err)
			got <- 0
			return
		}
		t.Cleanup(func() { l.Close() })
		go func() {
			c, err := l.Accept()
			if err != nil {
				got <- 0
				return
			}
			defer c.Close()
			got <- maxseg(t, c)
			time.Sleep(200 * time.Millisecond)
		}()
	}
	if ns == "" {
		listen()
	} else {
		inNS(t, ns, listen)
	}
	inNS(t, "cwmsspeer", func() {
		c, err := net.DialTimeout("tcp", addr, 3*time.Second)
		if err != nil {
			t.Errorf("dial %s: %v", addr, err)
			return
		}
		defer c.Close()
		client = maxseg(t, c)
	})
	select {
	case server = <-got:
	case <-time.After(3 * time.Second):
		t.Fatalf("no connection reached %s", addr)
	}
	return server, client
}

// A SYN that crosses the wg interface leaves with the MSS the tunnel MTU
// carries, in both directions and on both hooks, and the policy still decides
// what is reachable. Topology (the veth next to the gateway plays wg):
//
//	peer 10.97.0.2 <-cwmss0-> gateway 10.97.0.1 / 10.96.0.1 <-cwmss1-> server 10.96.0.2
//
// Every link is at MTU 1500, so without the clamp both ends settle on an MSS
// of about 1448; the control below proves the probe can tell the difference.
func TestNetnsMSSIsClamped(t *testing.T) {
	needNetns(t)

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	for _, ns := range []string{"cwmsspeer", "cwmsssrv"} {
		exec.Command("ip", "netns", "del", ns).Run()
		ip(t, "netns", "add", ns)
		ns := ns
		t.Cleanup(func() { exec.Command("ip", "netns", "del", ns).Run() })
	}
	t.Cleanup(func() {
		if c, err := nftables.New(); err == nil {
			c.DelTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: TableName})
			c.Flush()
			c.CloseLasting()
		}
	})
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0o644); err != nil {
		t.Fatal(err)
	}
	ip(t, "link", "add", "cwmss0", "type", "veth", "peer", "name", "cwmssp0")
	ip(t, "link", "set", "cwmssp0", "netns", "cwmsspeer")
	ip(t, "link", "add", "cwmss1", "type", "veth", "peer", "name", "cwmsss0")
	ip(t, "link", "set", "cwmsss0", "netns", "cwmsssrv")
	ip(t, "addr", "add", "10.97.0.1/24", "dev", "cwmss0")
	ip(t, "addr", "add", "10.96.0.1/24", "dev", "cwmss1")
	ip(t, "link", "set", "cwmss0", "up")
	ip(t, "link", "set", "cwmss1", "up")
	ip(t, "-n", "cwmsspeer", "addr", "add", "10.97.0.2/24", "dev", "cwmssp0")
	ip(t, "-n", "cwmsspeer", "link", "set", "cwmssp0", "up")
	ip(t, "-n", "cwmsspeer", "route", "add", "10.96.0.0/24", "via", "10.97.0.1")
	ip(t, "-n", "cwmsssrv", "addr", "add", "10.96.0.2/24", "dev", "cwmsss0")
	ip(t, "-n", "cwmsssrv", "link", "set", "cwmsss0", "up")
	ip(t, "-n", "cwmsssrv", "route", "add", "10.97.0.0/24", "via", "10.96.0.1")

	const mtu = 1390
	limit := MSSFor(mtu, false) // 1350
	tenant := Tenant{
		ID:    "meso",
		Peers: []netip.Addr{netip.MustParseAddr("10.97.0.2")},
		Rules: policy.Legacy([]string{"10.96.0.0/24", "10.97.0.1/32"}),
	}
	nft := NewNFT()

	// Control: policy only. The probe must see full-size MSS on both paths.
	if err := nft.Apply(Build("cwmss0", []Tenant{tenant})); err != nil {
		t.Fatal(err)
	}
	if s, c := mssSeen(t, "cwmsssrv", "10.96.0.2:7001"); s <= limit || c <= limit {
		t.Fatalf("control, forwarded: server MSS %d, client MSS %d; want both above %d", s, c, limit)
	}
	if s, _ := mssSeen(t, "", "10.97.0.1:7002"); s <= limit {
		t.Fatalf("control, input: server MSS %d; want above %d", s, limit)
	}

	// With the clamp, in the same atomic table as the policy.
	if err := nft.Apply(WithMSSClamp(Build("cwmss0", []Tenant{tenant}), "cwmss0", mtu)); err != nil {
		t.Fatal(err)
	}
	// Forward, peer to server: the SYN is clamped on arrival, the SYN/ACK on
	// leaving towards the peer.
	if s, c := mssSeen(t, "cwmsssrv", "10.96.0.2:7003"); s > limit || c > limit {
		t.Errorf("forwarded: server MSS %d, client MSS %d; want both at most %d", s, c, limit)
	}
	// Input, peer to the gateway host (445 terminates locally).
	if s, _ := mssSeen(t, "", "10.97.0.1:7004"); s > limit {
		t.Errorf("input: server MSS %d; want at most %d", s, limit)
	}
	// The policy still applies: nothing is allowed that was not.
	ip(t, "-n", "cwmsspeer", "route", "add", "10.95.0.0/24", "via", "10.97.0.1")
	inNS(t, "cwmsspeer", func() {
		if c, err := net.DialTimeout("tcp", "10.95.0.9:80", 500*time.Millisecond); err == nil {
			c.Close()
			t.Error("a destination outside the policy was reachable")
		}
	})
}

// The same clamp for IPv6, which the policy does not forward (it enforces
// IPv4 rules and drops the rest of the interface), so this runs the clamp
// chains alone: they hold no verdict and sit before the policy's chains, which
// is why a ruleset of nothing else is the right place to read their effect.
//
//	peer fd97::2 <-cwms60-> gateway fd97::1 / fd96::1 <-cwms61-> server fd96::2
//
// Every link is at MTU 1500, so an unclamped IPv6 MSS is about 1440.
func TestNetnsMSSIsClampedIPv6(t *testing.T) {
	needNetns(t)

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	for _, ns := range []string{"cwmsspeer", "cwmsssrv"} {
		exec.Command("ip", "netns", "del", ns).Run()
		ip(t, "netns", "add", ns)
		ns := ns
		t.Cleanup(func() { exec.Command("ip", "netns", "del", ns).Run() })
	}
	t.Cleanup(func() {
		if c, err := nftables.New(); err == nil {
			c.DelTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: TableName})
			c.Flush()
			c.CloseLasting()
		}
	})
	if err := os.WriteFile("/proc/sys/net/ipv6/conf/all/forwarding", []byte("1"), 0o644); err != nil {
		t.Fatal(err)
	}
	ip(t, "link", "add", "cwms60", "type", "veth", "peer", "name", "cwmsp60")
	ip(t, "link", "set", "cwmsp60", "netns", "cwmsspeer")
	ip(t, "link", "add", "cwms61", "type", "veth", "peer", "name", "cwmss60")
	ip(t, "link", "set", "cwmss60", "netns", "cwmsssrv")
	// nodad: no 1 s wait for duplicate address detection before the first SYN.
	ip(t, "addr", "add", "fd97::1/64", "dev", "cwms60", "nodad")
	ip(t, "addr", "add", "fd96::1/64", "dev", "cwms61", "nodad")
	ip(t, "link", "set", "cwms60", "up")
	ip(t, "link", "set", "cwms61", "up")
	ip(t, "-n", "cwmsspeer", "addr", "add", "fd97::2/64", "dev", "cwmsp60", "nodad")
	ip(t, "-n", "cwmsspeer", "link", "set", "cwmsp60", "up")
	ip(t, "-n", "cwmsspeer", "route", "add", "fd96::/64", "via", "fd97::1")
	ip(t, "-n", "cwmsssrv", "addr", "add", "fd96::2/64", "dev", "cwmss60", "nodad")
	ip(t, "-n", "cwmsssrv", "link", "set", "cwmss60", "up")
	ip(t, "-n", "cwmsssrv", "route", "add", "fd97::/64", "via", "fd96::1")

	const mtu = 1390
	limit := MSSFor(mtu, true) // 1330
	nft := NewNFT()
	empty := Ruleset{Table: TableName}

	// Control: no clamp. The probe must see the full-size MSS.
	if err := nft.Apply(empty); err != nil {
		t.Fatal(err)
	}
	if s, c := mssSeen(t, "cwmsssrv", "[fd96::2]:7011"); s <= limit || c <= limit {
		t.Fatalf("control, forwarded: server MSS %d, client MSS %d; want both above %d", s, c, limit)
	}
	if s, _ := mssSeen(t, "", "[fd97::1]:7012"); s <= limit {
		t.Fatalf("control, input: server MSS %d; want above %d", s, limit)
	}

	if err := nft.Apply(WithMSSClamp(empty, "cwms60", mtu)); err != nil {
		t.Fatal(err)
	}
	// Forward: the SYN is clamped arriving from the peer, the SYN/ACK leaving
	// towards it.
	if s, c := mssSeen(t, "cwmsssrv", "[fd96::2]:7013"); s > limit || c > limit {
		t.Errorf("forwarded: server MSS %d, client MSS %d; want both at most %d", s, c, limit)
	}
	// Input: the SYN is for the gateway host itself.
	if s, _ := mssSeen(t, "", "[fd97::1]:7014"); s > limit {
		t.Errorf("input: server MSS %d; want at most %d", s, limit)
	}
}
