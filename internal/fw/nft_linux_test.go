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

// needNetns decides whether the integration test can run. It is skipped with
// a reason when the machine cannot, and FAILS instead when CW_REQUIRE_NETNS=1
// (the privileged CI lane): a lane that is meant to run it must not skip it.
func needNetns(t *testing.T) {
	t.Helper()
	why := ""
	switch {
	case os.Geteuid() != 0:
		why = "needs root (CAP_NET_ADMIN) to create network namespaces and install nftables rules"
	default:
		if _, err := exec.LookPath("ip"); err != nil {
			why = "needs the iproute2 `ip` command to set up the test network"
		}
	}
	if why == "" {
		return
	}
	if os.Getenv("CW_REQUIRE_NETNS") == "1" {
		t.Fatalf("CW_REQUIRE_NETNS=1 but: %s", why)
	}
	t.Skipf("netns integration test skipped: %s (run as root, or CW_REQUIRE_NETNS=1 in the privileged CI lane)", why)
}

func ip(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
		t.Fatalf("ip %v: %v\n%s", args, err, out)
	}
}

// inNS runs fn on a thread that is in the named network namespace, then puts
// the thread back. Sockets made inside stay in that namespace.
func inNS(t *testing.T, name string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		runtime.LockOSThread()
		orig, err := os.Open("/proc/thread-self/ns/net")
		if err != nil {
			t.Error(err)
			return // thread stays locked: it dies with the goroutine
		}
		defer orig.Close()
		target, err := os.Open("/var/run/netns/" + name)
		if err != nil {
			t.Error(err)
			runtime.UnlockOSThread()
			return
		}
		defer target.Close()
		if err := unix.Setns(int(target.Fd()), unix.CLONE_NEWNET); err != nil {
			t.Error(err)
			runtime.UnlockOSThread()
			return
		}
		fn()
		if err := unix.Setns(int(orig.Fd()), unix.CLONE_NEWNET); err != nil {
			t.Error(err)
			return // never hand a thread in the wrong namespace back to the pool
		}
		runtime.UnlockOSThread()
	}()
	<-done
}

func serveTCP(t *testing.T, ns, addr string) {
	t.Helper()
	listen := func() {
		l, err := net.Listen("tcp", addr)
		if err != nil {
			t.Error(err)
			return
		}
		t.Cleanup(func() { l.Close() })
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				c.Close()
			}
		}()
	}
	if ns == "" {
		listen()
		return
	}
	inNS(t, ns, listen)
}

func serveUDP(t *testing.T, ns, addr string) {
	t.Helper()
	listen := func() {
		c, err := net.ListenPacket("udp", addr)
		if err != nil {
			t.Error(err)
			return
		}
		t.Cleanup(func() { c.Close() })
		go func() {
			buf := make([]byte, 64)
			for {
				n, from, err := c.ReadFrom(buf)
				if err != nil {
					return
				}
				c.WriteTo(buf[:n], from)
			}
		}()
	}
	if ns == "" {
		listen()
		return
	}
	inNS(t, ns, listen)
}

// reach is whether the peer namespace can talk to proto://addr within d.
func reach(t *testing.T, proto, addr string, d time.Duration) bool {
	t.Helper()
	ok := false
	inNS(t, "cwpeer", func() {
		c, err := net.DialTimeout(proto, addr, d)
		if err != nil {
			return
		}
		defer c.Close()
		if proto == "tcp" {
			ok = true
			return
		}
		c.SetDeadline(time.Now().Add(d))
		if _, err := c.Write([]byte("ping")); err != nil {
			return
		}
		buf := make([]byte, 8)
		n, err := c.Read(buf)
		ok = err == nil && n == 4
	})
	return ok
}

// The whole point: a peer in a namespace of its own, behind a veth pair that
// plays the wg interface, reaches exactly what its tenant's policy names --
// on a forwarded destination (another namespace) and on the gateway host
// itself -- and nothing else.
func TestNetnsPolicyIsEnforced(t *testing.T) {
	needNetns(t)

	runtime.LockOSThread() // the host namespace's thread, for the netlink calls below
	defer runtime.UnlockOSThread()

	for _, ns := range []string{"cwpeer", "cwsrv"} {
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

	// peer (10.99.0.2) <-cwtest0-> gateway (10.99.0.1 / 10.98.0.1) <-cwtest1-> server (10.98.0.2)
	ip(t, "link", "add", "cwtest0", "type", "veth", "peer", "name", "cwpeer0")
	ip(t, "link", "set", "cwpeer0", "netns", "cwpeer")
	ip(t, "link", "add", "cwtest1", "type", "veth", "peer", "name", "cwsrv0")
	ip(t, "link", "set", "cwsrv0", "netns", "cwsrv")
	ip(t, "addr", "add", "10.99.0.1/24", "dev", "cwtest0")
	ip(t, "addr", "add", "10.98.0.1/24", "dev", "cwtest1")
	ip(t, "link", "set", "cwtest0", "up")
	ip(t, "link", "set", "cwtest1", "up")
	ip(t, "-n", "cwpeer", "addr", "add", "10.99.0.2/24", "dev", "cwpeer0")
	ip(t, "-n", "cwpeer", "link", "set", "cwpeer0", "up")
	ip(t, "-n", "cwpeer", "link", "set", "lo", "up")
	ip(t, "-n", "cwpeer", "route", "add", "10.98.0.0/24", "via", "10.99.0.1")
	ip(t, "-n", "cwsrv", "addr", "add", "10.98.0.2/24", "dev", "cwsrv0")
	ip(t, "-n", "cwsrv", "link", "set", "cwsrv0", "up")
	ip(t, "-n", "cwsrv", "link", "set", "lo", "up")
	ip(t, "-n", "cwsrv", "route", "add", "10.99.0.0/24", "via", "10.98.0.1")

	// Services on every port the matrix asks about, so that a refusal can only
	// be the firewall's.
	for _, p := range []string{"445", "446", "88", "2222", "9005", "9011"} {
		serveTCP(t, "cwsrv", "10.98.0.2:"+p)
		serveTCP(t, "", "10.99.0.1:"+p)
	}
	for _, p := range []string{"88", "445", "53"} {
		serveUDP(t, "cwsrv", "10.98.0.2:"+p)
		serveUDP(t, "", "10.99.0.1:"+p)
	}

	rules, err := policy.Parse([]byte(`[
		{"cidr":"10.98.0.2/32","proto":"tcp","ports":[445]},
		{"cidr":"10.98.0.0/24","proto":"tcp","ports":["9000-9010"]},
		{"cidr":"10.99.0.1/32","proto":"tcp","ports":[445,88]},
		{"cidr":"10.99.0.1/32","proto":"udp","ports":[88]}]`))
	if err != nil {
		t.Fatal(err)
	}
	peer := netip.MustParseAddr("10.99.0.2")
	nft := NewNFT()
	apply := func(peers ...netip.Addr) {
		t.Helper()
		if err := nft.Apply(Build("cwtest0", []Tenant{{ID: "meso", Peers: peers, Rules: rules}})); err != nil {
			t.Fatal(err)
		}
	}

	type probe struct {
		proto, addr string
		allowed     bool
	}
	probes := []probe{
		// forwarded to the file server
		{"tcp", "10.98.0.2:445", true},
		{"tcp", "10.98.0.2:9005", true}, // in the range, through the /24 mask
		{"tcp", "10.98.0.2:9011", false},
		{"tcp", "10.98.0.2:446", false},
		{"tcp", "10.98.0.2:2222", false},
		{"udp", "10.98.0.2:88", false}, // tcp-only there
		{"udp", "10.98.0.2:445", false},
		// to the gateway host itself (INPUT)
		{"tcp", "10.99.0.1:445", true},
		{"tcp", "10.99.0.1:88", true},
		{"udp", "10.99.0.1:88", true},
		{"tcp", "10.99.0.1:2222", false},
		{"udp", "10.99.0.1:53", false},
		{"udp", "10.99.0.1:445", false},
	}
	check := func(label string) {
		t.Helper()
		for _, p := range probes {
			d := 400 * time.Millisecond
			if p.allowed {
				d = 3 * time.Second // the first packets wait for ARP
			}
			if got := reach(t, p.proto, p.addr, d); got != p.allowed {
				t.Errorf("%s: %s %s reachable=%v, want %v", label, p.proto, p.addr, got, p.allowed)
			}
		}
	}

	apply(peer)
	check("peer enrolled")

	// The peer leaves: the table is replaced (second Apply over the first).
	apply()
	for _, p := range probes {
		if reach(t, p.proto, p.addr, 400*time.Millisecond) {
			t.Errorf("peer removed: %s %s still reachable", p.proto, p.addr)
		}
	}

	// And back.
	apply(peer)
	check("peer enrolled again")
}
