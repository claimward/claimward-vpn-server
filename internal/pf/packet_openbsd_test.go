//go:build openbsd

package pf

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/claimward/claimward-vpn-server/internal/fw"
	"github.com/claimward/claimward-vpn-server/internal/policy"
)

// The packet proof: real packets cross the anchor this package loads. Nothing
// here trusts the encoder's own readback; a rule is right when traffic is
// dropped, passed or MSS-clamped by the kernel.
//
// Topology, all inside one VM (pair(4) interfaces patched back to back, one
// routing domain per host, so that the traffic really crosses pf instead of
// being short-cut through lo0):
//
//	rdomain 1: pair1 10.77.0.2 (tenant a peer), 10.77.0.3 (tenant b peer)
//	rdomain 0: pair0 10.77.0.1  <== the interface the policy filters ("wg0")
//	           pair2 10.78.0.1  (forwarding on)
//	rdomain 2: pair3 10.78.0.2  (the destination, with its listeners)
const (
	pktIface  = "pair0"
	peerA     = "10.77.0.2"
	peerB     = "10.77.0.3"
	destHost  = "10.78.0.2"
	otherDest = "10.78.0.9"
)

func run(t *testing.T, name string, args ...string) {
	t.Helper()
	if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
}

// packetLab builds the topology and returns when it is ready; everything is
// torn down by t.Cleanup.
func packetLab(t *testing.T) {
	t.Helper()
	pfHost(t)
	prev, err := unix.SysctlUint32("net.inet.ip.forwarding")
	if err != nil {
		t.Fatal(err)
	}
	// The loopbacks of the routing domains are created first, so that the
	// cleanup (last in, first out) destroys them last: a domain's lo(4) cannot
	// go while an interface is still in the domain.
	for _, n := range []string{"lo1", "lo2", "pair0", "pair1", "pair2", "pair3"} {
		if exec.Command("ifconfig", n).Run() == nil {
			t.Fatalf("%s exists already; the lab needs its own interfaces", n)
		}
		run(t, "ifconfig", n, "create")
		n := n
		t.Cleanup(func() { _ = exec.Command("ifconfig", n, "destroy").Run() })
	}
	t.Cleanup(func() {
		_ = exec.Command("sysctl", fmt.Sprintf("net.inet.ip.forwarding=%d", prev)).Run()
	})
	run(t, "ifconfig", "lo1", "rdomain", "1", "up")
	run(t, "ifconfig", "lo2", "rdomain", "2", "up")
	run(t, "ifconfig", "pair1", "rdomain", "1")
	run(t, "ifconfig", "pair3", "rdomain", "2")
	run(t, "ifconfig", "pair0", "inet", "10.77.0.1/24", "up")
	run(t, "ifconfig", "pair1", "inet", peerA+"/24", "up")
	run(t, "ifconfig", "pair1", "inet", peerB+"/24", "alias")
	run(t, "ifconfig", "pair2", "inet", "10.78.0.1/24", "up")
	run(t, "ifconfig", "pair3", "inet", destHost+"/24", "up")
	run(t, "ifconfig", "pair0", "patch", "pair1")
	run(t, "ifconfig", "pair2", "patch", "pair3")
	run(t, "route", "-T1", "add", "default", "10.77.0.1")
	run(t, "route", "-T2", "add", "default", "10.78.0.1")
	run(t, "sysctl", "net.inet.ip.forwarding=1")
	setMain(t, "anchor \""+AnchorName+"\"\npass\n")
}

func rtable(n int) func(network, address string, c syscall.RawConn) error {
	return func(_, _ string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RTABLE, n)
		}); err != nil {
			return err
		}
		return serr
	}
}

// serve answers "ok" on TCP and echoes UDP on the given ports, inside rdomain 2.
func serve(t *testing.T, tcpPorts, udpPorts []int) {
	t.Helper()
	lc := net.ListenConfig{Control: rtable(2)}
	for _, p := range tcpPorts {
		l, err := lc.Listen(context.Background(), "tcp4", net.JoinHostPort(destHost, strconv.Itoa(p)))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { l.Close() })
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				_, _ = c.Write([]byte("ok"))
				c.Close()
			}
		}()
	}
	for _, p := range udpPorts {
		pc, err := lc.ListenPacket(context.Background(), "udp4", net.JoinHostPort(destHost, strconv.Itoa(p)))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { pc.Close() })
		go func() {
			buf := make([]byte, 64)
			for {
				n, a, err := pc.ReadFrom(buf)
				if err != nil {
					return
				}
				_, _ = pc.WriteTo(buf[:n], a)
			}
		}()
	}
}

// tcpReaches is whether a connection from src to dst:port is established and
// answered within the timeout.
func tcpReaches(src, dst string, port int, wait time.Duration) bool {
	d := net.Dialer{Control: rtable(1), LocalAddr: &net.TCPAddr{IP: net.ParseIP(src)}, Timeout: wait}
	c, err := d.Dial("tcp4", net.JoinHostPort(dst, strconv.Itoa(port)))
	if err != nil {
		return false
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(wait))
	b, err := io.ReadAll(c)
	return err == nil && string(b) == "ok"
}

func udpReaches(src, dst string, port int, wait time.Duration) bool {
	d := net.Dialer{Control: rtable(1), LocalAddr: &net.UDPAddr{IP: net.ParseIP(src)}}
	c, err := d.Dial("udp4", net.JoinHostPort(dst, strconv.Itoa(port)))
	if err != nil {
		return false
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(wait))
	if _, err := c.Write([]byte("ping")); err != nil {
		return false
	}
	buf := make([]byte, 16)
	n, err := c.Read(buf)
	return err == nil && string(buf[:n]) == "ping"
}

func packetRuleset(mtu int) fw.Ruleset {
	rs := fw.Build(pktIface, []fw.Tenant{
		{ID: "a", Peers: []netip.Addr{netip.MustParseAddr(peerA)}, Rules: []policy.Rule{
			{CIDR: destHost + "/32", Proto: policy.ProtoTCP, Ports: []policy.Port{{Lo: 8000, Hi: 8000}}},
			{CIDR: destHost + "/32", Proto: policy.ProtoUDP, Ports: []policy.Port{{Lo: 5353, Hi: 5353}}},
		}},
		{ID: "b", Peers: []netip.Addr{netip.MustParseAddr(peerB)}, Rules: []policy.Rule{
			{CIDR: otherDest + "/32", Proto: policy.ProtoTCP, Ports: []policy.Port{{Lo: 8000, Hi: 8000}}},
		}},
	})
	if mtu > 0 {
		rs = fw.WithMSSClamp(rs, pktIface, mtu)
	}
	return rs
}

var blockCounter = regexp.MustCompile(`block drop in quick on ` + pktIface + ` all\s+\[ Evaluations: \d+\s+Packets: (\d+)`)

func TestPacketsAreDroppedAndPassedAsThePolicySays(t *testing.T) {
	packetLab(t)
	serve(t, []int{8000, 8001}, []int{5353, 5354})
	if err := NewApplier().Apply(packetRuleset(0)); err != nil {
		t.Fatal(err)
	}
	const wait = 2 * time.Second

	// No rule may carry a translation or a route: a pool left at the wrong
	// address type reads as "nat-to any rdr-to any".
	for _, l := range strings.Split(pfctl(t, "", "-a", AnchorName, "-sr"), "\n") {
		for _, bad := range []string{"nat-to", "rdr-to", "route-to", "reply-to", "dup-to"} {
			if strings.Contains(l, bad) {
				t.Errorf("rule with %s: %s", bad, l)
			}
		}
	}

	// Control: the lab itself works, which a policy that blocks everything
	// would hide. With the anchor emptied there is no filter.
	flushAnchor(AnchorName)
	if !tcpReaches(peerA, destHost, 8001, wait) {
		t.Fatal("the lab does not forward: tcp to 8001 fails with no policy loaded")
	}
	if err := NewApplier().Apply(packetRuleset(0)); err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		name string
		got  func() bool
		want bool
	}{
		{"tenant a tcp to its allowed port", func() bool { return tcpReaches(peerA, destHost, 8000, wait) }, true},
		{"tenant a tcp to a port its policy lacks", func() bool { return tcpReaches(peerA, destHost, 8001, wait) }, false},
		{"tenant a udp to its allowed port", func() bool { return udpReaches(peerA, destHost, 5353, wait) }, true},
		{"tenant a udp to a port its policy lacks", func() bool { return udpReaches(peerA, destHost, 5354, wait) }, false},
		{"tenant b tcp to tenant a's destination and port", func() bool { return tcpReaches(peerB, destHost, 8000, wait) }, false},
		{"tenant b udp to tenant a's udp service", func() bool { return udpReaches(peerB, destHost, 5353, wait) }, false},
	} {
		if got := c.got(); got != c.want {
			t.Errorf("%s: reached = %v, want %v", c.name, got, c.want)
		}
	}

	// The drops are pf's: the final block rule counted packets.
	out := pfctl(t, "", "-a", AnchorName, "-vsr")
	m := blockCounter.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no counter for the final block rule in:\n%s", out)
	}
	if n, _ := strconv.Atoi(m[1]); n == 0 {
		t.Errorf("the final block rule counted no packet:\n%s", out)
	}
}

var mssOption = regexp.MustCompile(`mss (\d+)`)

// synMSS captures, on the interface the forwarded packets LEAVE by (after
// pf), the SYN of a connection from tenant a and returns its MSS option.
func synMSS(t *testing.T) int {
	t.Helper()
	cmd := exec.Command("tcpdump", "-n", "-l", "-i", "pair2", "-c", "1", "tcp[tcpflags] == tcp-syn and dst port 8000")
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdout, cmd.Stderr = w, w
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	w.Close()
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait(); r.Close() }()
	lines := make(chan string, 16)
	go func() {
		s := bufio.NewScanner(r)
		for s.Scan() {
			lines <- s.Text()
		}
		close(lines)
	}()
	var all []string
	ready := time.After(5 * time.Second)
	for listening := false; !listening; {
		select {
		case l, ok := <-lines:
			if !ok {
				t.Fatalf("tcpdump ended before it listened:\n%s", strings.Join(all, "\n"))
			}
			all = append(all, l)
			listening = strings.Contains(l, "listening on")
		case <-ready:
			t.Fatalf("tcpdump did not start listening:\n%s", strings.Join(all, "\n"))
		}
	}
	time.Sleep(500 * time.Millisecond)
	if !tcpReaches(peerA, destHost, 8000, 3*time.Second) {
		t.Fatal("the connection that tcpdump should see did not complete")
	}
	deadline := time.After(8 * time.Second)
	for {
		select {
		case l, ok := <-lines:
			if !ok {
				t.Fatalf("no SYN captured:\n%s", strings.Join(all, "\n"))
			}
			all = append(all, l)
			if m := mssOption.FindStringSubmatch(l); m != nil {
				n, _ := strconv.Atoi(m[1])
				t.Logf("captured SYN: %s", l)
				return n
			}
		case <-deadline:
			t.Fatalf("no SYN with an mss option captured:\n%s", strings.Join(all, "\n"))
		}
	}
}

// The MSS clamp acts on real packets: the SYN that leaves pair2 carries the
// clamped value, and without the clamp it carries the interface's own.
func TestMSSClampActsOnTheWire(t *testing.T) {
	packetLab(t)
	serve(t, []int{8000}, nil)

	if err := NewApplier().Apply(packetRuleset(0)); err != nil {
		t.Fatal(err)
	}
	control := synMSS(t)
	if control != 1460 {
		t.Fatalf("without a clamp the SYN carries mss %d, want the pair(4) default 1460", control)
	}

	const mtu = 1390 // wg0's MTU: the clamp is mtu-40 for IPv4
	if err := NewApplier().Apply(packetRuleset(mtu)); err != nil {
		t.Fatal(err)
	}
	clamped := synMSS(t)
	t.Logf("measured MSS on the wire: %d without the clamp, %d with max-mss from MTU %d", control, clamped, mtu)
	if clamped != mtu-40 {
		t.Errorf("with the clamp the SYN carries mss %d, want %d", clamped, mtu-40)
	}
}
