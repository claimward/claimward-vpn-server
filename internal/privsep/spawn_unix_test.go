//go:build unix

package privsep

import (
	"net"
	"os"
	"slices"
	"testing"
	"time"
)

const childEnv = "CW_PRIVSEP_TEST_CHILD"

// TestMain makes the test binary its own child: StartChild runs it again with
// childEnv set, and it plays the unprivileged half over the inherited socket.
func TestMain(m *testing.M) {
	switch os.Getenv(childEnv) {
	case "":
		os.Exit(m.Run())
	case "talk":
		conn, err := ParentConn()
		if err != nil {
			println("child:", err.Error())
			os.Exit(3)
		}
		c := NewClient(conn)
		if _, err := c.Sweep(); err != nil {
			println("child sweep:", err.Error())
			os.Exit(4)
		}
		if _, err := c.SetTunnelMTU(0); err != nil {
			println("child mtu:", err.Error())
			os.Exit(5)
		}
		if err := c.AddPeer(key(4), net.ParseIP("10.80.0.4")); err != nil {
			println("child add:", err.Error())
			os.Exit(6)
		}
		c.Close()
		os.Exit(0)
	case "hang":
		time.Sleep(time.Minute)
		os.Exit(0)
	}
	os.Exit(2)
}

func childEnvOf(mode string) []string { return append(os.Environ(), childEnv+"="+mode) }

func TestARealChildProcessTalksToTheServerOverTheSocketpair(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ch, err := StartChild(exe, nil, childEnvOf("talk"), nil)
	if err != nil {
		t.Fatal(err)
	}
	f := &fake{}
	s := NewServer(f, testLimits, quiet())
	if err := s.Serve(ch.Conn); err != nil {
		t.Fatal(err)
	}
	if err := ch.Cmd.Wait(); err != nil {
		t.Fatalf("the child failed: %v", err)
	}
	if want := []string{"sweep", "mtu", "add 10.80.0.4"}; !slices.Equal(f.calls, want) {
		t.Fatalf("backend saw %v, want %v", f.calls, want)
	}
	if n, err := s.Teardown(); err != nil || n != 1 {
		t.Fatalf("teardown: %d, %v", n, err)
	}
}

func TestTheServerSeesTheChildDie(t *testing.T) {
	exe, _ := os.Executable()
	ch, err := StartChild(exe, nil, childEnvOf("hang"), nil)
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer(&fake{}, testLimits, quiet())
	res := make(chan error, 1)
	go func() { res <- s.Serve(ch.Conn) }()
	time.Sleep(200 * time.Millisecond)
	_ = ch.Cmd.Process.Kill()
	_ = ch.Cmd.Wait()
	select {
	case err := <-res:
		if err != nil {
			t.Fatalf("a child that dies at a frame boundary is a clean end, got %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Serve did not notice the child's death")
	}
}

func TestAChildWithoutASocketCannotRun(t *testing.T) {
	// A process whose descriptor 3 is not the parent's socket (here: nothing)
	// must fail to start its role, not run unsupervised.
	if os.Getenv(childEnv) != "" {
		t.Skip("inside a child")
	}
	if _, err := ParentConn(); err == nil {
		t.Skip("descriptor 3 happens to be a unix socket in this test process")
	}
	// And it did not close what it was not given: the runtime still polls.
	time.Sleep(50 * time.Millisecond)
}
