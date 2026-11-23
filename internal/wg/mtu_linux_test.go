package wg

import (
	"net"
	"os"
	"os/exec"
	"testing"
)

// SetInterfaceMTU on a real interface (root, Linux): a dummy link in a fresh
// network namespace, so the host's own network is never touched. In the
// privileged CI lane CW_REQUIRE_NETNS=1 turns a skip into a failure.
func TestSetInterfaceMTUOnARealLink(t *testing.T) {
	why := ""
	if os.Geteuid() != 0 {
		why = "needs root"
	} else if _, err := exec.LookPath("ip"); err != nil {
		why = "needs iproute2"
	}
	if why != "" {
		if os.Getenv("CW_REQUIRE_NETNS") == "1" {
			t.Fatalf("CW_REQUIRE_NETNS=1 but: %s", why)
		}
		t.Skip(why)
	}
	// Run the body in a child of this test binary inside a new namespace.
	if os.Getenv("CW_MTU_CHILD") == "1" {
		mtuChild(t)
		return
	}
	cmd := exec.Command("unshare", "--net", os.Args[0], "-test.run", "^TestSetInterfaceMTUOnARealLink$", "-test.v")
	cmd.Env = append(os.Environ(), "CW_MTU_CHILD=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("child in a new network namespace: %v\n%s", err, out)
	}
}

func mtuChild(t *testing.T) {
	t.Helper()
	for _, a := range [][]string{
		{"link", "add", "cwmtu0", "type", "dummy"},
		{"link", "set", "cwmtu0", "up"},
	} {
		if out, err := exec.Command("ip", a...).CombinedOutput(); err != nil {
			t.Fatalf("ip %v: %v\n%s", a, err, out)
		}
	}
	for _, mtu := range []int{1390, 1280} {
		if err := SetInterfaceMTU("cwmtu0", mtu); err != nil {
			t.Fatal(err)
		}
		ifc, err := net.InterfaceByName("cwmtu0")
		if err != nil {
			t.Fatal(err)
		}
		if ifc.MTU != mtu {
			t.Errorf("MTU after SetInterfaceMTU(%d) = %d", mtu, ifc.MTU)
		}
	}
	if err := SetInterfaceMTU("cwnosuch0", 1400); err == nil {
		t.Error("SetInterfaceMTU on a missing interface succeeded")
	}
}
