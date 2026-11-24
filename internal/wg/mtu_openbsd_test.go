package wg

import (
	"net"
	"os"
	"os/exec"
	"testing"
	"unsafe"
)

// The hand-written ifreq must be the 32 bytes SIOCSIFMTU's number encodes.
func TestIfreqMTUSize(t *testing.T) {
	if n := unsafe.Sizeof(ifreqMTU{}); n != 32 {
		t.Fatalf("sizeof(ifreqMTU) = %d, want 32", n)
	}
}

// SetInterfaceMTU on a real interface: a vether(4) created for the test and
// destroyed after it. CW_REQUIRE_OPENBSD=1 (the VM lane) turns a skip into a
// failure.
func TestSetInterfaceMTUOnARealLink(t *testing.T) {
	if os.Geteuid() != 0 {
		if os.Getenv("CW_REQUIRE_OPENBSD") == "1" {
			t.Fatal("CW_REQUIRE_OPENBSD=1 but not root")
		}
		t.Skip("needs root")
	}
	if out, err := exec.Command("ifconfig", "vether9", "create").CombinedOutput(); err != nil {
		t.Fatalf("ifconfig vether9 create: %v\n%s", err, out)
	}
	t.Cleanup(func() { exec.Command("ifconfig", "vether9", "destroy").Run() })
	for _, mtu := range []int{1390, 1280} {
		if err := SetInterfaceMTU("vether9", mtu); err != nil {
			t.Fatal(err)
		}
		ifc, err := net.InterfaceByName("vether9")
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
