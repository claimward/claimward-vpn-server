package wg

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ifreqMTU is the OpenBSD struct ifreq (net/if.h) as SIOCSIFMTU reads it: the
// interface name, then the union whose int member ifr_mtu carries the MTU.
// The union is 16 bytes there (struct sockaddr), so the whole struct is the
// 32 bytes the ioctl number 0x8020697f encodes.
type ifreqMTU struct {
	Name [unix.IFNAMSIZ]byte
	MTU  int32
	_    [12]byte
}

// SetInterfaceMTU sets the MTU of the named interface (SIOCSIFMTU). It needs
// root, which the gateway already requires to load its pf ruleset.
func SetInterfaceMTU(name string, mtu int) error {
	if len(name) == 0 || len(name) >= unix.IFNAMSIZ {
		return fmt.Errorf("set MTU of %q: bad interface name", name)
	}
	if mtu <= 0 || mtu > 1<<20 {
		return fmt.Errorf("set MTU of %s: bad MTU %d", name, mtu)
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("set MTU of %s: %w", name, err)
	}
	defer unix.Close(fd)
	var req ifreqMTU
	copy(req.Name[:], name)
	req.MTU = int32(mtu)
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.SIOCSIFMTU), uintptr(unsafe.Pointer(&req))); e != 0 {
		return fmt.Errorf("set MTU of %s to %d: %w", name, mtu, e)
	}
	return nil
}
