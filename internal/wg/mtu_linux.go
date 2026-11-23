package wg

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// SetInterfaceMTU sets the MTU of the named interface (SIOCSIFMTU). It needs
// CAP_NET_ADMIN, which the gateway already holds to manage peers.
func SetInterfaceMTU(name string, mtu int) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("set MTU of %s: %w", name, err)
	}
	defer unix.Close(fd)
	req, err := unix.NewIfreq(name)
	if err != nil {
		return fmt.Errorf("set MTU of %s: %w", name, err)
	}
	req.SetUint32(uint32(mtu))
	if err := unix.IoctlIfreq(fd, unix.SIOCSIFMTU, req); err != nil {
		return fmt.Errorf("set MTU of %s to %d: %w", name, mtu, err)
	}
	return nil
}
