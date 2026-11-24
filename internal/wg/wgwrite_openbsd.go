package wg

import (
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// hostLayout is the layout the release's own header gave the generator.
var hostLayout = ioLayout{
	IfaceSize: SizeofWgIfaceIO, IfaceFlags: OffIfaceFlags, IfacePeersCount: OffIfacePeersCount,
	PeerSize: SizeofWgPeerIO, PeerFlags: OffPeerFlags, PeerProto: OffPeerProto, PeerPublic: OffPeerPublic,
	PeerAipsCount: OffPeerAipsCount,
	AipSize:       SizeofWgAipIO, AipAf: OffAipAf, AipCidr: OffAipCidr, AipAddr: OffAipAddr,
}

// dataIO is struct wg_data_io. size_t and the pointer are 64 bits wide on the
// supported ports; TestWGLayoutAgainstC compares its size and offsets with C's.
type dataIO struct {
	Name  [unix.IFNAMSIZ]byte
	Size  uintptr
	Iface *byte
}

// ioctlWriter programs a wg(4) interface through SIOCSWG, the call ifconfig(8)
// makes. It needs root: the parent of the privilege-separated server is root.
type ioctlWriter struct{ device string }

func newPeerWriter(device string) peerWriter { return ioctlWriter{device: device} }

func (w ioctlWriter) setPeers(ops []peerOp) error {
	if len(w.device) == 0 || len(w.device) >= unix.IFNAMSIZ {
		return fmt.Errorf("wg: bad interface name %q", w.device)
	}
	buf, err := encodeSet(hostLayout, ops)
	if err != nil {
		return err
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("wg: %w", err)
	}
	defer unix.Close(fd)
	var req dataIO
	copy(req.Name[:], w.device)
	req.Size = uintptr(len(buf))
	req.Iface = &buf[0]
	_, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(SIOCSWG), uintptr(unsafe.Pointer(&req)))
	runtime.KeepAlive(buf)
	if e != 0 {
		return fmt.Errorf("wg: SIOCSWG on %s: %w", w.device, e)
	}
	return nil
}
