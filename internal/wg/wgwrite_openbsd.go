package wg

import (
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
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

func newPeerWriter(_ *wgctrl.Client, device string) peerWriter { return ioctlWriter{device: device} }

// peers reads the device with SIOCGWG. The kernel answers with the size it
// needs when the buffer is short, so the read grows and retries, within
// maxReadBytes; peers added meanwhile make it retry again, a few times at most.
func (w ioctlWriter) peers() ([]Peer, error) {
	if len(w.device) == 0 || len(w.device) >= unix.IFNAMSIZ {
		return nil, fmt.Errorf("wg: bad interface name %q", w.device)
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("wg: %w", err)
	}
	defer unix.Close(fd)
	size := hostLayout.IfaceSize + 16*hostLayout.PeerSize
	for try := 0; try < 4; try++ {
		buf := make([]byte, size)
		var req dataIO
		copy(req.Name[:], w.device)
		req.Size = uintptr(len(buf))
		req.Iface = &buf[0]
		_, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(SIOCGWG), uintptr(unsafe.Pointer(&req)))
		runtime.KeepAlive(buf)
		if e != 0 {
			return nil, fmt.Errorf("wg: SIOCGWG on %s: %w", w.device, e)
		}
		need := int(req.Size)
		if need > maxReadBytes || need < hostLayout.IfaceSize {
			return nil, fmt.Errorf("wg: SIOCGWG on %s asks for %d bytes", w.device, need)
		}
		if need > len(buf) {
			size = need
			continue
		}
		return decodeGet(hostLayout, buf[:need])
	}
	return nil, fmt.Errorf("wg: SIOCGWG on %s: the device kept changing", w.device)
}

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
