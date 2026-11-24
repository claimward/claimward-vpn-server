//go:build openbsd

package pf

import (
	"encoding/binary"
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

// devPF is the pf device. Every operation below is an ioctl on it: pfctl is
// never executed.
const devPF = "/dev/pf"

// maxReadRules bounds how many rules of one ruleset are read back, so that a
// ruleset the administrator made enormous cannot make the server allocate
// without end.
const maxReadRules = 1 << 17

// ioctl is one ioctl(2). arg is converted in the call expression, as the
// unsafe.Pointer rules require for a uintptr argument of a system call.
func ioctl(fd int, req uintptr, arg unsafe.Pointer) error {
	_, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), req, uintptr(arg))
	if e != 0 {
		return e
	}
	return nil
}

// setCString writes s and a NUL into dst. C's char is signed on amd64 and
// unsigned on arm64, so the generated char arrays differ per architecture.
func setCString[T ~int8 | ~uint8](dst []T, s string) error {
	if len(s) >= len(dst) {
		return fmt.Errorf("pf: %q does not fit %d bytes with its NUL", s, len(dst))
	}
	for i := range dst {
		dst[i] = 0
	}
	for i := 0; i < len(s); i++ {
		dst[i] = T(s[i])
	}
	return nil
}

// pfRunning is whether pf is enabled (DIOCGETSTATUS).
func pfRunning(fd int) (bool, error) {
	var st PfStatus
	if err := ioctl(fd, DIOCGETSTATUS, unsafe.Pointer(&st)); err != nil {
		return false, fmt.Errorf("pf: DIOCGETSTATUS: %w", err)
	}
	return st.Running != 0, nil
}

// readRules reads every rule of the active ruleset of anchor, as the kernel's
// pfioc_rule bytes. DIOCGETRULES opens a read transaction (its ticket) that
// DIOCGETRULE walks in order and DIOCXEND closes.
func readRules(fd int, anchor string) ([][]byte, error) {
	head := make([]byte, SizeofPfiocRule)
	if len(anchor) >= len(head[OffIocAnchor:OffIocCall]) {
		return nil, fmt.Errorf("pf: anchor %q is too long", anchor)
	}
	copy(head[OffIocAnchor:], anchor)
	if err := ioctl(fd, DIOCGETRULES, unsafe.Pointer(&head[0])); err != nil {
		return nil, fmt.Errorf("pf: DIOCGETRULES %q: %w", anchor, err)
	}
	nr := binary.NativeEndian.Uint32(head[OffIocNr:])
	ticket := binary.NativeEndian.Uint32(head[OffIocTicket:])
	defer func() {
		t := ticket
		_ = ioctl(fd, DIOCXEND, unsafe.Pointer(&t))
	}()
	if nr > maxReadRules {
		return nil, fmt.Errorf("pf: anchor %q holds %d rules (more than %d)", anchor, nr, maxReadRules)
	}
	out := make([][]byte, 0, nr)
	for i := uint32(0); i < nr; i++ {
		b := make([]byte, SizeofPfiocRule)
		copy(b[OffIocAnchor:], anchor)
		binary.NativeEndian.PutUint32(b[OffIocTicket:], ticket)
		binary.NativeEndian.PutUint32(b[OffIocNr:], i)
		if err := ioctl(fd, DIOCGETRULE, unsafe.Pointer(&b[0])); err != nil {
			return nil, fmt.Errorf("pf: DIOCGETRULE %q #%d: %w", anchor, i, err)
		}
		out = append(out, b)
	}
	return out, nil
}

// ifaceFlags is pfik_flags of the pf interface named name, and whether pf knows
// it at all.
func ifaceFlags(fd int, name string) (uint32, bool, error) {
	capacity := 8
	for tries := 0; tries < 4; tries++ {
		buf := make([]byte, capacity*SizeofPfiKif)
		io := PfiocIface{Buffer: &buf[0], Esize: SizeofPfiKif, Size: int32(capacity)}
		if err := setCString(io.Name[:], name); err != nil {
			return 0, false, err
		}
		if err := ioctl(fd, DIOCIGETIFACES, unsafe.Pointer(&io)); err != nil {
			return 0, false, fmt.Errorf("pf: DIOCIGETIFACES: %w", err)
		}
		if int(io.Size) > capacity {
			capacity = int(io.Size) + 8
			continue
		}
		for i := 0; i < int(io.Size); i++ {
			k := buf[i*SizeofPfiKif : (i+1)*SizeofPfiKif]
			if cstring(k[OffKifName:OffKifName+16]) == name {
				return binary.NativeEndian.Uint32(k[OffKifFlags:]), true, nil
			}
		}
		return 0, false, nil
	}
	return 0, false, fmt.Errorf("pf: the interface list kept growing")
}

// readTable is the addresses of one table of anchor, from DIOCRGETADDRS.
func readTable(fd int, anchor, name string, want int) ([]PfrAddr, error) {
	buf := make([]PfrAddr, want+1)
	io := PfiocTable{Buffer: (*byte)(unsafe.Pointer(&buf[0])), Esize: SizeofPfrAddr, Size: int32(len(buf))}
	if err := setCString(io.Table.Anchor[:], anchor); err != nil {
		return nil, err
	}
	if err := setCString(io.Table.Name[:], name); err != nil {
		return nil, err
	}
	if err := ioctl(fd, DIOCRGETADDRS, unsafe.Pointer(&io)); err != nil {
		return nil, fmt.Errorf("pf: DIOCRGETADDRS %s: %w", name, err)
	}
	if int(io.Size) > len(buf) {
		return nil, fmt.Errorf("pf: table %s holds %d addresses, want %d", name, io.Size, want)
	}
	return buf[:io.Size], nil
}
