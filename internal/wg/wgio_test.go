package wg

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

// walkSet reads a buffer the way wg_ioctl_set (if_wg.c) does, and refuses what
// the kernel, which never looks at a length, would read past the end of: it is
// the model of the kernel half the encoder is tested against.
func walkSet(l ioLayout, buf []byte) ([]peerOp, error) {
	if len(buf) < l.IfaceSize {
		return nil, fmt.Errorf("header: %d bytes", len(buf))
	}
	if buf[0] != 0 {
		return nil, fmt.Errorf("interface flags %#x: the interface must not change", buf[0])
	}
	n := binary.NativeEndian.Uint64(buf[l.IfacePeersCount:])
	off := l.IfaceSize
	var ops []peerOp
	for i := uint64(0); i < n; i++ {
		if off+l.PeerSize > len(buf) {
			return nil, fmt.Errorf("peer %d header past the end", i)
		}
		peer := buf[off : off+l.PeerSize]
		off += l.PeerSize
		flags := binary.NativeEndian.Uint32(peer[l.PeerFlags:])
		if flags&wgPeerHasPublic == 0 {
			return nil, fmt.Errorf("peer %d: no public key flag", i)
		}
		if binary.NativeEndian.Uint32(peer[l.PeerProto:]) != 0 {
			return nil, fmt.Errorf("peer %d: protocol version set", i)
		}
		op := peerOp{Remove: flags&wgPeerRemove != 0}
		copy(op.Public[:], peer[l.PeerPublic:])
		if op.Remove == (flags&wgPeerReplaceAIPs != 0) {
			return nil, fmt.Errorf("peer %d: flags %#x are neither add nor remove", i, flags)
		}
		an := binary.NativeEndian.Uint64(peer[l.PeerAipsCount:])
		for j := uint64(0); j < an; j++ {
			if off+l.AipSize > len(buf) {
				return nil, fmt.Errorf("peer %d address %d past the end", i, j)
			}
			aip := buf[off : off+l.AipSize]
			off += l.AipSize
			if aip[l.AipAf] != afInet {
				return nil, fmt.Errorf("address family %d", aip[l.AipAf])
			}
			cidr := binary.NativeEndian.Uint32(aip[l.AipCidr:])
			if cidr > 32 {
				return nil, fmt.Errorf("cidr %d", cidr)
			}
			op.AIPs = append(op.AIPs, netip.PrefixFrom(netip.AddrFrom4([4]byte(aip[l.AipAddr:l.AipAddr+4])), int(cidr)))
		}
		ops = append(ops, op)
	}
	if off != len(buf) {
		return nil, fmt.Errorf("%d bytes after the last peer", len(buf)-off)
	}
	return ops, nil
}

func key(b byte) (k [wgKeyLen]byte) {
	for i := range k {
		k[i] = b + byte(i)
	}
	return k
}

func TestEncodeAddWithAllowedIPs(t *testing.T) {
	in := []peerOp{{Public: key(1), AIPs: []netip.Prefix{netip.MustParsePrefix("10.80.0.7/32"), netip.MustParsePrefix("192.168.0.0/16")}}}
	buf, err := encodeSet(layout64, in)
	if err != nil {
		t.Fatal(err)
	}
	if want := 80 + 208 + 2*24; len(buf) != want {
		t.Fatalf("len = %d, want %d", len(buf), want)
	}
	// The bytes the kernel finds, at the offsets of if_wg.h.
	if got := binary.NativeEndian.Uint64(buf[72:]); got != 1 {
		t.Errorf("i_peers_count = %d", got)
	}
	if got := binary.NativeEndian.Uint32(buf[80:]); got != wgPeerHasPublic|wgPeerReplaceAIPs {
		t.Errorf("p_flags = %#x", got)
	}
	if got := binary.NativeEndian.Uint64(buf[80+200:]); got != 2 {
		t.Errorf("p_aips_count = %d", got)
	}
	aip0 := buf[80+208:]
	if aip0[0] != 2 || binary.NativeEndian.Uint32(aip0[4:]) != 32 || [4]byte(aip0[8:12]) != [4]byte{10, 80, 0, 7} {
		t.Errorf("first address = % x", aip0[:24])
	}
	out, err := walkSet(layout64, buf)
	if err != nil || !reflect.DeepEqual(out, in) {
		t.Fatalf("round trip: %v, %v", out, err)
	}
}

func TestEncodeRemove(t *testing.T) {
	in := []peerOp{{Public: key(9), Remove: true}}
	buf, err := encodeSet(layout64, in)
	if err != nil {
		t.Fatal(err)
	}
	if want := 80 + 208; len(buf) != want {
		t.Fatalf("len = %d, want %d", len(buf), want)
	}
	if got := binary.NativeEndian.Uint32(buf[80:]); got != wgPeerHasPublic|wgPeerRemove {
		t.Errorf("p_flags = %#x", got)
	}
	out, err := walkSet(layout64, buf)
	if err != nil || !reflect.DeepEqual(out, in) {
		t.Fatalf("round trip: %v, %v", out, err)
	}
}

func TestEncodeRefusals(t *testing.T) {
	many := func(n int) []netip.Prefix {
		out := make([]netip.Prefix, n)
		for i := range out {
			out[i] = netip.MustParsePrefix("10.0.0.1/32")
		}
		return out
	}
	cases := []struct {
		name string
		ops  []peerOp
		want string
	}{
		{"none", nil, "no peer"},
		{"too many peers", make([]peerOp, maxPeerOps+1), "exceed the limit"},
		{"too many addresses", []peerOp{{AIPs: many(maxPeerAIPs + 1)}}, "more than"},
		{"remove with addresses", []peerOp{{Remove: true, AIPs: many(1)}}, "removed and also"},
		{"ipv6", []peerOp{{AIPs: []netip.Prefix{netip.MustParsePrefix("fd00::1/128")}}}, "not an IPv4"},
		{"4in6", []peerOp{{AIPs: []netip.Prefix{netip.MustParsePrefix("::ffff:10.0.0.1/128")}}}, "not an IPv4"},
		{"invalid", []peerOp{{AIPs: []netip.Prefix{{}}}}, "not an IPv4"},
	}
	for _, c := range cases {
		buf, err := encodeSet(layout64, c.ops)
		if err == nil || !strings.Contains(err.Error(), c.want) || buf != nil {
			t.Errorf("%s: got %v (buf %d bytes), want an error with %q", c.name, err, len(buf), c.want)
		}
	}
	// The bounds themselves are accepted.
	if _, err := encodeSet(layout64, []peerOp{{AIPs: many(maxPeerAIPs)}}); err != nil {
		t.Errorf("%d addresses refused: %v", maxPeerAIPs, err)
	}
	if _, err := encodeSet(layout64, make([]peerOp, maxPeerOps)); err != nil {
		t.Errorf("%d peers refused: %v", maxPeerOps, err)
	}
}

// FuzzEncodeSet: whatever the shape asked for, the encoder either refuses or
// produces exactly the bytes the kernel's own walk consumes -- never one more or
// one less, since the kernel trusts the counts and reads no length.
func FuzzEncodeSet(f *testing.F) {
	f.Add([]byte{1, 2, 10, 80, 0, 7, 32})
	f.Add([]byte{0})
	f.Add([]byte{255, 255, 1, 2, 3, 4, 33, 4, 5, 6, 7, 200})
	f.Fuzz(func(t *testing.T, data []byte) {
		var ops []peerOp
		for len(data) >= 2 {
			op := peerOp{Remove: data[0]&1 == 1}
			op.Public = key(data[0])
			n := int(data[1])
			data = data[2:]
			for ; n > 0 && len(data) >= 5; n-- {
				op.AIPs = append(op.AIPs, netip.PrefixFrom(netip.AddrFrom4([4]byte(data[:4])), int(data[4])))
				data = data[5:]
				if len(op.AIPs) > 3*maxPeerAIPs {
					break
				}
			}
			ops = append(ops, op)
			if len(ops) > 2*maxPeerOps {
				break
			}
		}
		buf, err := encodeSet(layout64, ops)
		if err != nil {
			if buf != nil {
				t.Fatalf("an error and %d bytes", len(buf))
			}
			return
		}
		if len(buf) > layout64.IfaceSize+maxPeerOps*(layout64.PeerSize+maxPeerAIPs*layout64.AipSize) {
			t.Fatalf("%d bytes exceed the bound", len(buf))
		}
		out, err := walkSet(layout64, buf)
		if err != nil {
			t.Fatalf("the kernel's walk refuses the encoder's output: %v", err)
		}
		if len(out) != len(ops) {
			t.Fatalf("%d peers in, %d out", len(ops), len(out))
		}
		for i := range ops {
			if out[i].Public != ops[i].Public || out[i].Remove != ops[i].Remove || len(out[i].AIPs) != len(ops[i].AIPs) {
				t.Fatalf("peer %d: %+v became %+v", i, ops[i], out[i])
			}
		}
	})
}
