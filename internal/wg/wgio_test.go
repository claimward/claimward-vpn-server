package wg

import (
	"encoding/binary"
	"fmt"
	"net"
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
		{"length 33", []peerOp{{AIPs: []netip.Prefix{netip.PrefixFrom(netip.MustParseAddr("10.0.0.1"), 33)}}}, "not an IPv4"},
		{"length -1", []peerOp{{AIPs: []netip.Prefix{netip.PrefixFrom(netip.MustParseAddr("10.0.0.1"), -1)}}}, "not an IPv4"},
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

// getBuf lays out what SIOCGWG writes: header, then per peer its header and its
// addresses (each given as family, cidr, address bytes).
func getBuf(peers []Peer, fams [][]byte) []byte {
	l := layout64
	buf := make([]byte, l.IfaceSize)
	binary.NativeEndian.PutUint64(buf[l.IfacePeersCount:], uint64(len(peers)))
	for i, p := range peers {
		ph := make([]byte, l.PeerSize)
		copy(ph[l.PeerPublic:], p.PublicKey[:])
		binary.NativeEndian.PutUint64(ph[l.PeerAipsCount:], uint64(len(p.AllowedIPs)))
		buf = append(buf, ph...)
		for j, n := range p.AllowedIPs {
			a := make([]byte, l.AipSize)
			a[l.AipAf] = fams[i][j]
			ones, _ := n.Mask.Size()
			binary.NativeEndian.PutUint32(a[l.AipCidr:], uint32(ones))
			copy(a[l.AipAddr:], n.IP)
			buf = append(buf, a...)
		}
	}
	return buf
}

func TestDecodeGet(t *testing.T) {
	_, n4, _ := net.ParseCIDR("10.80.0.5/32")
	_, n6, _ := net.ParseCIDR("fd00::/64")
	in := []Peer{{PublicKey: key(1), AllowedIPs: []net.IPNet{*n4}}, {PublicKey: key(7), AllowedIPs: []net.IPNet{*n6, *n4}}, {PublicKey: key(9)}}
	out, err := decodeGet(layout64, getBuf(in, [][]byte{{afInet}, {afInet6, afInet}, nil}))
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 3 || out[1].PublicKey != in[1].PublicKey || len(out[0].AllowedIPs) != 1 || len(out[1].AllowedIPs) != 2 || len(out[2].AllowedIPs) != 0 {
		t.Fatalf("decoded %+v", out)
	}
	if out[0].AllowedIPs[0].String() != "10.80.0.5/32" || out[1].AllowedIPs[0].String() != "fd00::/64" || out[1].AllowedIPs[1].String() != "10.80.0.5/32" {
		t.Errorf("addresses: %v %v", out[0].AllowedIPs, out[1].AllowedIPs)
	}
}

func TestDecodeGetRefusals(t *testing.T) {
	_, n4, _ := net.ParseCIDR("10.80.0.5/32")
	one := []Peer{{PublicKey: key(1), AllowedIPs: []net.IPNet{*n4}}}
	good := getBuf(one, [][]byte{{afInet}})
	l := layout64
	bad := func(f func(b []byte)) []byte {
		b := append([]byte(nil), good...)
		f(b)
		return b
	}
	cases := []struct {
		name string
		buf  []byte
		want string
	}{
		{"short header", good[:l.IfaceSize-1], "less than"},
		{"peers past the end", bad(func(b []byte) { binary.NativeEndian.PutUint64(b[l.IfacePeersCount:], 2) }), "cannot fit"},
		{"huge peer count", bad(func(b []byte) { binary.NativeEndian.PutUint64(b[l.IfacePeersCount:], 1<<62) }), "cannot fit"},
		{"addresses past the end", bad(func(b []byte) { binary.NativeEndian.PutUint64(b[l.IfaceSize+l.PeerAipsCount:], 2) }), "past the end"},
		{"truncated address", good[:len(good)-1], "past the end"},
		{"unknown family", bad(func(b []byte) { b[l.IfaceSize+l.PeerSize+l.AipAf] = 99 }), "family"},
		{"cidr 33", bad(func(b []byte) { binary.NativeEndian.PutUint32(b[l.IfaceSize+l.PeerSize+l.AipCidr:], 33) }), "cidr"},
		{"cidr 129", bad(func(b []byte) {
			b[l.IfaceSize+l.PeerSize+l.AipAf] = afInet6
			binary.NativeEndian.PutUint32(b[l.IfaceSize+l.PeerSize+l.AipCidr:], 129)
		}), "cidr"},
	}
	for _, c := range cases {
		out, err := decodeGet(l, c.buf)
		if err == nil || !strings.Contains(err.Error(), c.want) || out != nil {
			t.Errorf("%s: got %v, %v; want an error with %q", c.name, out, err, c.want)
		}
	}
	// The boundary itself decodes: /32 on IPv4 and /128 on IPv6.
	if _, err := decodeGet(l, good); err != nil {
		t.Errorf("good buffer refused: %v", err)
	}
	b6 := bad(func(b []byte) {
		b[l.IfaceSize+l.PeerSize+l.AipAf] = afInet6
		binary.NativeEndian.PutUint32(b[l.IfaceSize+l.PeerSize+l.AipCidr:], 128)
	})
	if _, err := decodeGet(l, b6); err != nil {
		t.Errorf("/128 refused: %v", err)
	}
}

// FuzzDecodeGet: the kernel's answer is untrusted bytes to the decoder; whatever
// they say, it returns peers or an error, and never more peers than bytes.
func FuzzDecodeGet(f *testing.F) {
	_, n4, _ := net.ParseCIDR("10.80.0.5/32")
	f.Add(getBuf([]Peer{{PublicKey: key(1), AllowedIPs: []net.IPNet{*n4}}}, [][]byte{{afInet}}))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		out, err := decodeGet(layout64, data)
		if err != nil {
			if out != nil {
				t.Fatalf("an error and %d peers", len(out))
			}
			return
		}
		if len(out)*layout64.PeerSize > len(data) {
			t.Fatalf("%d peers from %d bytes", len(out), len(data))
		}
	})
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
