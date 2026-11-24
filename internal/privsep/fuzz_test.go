package privsep

import (
	"bytes"
	"io"
	"net/netip"
	"testing"

	"github.com/claimward/claimward-vpn-server/internal/fw"
)

// frame is a request as the child's encoder would write it.
func frame(t *testing.T, r Request) []byte {
	t.Helper()
	body, err := r.encode()
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := WriteFrame(&b, r.Type(), body); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// guard is a Backend that fails the fuzz run if the parent ever lets through
// what Limits forbids: it is the invariant the parent exists to keep.
type guard struct {
	t   *testing.T
	mtu bool
}

func (g *guard) AddPeer(k [KeySize]byte, ip netip.Addr) error {
	if !testLimits.Pool.Contains(ip) || ip == testLimits.Pool.Addr() || k == ([KeySize]byte{}) {
		g.t.Fatalf("add-peer let through %v %x", ip, k)
	}
	return nil
}

func (g *guard) RemovePeer(k [KeySize]byte) error { return nil }
func (g *guard) Sweep() (int, error)              { return 0, nil }
func (g *guard) SetTunnelMTU(m int) (int, error) {
	if m != 0 && (m < testLimits.MinMTU || m > testLimits.MaxMTU) {
		g.t.Fatalf("set-mtu let through %d", m)
	}
	g.mtu = true
	if m == 0 {
		m = 1420
	}
	return m, nil
}

func (g *guard) ApplyTenants(ts []fw.Tenant, mtu int) error {
	if !g.mtu {
		g.t.Fatal("apply before the MTU was set")
	}
	if len(ts) > MaxTenants {
		g.t.Fatalf("%d tenants", len(ts))
	}
	for _, tn := range ts {
		for _, a := range tn.Peers {
			if !testLimits.Pool.Contains(a) {
				g.t.Fatalf("apply let through peer %v", a)
			}
		}
		for _, r := range tn.Rules {
			if err := r.Validate(); err != nil {
				g.t.Fatalf("apply let through rule %+v: %v", r, err)
			}
			if p := netip.MustParsePrefix(r.CIDR); p != p.Masked() {
				g.t.Fatalf("apply let through %s", r.CIDR)
			}
		}
	}
	return nil
}

// FuzzServe feeds the parent's whole read path -- framing, decoding, judging --
// whatever bytes a hostile child writes. It must neither panic, nor
// allocate past what the frame limit and the bytes sent allow, nor reach the
// backend with a request Limits forbids.
func FuzzServe(f *testing.F) {
	pk := key(1)
	f.Add(frame(&testing.T{}, AddPeer{Key: pk, IP: netip.MustParseAddr("10.80.0.2")}))
	f.Add([]byte{0, 0, 0, 2, Version, byte(TypeSweep)})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	f.Add([]byte{0, 0, 0, 6, Version, byte(TypeSetMTU), 0, 0, 5, 0x78})
	f.Add(append([]byte{0, 0, 0, 8, Version, byte(TypeApply)}, 0, 1, 0xff, 0xff, 0xff, 0xff))
	f.Fuzz(func(t *testing.T, in []byte) {
		s := NewServer(&guard{t: t}, testLimits, quiet())
		_ = s.Serve(struct {
			io.Reader
			io.Writer
		}{bytes.NewReader(in), io.Discard})
	})
}

// FuzzDecode is the decoder alone, with the round trip: what Decode accepts
// and Limits allows must encode back to the body it was made from.
func FuzzDecode(f *testing.F) {
	f.Add(uint8(TypeAddPeer), append(make([]byte, 31), 1, 1, 10, 80, 0, 2))
	f.Add(uint8(TypeApply), []byte{0, 1, 0, 0, 0, 1, 10, 80, 0, 5, 0, 1, 10, 0, 0, 0, 24, 1, 1, 0, 80, 0, 80})
	f.Add(uint8(TypeSetMTU), []byte{0, 0, 5, 0x78})
	f.Fuzz(func(t *testing.T, typ uint8, body []byte) {
		r, err := Decode(Type(typ), body)
		if err != nil {
			return
		}
		if err := testLimits.Check(r); err != nil {
			return
		}
		again, err := r.encode()
		if err != nil {
			t.Fatalf("an accepted request does not encode: %v", err)
		}
		if !bytes.Equal(again, body) {
			t.Fatalf("round trip: %x became %x", body, again)
		}
	})
}
