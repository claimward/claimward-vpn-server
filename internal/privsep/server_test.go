package privsep

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/claimward/claimward-vpn-server/internal/fw"
	"github.com/claimward/claimward-vpn-server/internal/policy"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type fake struct {
	mu      sync.Mutex
	calls   []string
	applied [][]fw.Tenant
	mtuSeen int
	failAdd bool
	// failRemove makes RemovePeer fail; mtuOut, when set, is the MTU in force
	// whatever was asked.
	failRemove bool
	mtuOut     int
}

func (f *fake) note(s string) { f.mu.Lock(); f.calls = append(f.calls, s); f.mu.Unlock() }

func (f *fake) AddPeer(k [KeySize]byte, ip netip.Addr) error {
	f.note("add " + ip.String())
	if f.failAdd {
		return errors.New("kernel said no")
	}
	return nil
}
func (f *fake) RemovePeer(k [KeySize]byte) error {
	f.note("remove")
	if f.failRemove {
		return errors.New("kernel said no")
	}
	return nil
}
func (f *fake) Sweep() (int, error) { f.note("sweep"); return 3, nil }
func (f *fake) SetTunnelMTU(m int) (int, error) {
	f.note("mtu")
	if m == 0 {
		m = 1420
	}
	if f.mtuOut != 0 {
		m = f.mtuOut
	}
	return m, nil
}
func (f *fake) ApplyTenants(ts []fw.Tenant, mtu int) error {
	f.note("apply")
	f.mtuSeen = mtu
	f.applied = append(f.applied, ts)
	return nil
}

func (f *fake) count() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.calls) }

var testLimits = Limits{Pool: netip.MustParsePrefix("10.80.0.0/24"), MinMTU: 1280, MaxMTU: 9000}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func key(b byte) wgtypes.Key {
	var k wgtypes.Key
	k[0] = b
	k[31] = b
	return k
}

// pair runs a Server over one end of a pipe and returns a Client on the other.
func pair(t *testing.T, f *fake) (*Client, chan error) {
	t.Helper()
	a, b := net.Pipe()
	s := NewServer(f, testLimits, quiet())
	res := make(chan error, 1)
	go func() { res <- s.Serve(a); a.Close() }()
	c := NewClient(b)
	t.Cleanup(func() { c.Close() })
	return c, res
}

func TestARoundTripReachesTheBackend(t *testing.T) {
	f := &fake{}
	c, _ := pair(t, f)
	if n, err := c.Sweep(); err != nil || n != 3 {
		t.Fatalf("sweep: %d, %v", n, err)
	}
	if m, err := c.SetTunnelMTU(0); err != nil || m != 1420 {
		t.Fatalf("mtu: %d, %v", m, err)
	}
	if err := c.AddPeer(key(1), net.ParseIP("10.80.0.2")); err != nil {
		t.Fatal(err)
	}
	ts := []fw.Tenant{
		{ID: "b", Peers: []netip.Addr{netip.MustParseAddr("10.80.0.3")}},
		{ID: "a", Peers: []netip.Addr{netip.MustParseAddr("10.80.0.2")}, Rules: []policy.Rule{{CIDR: "10.0.0.0/24", Proto: "tcp", Ports: []policy.Port{{Lo: 445, Hi: 445}, {Lo: 8000, Hi: 8100}}}}},
	}
	if err := c.ApplyTenants(ts); err != nil {
		t.Fatal(err)
	}
	if f.mtuSeen != 1420 || len(f.applied) != 1 || len(f.applied[0]) != 2 {
		t.Fatalf("apply saw mtu %d, %d sets", f.mtuSeen, len(f.applied))
	}
	// Sorted by the child's ID, numbered by the parent: the text never crosses.
	got := f.applied[0]
	if got[0].ID != "00000000" || len(got[0].Rules) != 1 || got[0].Rules[0].CIDR != "10.0.0.0/24" || len(got[0].Rules[0].Ports) != 2 {
		t.Fatalf("first tenant: %+v", got[0])
	}
	if err := c.RemovePeer(key(1)); err != nil {
		t.Fatal(err)
	}
}

// refusedWithNoEffect sends a request the parent must refuse and checks that
// the backend never heard of it and the session still stands.
func refusedWithNoEffect(t *testing.T, f *fake, c *Client, name string, req Request) {
	t.Helper()
	before := f.count()
	_, err := c.call(req)
	var ref *RefusedError
	if !errors.As(err, &ref) {
		t.Fatalf("%s: got %v, want a refusal", name, err)
	}
	if f.count() != before {
		t.Fatalf("%s: the backend was called: %v", name, f.calls[before:])
	}
}

func TestTheParentRefusesWhatIsNotInTheAllowlist(t *testing.T) {
	f := &fake{}
	c, _ := pair(t, f)
	good := netip.MustParseAddr("10.80.0.9")
	cases := []struct {
		name string
		req  Request
	}{
		{"peer outside the pool", AddPeer{Key: key(1), IP: netip.MustParseAddr("192.168.1.5")}},
		{"peer at the network address", AddPeer{Key: key(1), IP: netip.MustParseAddr("10.80.0.0")}},
		{"zero key", AddPeer{IP: good}},
		{"remove a peer it never added", RemovePeer{Key: key(7)}},
		{"remove the zero key", RemovePeer{}},
		{"MTU below the minimum", SetMTU{MTU: 600}},
		{"MTU above the maximum", SetMTU{MTU: 65000}},
		{"apply before the MTU is set", Apply{}},
		{"peer in a table outside the pool", func() Request {
			return Apply{Tenants: []fw.Tenant{{Peers: []netip.Addr{netip.MustParseAddr("8.8.8.8")}}}}
		}()},
	}
	for _, tc := range cases {
		refusedWithNoEffect(t, f, c, tc.name, tc.req)
	}
	// With the MTU set, the apply-specific refusals (a new session: the first
	// one spent most of its MaxRefusals).
	f = &fake{}
	c, _ = pair(t, f)
	if _, err := c.SetTunnelMTU(1400); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		body []byte
	}{
		{"a prefix with host bits set", applyBody(netip.MustParseAddr("10.0.0.1"), 24, 1, 1, [][2]uint16{{80, 80}})},
		{"prefix length 33", applyBody(netip.MustParseAddr("10.0.0.0"), 33, 1, 1, [][2]uint16{{80, 80}})},
		{"protocol 9", applyBody(netip.MustParseAddr("10.0.0.0"), 24, 9, 1, [][2]uint16{{80, 80}})},
		{"port 0", applyBody(netip.MustParseAddr("10.0.0.0"), 24, 1, 1, [][2]uint16{{0, 80}})},
		{"backwards range", applyBody(netip.MustParseAddr("10.0.0.0"), 24, 1, 1, [][2]uint16{{90, 80}})},
		{"no ports", applyBody(netip.MustParseAddr("10.0.0.0"), 24, 1, 1, nil)},
	} {
		before := f.count()
		if _, err := c.rawCall(TypeApply, tc.body); !isRefused(err) {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if f.count() != before {
			t.Fatalf("%s: the backend was called", tc.name)
		}
	}
	// A second SetMTU and a late Sweep.
	refusedWithNoEffect(t, f, c, "second set-mtu", SetMTU{MTU: 1300})
	if err := c.AddPeer(key(2), net.ParseIP("10.80.0.9")); err != nil {
		t.Fatal(err)
	}
	refusedWithNoEffect(t, f, c, "sweep after a peer", Sweep{})
	// The address of one peer is not another's.
	refusedWithNoEffect(t, f, c, "address of another peer", AddPeer{Key: key(3), IP: good})
}

func isRefused(err error) bool { var r *RefusedError; return errors.As(err, &r) }

// rawCall sends a body as it is: a hostile child does not use Client's encoders.
func (c *Client) rawCall(t Type, body []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := WriteFrame(c.rw, t, body); err != nil {
		return nil, err
	}
	rt, reply, err := ReadFrame(c.rw)
	if err != nil {
		return nil, err
	}
	if rt != t|ReplyFlag || len(reply) < 1 {
		return nil, errors.New("bad reply")
	}
	switch reply[0] {
	case StatusOK:
		return reply[1:], nil
	case StatusRefused:
		return nil, &RefusedError{Msg: string(reply[1:])}
	}
	return nil, &FailedError{Msg: string(reply[1:])}
}

func applyBody(dst netip.Addr, bits, proto, nports int, ports [][2]uint16) []byte {
	b := binary.BigEndian.AppendUint16(nil, 1) // one tenant
	b = binary.BigEndian.AppendUint32(b, 1)    // one peer
	b = append(b, 10, 80, 0, 5)
	b = binary.BigEndian.AppendUint16(b, 1) // one rule
	a := dst.As4()
	b = append(b, a[:]...)
	b = append(b, byte(bits), byte(proto), byte(len(ports)))
	for _, p := range ports {
		b = binary.BigEndian.AppendUint16(b, p[0])
		b = binary.BigEndian.AppendUint16(b, p[1])
	}
	return b
}

func TestAMalformedBodyIsRefusedAndTheSessionGoesOn(t *testing.T) {
	f := &fake{}
	c, _ := pair(t, f)
	for name, tc := range map[string]struct {
		t    Type
		body []byte
	}{
		"add-peer short":          {TypeAddPeer, make([]byte, 35)},
		"add-peer with an IPv6":   {TypeAddPeer, make([]byte, 32+16)},
		"remove-peer long":        {TypeRemovePeer, make([]byte, 33)},
		"sweep with a body":       {TypeSweep, []byte{1}},
		"mtu of three bytes":      {TypeSetMTU, []byte{0, 0, 5}},
		"apply truncated":         {TypeApply, []byte{0, 1, 0, 0}},
		"apply, 4G peers claimed": {TypeApply, []byte{0, 1, 0xff, 0xff, 0xff, 0xff, 0, 0}},
		"apply, trailing bytes":   {TypeApply, []byte{0, 0, 9}},
		"apply, 60000 tenants":    {TypeApply, []byte{0xea, 0x60}},
		"unknown type 0":          {0, nil},
		"unknown type 6":          {6, nil},
		"unknown type 99":         {99, []byte{1, 2, 3}},
	} {
		if _, err := c.rawCall(tc.t, tc.body); !isRefused(err) {
			t.Errorf("%s: got %v, want a refusal", name, err)
		}
	}
	if f.count() != 0 {
		t.Fatalf("the backend was called: %v", f.calls)
	}
	// Still in step: a good request works.
	if _, err := c.SetTunnelMTU(1400); err != nil {
		t.Fatalf("the session did not survive refusals: %v", err)
	}
}

func TestABrokenStreamEndsTheSession(t *testing.T) {
	huge := make([]byte, 4)
	binary.BigEndian.PutUint32(huge, MaxFrame+1)
	for name, raw := range map[string][]byte{
		"oversized frame":    huge,
		"length 1":           {0, 0, 0, 1, Version},
		"length 0":           {0, 0, 0, 0},
		"another version":    {0, 0, 0, 2, 9, byte(TypeSweep)},
		"a reply as request": {0, 0, 0, 2, Version, byte(TypeSweep | ReplyFlag)},
		"truncated header":   {0, 0},
		"truncated body":     {0, 0, 0, 40, Version, 1, 2},
	} {
		f := &fake{}
		s := NewServer(f, testLimits, quiet())
		err := s.Serve(struct {
			io.Reader
			io.Writer
		}{bytes.NewReader(raw), io.Discard})
		var pe *ProtocolError
		if !errors.As(err, &pe) {
			t.Errorf("%s: got %v, want a protocol error", name, err)
		}
		if f.count() != 0 {
			t.Errorf("%s: the backend was called", name)
		}
	}
}

func TestOversizedFramesAreNotAllocated(t *testing.T) {
	// A header that announces MaxFrame+1 must be refused from the header alone:
	// there is no body behind it to read.
	hdr := binary.BigEndian.AppendUint32(nil, MaxFrame+1)
	_, _, err := ReadFrame(bytes.NewReader(hdr))
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("got %v", err)
	}
	if err := WriteFrame(io.Discard, TypeApply, make([]byte, MaxFrame)); err == nil {
		t.Fatal("a frame over the limit was written")
	}
}

func TestACleanEndIsNotAnError(t *testing.T) {
	s := NewServer(&fake{}, testLimits, quiet())
	if err := s.Serve(struct {
		io.Reader
		io.Writer
	}{bytes.NewReader(nil), io.Discard}); err != nil {
		t.Fatal(err)
	}
}

func TestAChildThatKeepsAskingForWhatItMayNotHaveIsCutOff(t *testing.T) {
	f := &fake{}
	c, res := pair(t, f)
	var last error
	for i := 0; i < MaxRefusals+2; i++ {
		_, last = c.call(RemovePeer{Key: key(9)})
		if last != nil && !isRefused(last) {
			break
		}
	}
	select {
	case err := <-res:
		if !errors.Is(err, ErrTooManyRefusals) {
			t.Fatalf("session ended with %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the session was not cut off")
	}
	if f.count() != 0 {
		t.Fatalf("backend called: %v", f.calls)
	}
}

func TestAKernelFailureIsNotARefusal(t *testing.T) {
	f := &fake{failAdd: true}
	c, _ := pair(t, f)
	err := c.AddPeer(key(1), net.ParseIP("10.80.0.2"))
	var fe *FailedError
	if !errors.As(err, &fe) {
		t.Fatalf("got %v", err)
	}
	// The peer was not added, so it cannot be removed (and is not torn down).
	if err := c.RemovePeer(key(1)); !isRefused(err) {
		t.Fatalf("got %v", err)
	}
}

func TestTeardownRemovesWhatTheSessionAdded(t *testing.T) {
	f := &fake{}
	s := NewServer(f, testLimits, quiet())
	a, b := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- s.Serve(a) }()
	c := NewClient(b)
	for i := byte(1); i <= 3; i++ {
		if err := c.AddPeer(key(i), net.ParseIP("10.80.0."+string('0'+rune(i)))); err != nil {
			t.Fatal(err)
		}
	}
	c.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if n, err := s.Teardown(); err != nil || n != 3 {
		t.Fatalf("teardown removed %d: %v", n, err)
	}
	if n, _ := s.Teardown(); n != 0 {
		t.Fatalf("second teardown removed %d", n)
	}
}

func TestACallAfterTheSessionEndedFails(t *testing.T) {
	c, _ := pair(t, &fake{})
	c.Close()
	if _, err := c.Sweep(); !errors.Is(err, ErrClosed) {
		t.Fatalf("got %v", err)
	}
	select {
	case <-c.Done():
	default:
		t.Fatal("Done is not closed")
	}
}

func TestTheClientIsAGatewayAndATenantApplier(t *testing.T) {
	var _ interface {
		AddPeer(wgtypes.Key, net.IP) error
		RemovePeer(wgtypes.Key) error
		io.Closer
	} = (*Client)(nil)
	var _ fw.TenantApplier = (*Client)(nil)
}
