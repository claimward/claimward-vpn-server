package privsep

import (
	"bytes"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/claimward/claimward-vpn-server/internal/fw"
	"github.com/claimward/claimward-vpn-server/internal/policy"
)

func TestARuleTruncatedInItsPortsOrItsPrefixIsRefused(t *testing.T) {
	hdr := func(bits, proto, np byte) []byte { return []byte{10, 0, 0, 0, bits, proto, np} }
	one := func(rule ...[]byte) []byte {
		return joinBytes(append([][]byte{u16(1), u32(0), u16(1)}, rule...)...)
	}
	mustFail(t, "port range cut in its first half", TypeApply, one(hdr(8, wireProtoTCP, 2), []byte{0, 80}), "body ends early")
	mustFail(t, "port range cut in its second half", TypeApply, one(hdr(8, wireProtoTCP, 1), []byte{0, 80, 0}), "body ends early")
	mustFail(t, "no port bytes", TypeApply, one(hdr(8, wireProtoUDP, 1)), "body ends early")
	mustFail(t, "prefix of 33 bits", TypeApply, one(hdr(33, wireProtoTCP, 1), []byte{0, 80, 0, 80}), "prefix length")
	mustFail(t, "a rule shorter than its header", TypeApply, one([]byte{10, 0, 0, 0, 8, wireProtoAny}), "holds fewer")
	if _, err := decodeRule(&cursor{b: []byte{10, 0, 0}}); err == nil {
		t.Error("decodeRule read a rule of three bytes")
	}
}

func TestTheAnyRuleIsValidatedLikeTheOthers(t *testing.T) {
	for _, cidr := range []string{"nope", "fd00::/8", ""} {
		if err := validateRule(policy.Rule{CIDR: cidr, Proto: policy.ProtoAny}); err == nil {
			t.Errorf("an any rule to %q passed", cidr)
		}
	}
	if err := validateRule(policy.Rule{CIDR: "10.0.0.0/8", Proto: policy.ProtoAny}); err != nil {
		t.Errorf("a plain any rule: %v", err)
	}
}

func TestLimitsRefuseWhatTheServerWouldNotDo(t *testing.T) {
	if err := testLimits.Check(RemovePeer{}); err == nil || !strings.Contains(err.Error(), "all zero") {
		t.Errorf("remove of the zero key: %v", err)
	}
	out := Apply{Tenants: []fw.Tenant{{Peers: []netip.Addr{netip.MustParseAddr("192.168.0.1")}}}}
	if err := testLimits.Check(out); err == nil || !strings.Contains(err.Error(), "tenant 0") {
		t.Errorf("a peer outside the pool: %v", err)
	}
}

type failingWriter struct{ io.Reader }

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("socket gone") }

// A reply that cannot be written ends the session with the transport's error.
func TestAServerThatCannotAnswerEndsTheSession(t *testing.T) {
	var in bytes.Buffer
	if err := WriteFrame(&in, TypeSweep, nil); err != nil {
		t.Fatal(err)
	}
	s := NewServer(&fake{}, testLimits, quiet())
	err := s.Serve(failingWriter{&in})
	if err == nil || !strings.Contains(err.Error(), "socket gone") {
		t.Fatalf("Serve = %v", err)
	}
}

func TestAMalformedRequestIsRefusedWithTheReasonItWasMalformed(t *testing.T) {
	f := &fake{}
	c, _ := pair(t, f)
	_, err := c.call(rawRequest{typ: TypeAddPeer, body: []byte{1, 2, 3}})
	var ref *RefusedError
	if !errors.As(err, &ref) || !strings.Contains(ref.Msg, "add-peer: body of 3 bytes") {
		t.Fatalf("err = %v", err)
	}
	if f.count() != 0 {
		t.Fatal("the backend heard of it")
	}
}

// rawRequest sends a body as it is, whatever it holds.
type rawRequest struct {
	typ  Type
	body []byte
}

func (r rawRequest) Type() Type              { return r.typ }
func (r rawRequest) encode() ([]byte, error) { return r.body, nil }

func TestAKernelFailureOnRemoveKeepsThePeerAndIsNotARefusal(t *testing.T) {
	f := &fake{}
	c, _ := pair(t, f)
	if err := c.AddPeer(key(1), net.ParseIP("10.80.0.2")); err != nil {
		t.Fatal(err)
	}
	f.failRemove = true
	err := c.RemovePeer(key(1))
	var fe *FailedError
	if !errors.As(err, &fe) {
		t.Fatalf("err = %v, want a kernel failure", err)
	}
	// The peer is still the session's: it can be removed once the kernel agrees.
	f.failRemove = false
	if err := c.RemovePeer(key(1)); err != nil {
		t.Fatalf("the peer was forgotten: %v", err)
	}
}

func TestAnMTUInForceOutsideTheBoundsIsAFailureNotAnAnswer(t *testing.T) {
	for _, mtu := range []int{1279, 9001} {
		f := &fake{mtuOut: mtu}
		c, _ := pair(t, f)
		_, err := c.SetTunnelMTU(1420)
		var fe *FailedError
		if !errors.As(err, &fe) {
			t.Fatalf("mtu %d in force: err = %v", mtu, err)
		}
	}
	for _, mtu := range []int{1280, 9000} {
		f := &fake{mtuOut: mtu}
		c, _ := pair(t, f)
		if got, err := c.SetTunnelMTU(1420); err != nil || got != mtu {
			t.Fatalf("mtu %d in force: %d, %v", mtu, got, err)
		}
	}
}

// brokenConn writes and reads as it is told.
type brokenConn struct {
	rd       io.Reader
	writeErr error
}

func (b brokenConn) Read(p []byte) (int, error)  { return b.rd.Read(p) }
func (b brokenConn) Write(p []byte) (int, error) { return len(p), b.writeErr }
func (brokenConn) Close() error                  { return nil }

func TestTheClientNamesTheStepThatFailed(t *testing.T) {
	t.Run("encode", func(t *testing.T) {
		f := &fake{}
		c, _ := pair(t, f)
		_, err := c.call(AddPeer{IP: netip.MustParseAddr("fd00::1")})
		var ref *RefusedError
		if err == nil || errors.As(err, &ref) || f.count() != 0 {
			t.Fatalf("err = %v, backend calls %v", err, f.calls)
		}
	})
	t.Run("write", func(t *testing.T) {
		// The reply is there to read: only the write fails.
		reply := make([]byte, 0, 8)
		reply = append(reply, 0, 0, 0, 3, Version, byte(TypeSweep)|byte(ReplyFlag), StatusOK)
		c := NewClient(brokenConn{rd: strings.NewReader(string(reply)), writeErr: errors.New("EPIPE")})
		_, err := c.call(Sweep{})
		if err == nil || !strings.Contains(err.Error(), "EPIPE") || !isDone(c) {
			t.Fatalf("err = %v, done %v", err, isDone(c))
		}
	})
	t.Run("read", func(t *testing.T) {
		c := NewClient(brokenConn{rd: strings.NewReader("")})
		_, err := c.call(Sweep{})
		if err == nil || strings.Contains(err.Error(), "unexpected reply") || !isDone(c) {
			t.Fatalf("err = %v, done %v", err, isDone(c))
		}
	})
	t.Run("an address that is not IPv4", func(t *testing.T) {
		c, _ := pair(t, &fake{})
		err := c.AddPeer(key(1), net.ParseIP("fd00::1"))
		if err == nil || !strings.Contains(err.Error(), "is not an IPv4 address") {
			t.Fatalf("err = %v", err)
		}
	})
}
