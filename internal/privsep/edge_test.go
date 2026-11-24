package privsep

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/claimward/claimward-vpn-server/internal/fw"
	"github.com/claimward/claimward-vpn-server/internal/policy"
)

// joinBytes builds the body of an Apply by hand, so a test can say what the
// encoder would never write.
func joinBytes(parts ...[]byte) []byte {
	var b []byte
	for _, p := range parts {
		b = append(b, p...)
	}
	return b
}

func u16(v int) []byte { return binary.BigEndian.AppendUint16(nil, uint16(v)) }
func u32(v int) []byte { return binary.BigEndian.AppendUint32(nil, uint32(v)) }

func mustFail(t *testing.T, name string, typ Type, body []byte, want string) {
	t.Helper()
	_, err := Decode(typ, body)
	if err == nil {
		t.Fatalf("%s: decoded, want an error with %q", name, want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("%s: error %q, want it to hold %q", name, err, want)
	}
}

func TestDecodeSaysWhichShapeIsWrong(t *testing.T) {
	k := make([]byte, KeySize)
	rule := []byte{10, 0, 0, 0, 8, wireProtoTCP, 1, 0, 80, 0, 80}
	cases := []struct {
		name string
		typ  Type
		body []byte
		want string
	}{
		{"add-peer short", TypeAddPeer, joinBytes(k, []byte{10, 80, 0}), "add-peer"},
		{"add-peer long", TypeAddPeer, joinBytes(k, []byte{10, 80, 0, 1, 1}), "add-peer"},
		{"remove-peer short", TypeRemovePeer, k[:KeySize-1], "remove-peer"},
		{"remove-peer long", TypeRemovePeer, append(append([]byte(nil), k...), 0), "remove-peer"},
		{"apply empty", TypeApply, nil, "body ends early"},
		{"too many tenants", TypeApply, u16(MaxTenants + 1), "exceed the limit"},
		{"tenant without a peer count", TypeApply, joinBytes(u16(1), []byte{0, 0}), "tenant 0"},
		{"peer count beyond the bytes", TypeApply, joinBytes(u16(1), u32(1)), "holds fewer"},
		{"too many peers", TypeApply, joinBytes(u16(1), u32(MaxPeers+1), make([]byte, 4*(MaxPeers+1))), "more than"},
		{"tenant without a rule count", TypeApply, joinBytes(u16(1), u32(0), []byte{0}), "body ends early"},
		{"too many rules", TypeApply, joinBytes(u16(1), u32(0), u16(MaxRulesPerTenant+1)), "exceed the limit"},
		{"rule count beyond the bytes", TypeApply, joinBytes(u16(1), u32(0), u16(2), rule), "holds fewer"},
		{"trailing bytes", TypeApply, joinBytes(u16(1), u32(0), u16(1), rule, []byte{9}), "trailing"},
		{"trailing bytes after no tenant", TypeApply, joinBytes(u16(0), []byte{9}), "trailing"},
	}
	for _, c := range cases {
		mustFail(t, c.name, c.typ, c.body, c.want)
	}
}

func TestACursorRefusesToReadPastItsEnd(t *testing.T) {
	if _, err := (&cursor{b: []byte{1}}).take(2); err == nil {
		t.Error("take past the end")
	}
	if _, err := (&cursor{b: []byte{1}}).take(-1); err == nil {
		t.Error("take of a negative count")
	}
	if _, err := (&cursor{}).u8(); err == nil {
		t.Error("u8 of nothing")
	}
	if _, err := (&cursor{b: []byte{1}}).u16(); err == nil {
		t.Error("u16 of one byte")
	}
	if _, err := (&cursor{b: []byte{1, 2, 3}}).u32(); err == nil {
		t.Error("u32 of three bytes")
	}
	if _, err := (&cursor{b: []byte{1, 2, 3}}).addr4(); err == nil {
		t.Error("addr4 of three bytes")
	}
	if err := (&cursor{b: []byte{1}}).done(); err == nil {
		t.Error("done with a byte left")
	}
}

func TestTheEncoderRefusesWhatTheWireCannotSay(t *testing.T) {
	v6 := netip.MustParseAddr("fd00::1")
	okRule := policy.Rule{CIDR: "10.0.0.0/8", Proto: "tcp", Ports: []policy.Port{{Lo: 80, Hi: 80}}}
	many := make([]policy.Rule, MaxRulesPerTenant+1)
	for i := range many {
		many[i] = okRule
	}
	cases := []struct {
		name string
		req  Request
		want string
	}{
		{"add-peer v6", AddPeer{IP: v6}, "not IPv4"},
		{"too many tenants", Apply{Tenants: make([]fw.Tenant, MaxTenants+1)}, "exceed"},
		{"too many rules", Apply{Tenants: []fw.Tenant{{Rules: many}}}, "exceed"},
		{"peer v6", Apply{Tenants: []fw.Tenant{{Peers: []netip.Addr{v6}}}}, "not IPv4"},
		{"invalid rule", Apply{Tenants: []fw.Tenant{{Rules: []policy.Rule{{CIDR: "nope", Proto: "tcp"}}}}}, "cidr"},
	}
	for _, c := range cases {
		_, err := c.req.encode()
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}
}

// A routes-only tenant has rules for every protocol and port: it crosses the
// wire as the protocol "any", and comes out the same.
func TestALegacyAnyRuleCrossesTheWire(t *testing.T) {
	in := Apply{Tenants: []fw.Tenant{{Peers: []netip.Addr{netip.MustParseAddr("10.80.0.2")}, Rules: policy.Legacy([]string{"10.0.0.0/24", "192.168.1.0/24"})}}}
	body, err := in.encode()
	if err != nil {
		t.Fatal(err)
	}
	out, err := Decode(TypeApply, body)
	if err != nil {
		t.Fatal(err)
	}
	got := out.(Apply).Tenants[0].Rules
	if len(got) != 2 || got[0].Proto != policy.ProtoAny || got[1].CIDR != "192.168.1.0/24" || len(got[0].Ports) != 0 {
		t.Fatalf("rules %+v", got)
	}
	if err := testLimits.Check(out); err != nil {
		t.Fatalf("the parent refuses a legacy rule: %v", err)
	}
}

func TestAnAnyRuleWithPortsIsRefusedAndATCPRuleWithoutIsToo(t *testing.T) {
	if _, err := (Apply{Tenants: []fw.Tenant{{Rules: []policy.Rule{{CIDR: "10.0.0.0/8", Proto: policy.ProtoAny, Ports: []policy.Port{{Lo: 1, Hi: 2}}}}}}}).encode(); err == nil {
		t.Error("an any rule with ports was encoded")
	}
	anyWithPort := joinBytes(u16(1), u32(0), u16(1), []byte{10, 0, 0, 0, 8, wireProtoAny, 1, 0, 80, 0, 80})
	mustFail(t, "any with a port", TypeApply, anyWithPort, "port")
	tcpNoPort := joinBytes(u16(1), u32(0), u16(1), []byte{10, 0, 0, 0, 8, wireProtoTCP, 0, 0, 0, 0, 0})
	mustFail(t, "tcp without a port", TypeApply, tcpNoPort, "port")
}

// rawPeer answers one request with the bytes it is given.
func rawPeer(t *testing.T, reply func(Type) (Type, []byte, bool)) *Client {
	t.Helper()
	a, b := net.Pipe()
	go func() {
		defer a.Close()
		typ, _, err := ReadFrame(a)
		if err != nil {
			return
		}
		rt, body, send := reply(typ)
		if send {
			_ = WriteFrame(a, rt, body)
		}
	}()
	c := NewClient(b)
	t.Cleanup(func() { c.Close() })
	return c
}

func isDone(c *Client) bool {
	select {
	case <-c.Done():
		return true
	default:
		return false
	}
}

func TestTheClientEndsItsSessionWhenTheParentMisbehaves(t *testing.T) {
	t.Run("encode failure keeps the session", func(t *testing.T) {
		c, _ := pair(t, &fake{})
		if _, err := c.call(AddPeer{IP: netip.MustParseAddr("fd00::1")}); err == nil {
			t.Fatal("encoded")
		}
		if isDone(c) {
			t.Fatal("an encode failure ended the session")
		}
	})
	t.Run("write failure", func(t *testing.T) {
		a, b := net.Pipe()
		a.Close()
		c := NewClient(b)
		if err := c.RemovePeer(key(1)); err == nil || !isDone(c) {
			t.Fatalf("err %v, done %v", err, isDone(c))
		}
	})
	t.Run("no reply", func(t *testing.T) {
		c := rawPeer(t, func(Type) (Type, []byte, bool) { return 0, nil, false })
		if err := c.RemovePeer(key(1)); err == nil || !isDone(c) {
			t.Fatalf("err %v, done %v", err, isDone(c))
		}
	})
	t.Run("short set-mtu reply", func(t *testing.T) {
		c := rawPeer(t, func(typ Type) (Type, []byte, bool) { return typ | ReplyFlag, []byte{StatusOK, 0, 0, 5}, true })
		if _, err := c.SetTunnelMTU(1420); err == nil || !strings.Contains(err.Error(), "malformed") {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("short sweep reply", func(t *testing.T) {
		c := rawPeer(t, func(typ Type) (Type, []byte, bool) { return typ | ReplyFlag, []byte{StatusOK, 0}, true })
		if _, err := c.Sweep(); err == nil || !strings.Contains(err.Error(), "malformed") {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("wrong reply type", func(t *testing.T) {
		c := rawPeer(t, func(Type) (Type, []byte, bool) { return TypeSweep | ReplyFlag, []byte{StatusOK}, true })
		if err := c.RemovePeer(key(1)); err == nil || !isDone(c) {
			t.Fatalf("err %v, done %v", err, isDone(c))
		}
	})
	t.Run("empty reply", func(t *testing.T) {
		c := rawPeer(t, func(typ Type) (Type, []byte, bool) { return typ | ReplyFlag, nil, true })
		if err := c.RemovePeer(key(1)); err == nil || !isDone(c) {
			t.Fatalf("err %v, done %v", err, isDone(c))
		}
	})
	t.Run("unknown status", func(t *testing.T) {
		c := rawPeer(t, func(typ Type) (Type, []byte, bool) { return typ | ReplyFlag, []byte{9}, true })
		if err := c.RemovePeer(key(1)); err == nil || !isDone(c) {
			t.Fatalf("err %v, done %v", err, isDone(c))
		}
	})
}

func TestSetTunnelMTURefusesWhatDoesNotFitFourBytes(t *testing.T) {
	f := &fake{}
	c, _ := pair(t, f)
	_, err := c.SetTunnelMTU(-1)
	var ref *RefusedError
	if err == nil || errors.As(err, &ref) || !strings.Contains(err.Error(), "out of range") {
		t.Fatalf("err %v", err)
	}
	if f.count() != 0 {
		t.Fatal("the parent heard of it")
	}
	if _, err := c.SetTunnelMTU(100); !errors.As(err, &ref) {
		t.Fatalf("an MTU below the floor: %v", err)
	}
}
