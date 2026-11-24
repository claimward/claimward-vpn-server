package privsep

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"

	"github.com/claimward/claimward-vpn-server/internal/fw"
	"github.com/claimward/claimward-vpn-server/internal/pf"
	"github.com/claimward/claimward-vpn-server/internal/policy"
)

// KeySize is the size of a WireGuard public key.
const KeySize = 32

// Bounds of an ApplyTenants request. They are the kernel's own (pf.MaxTables,
// pf.MaxAddrs) and the policy's (policy.MaxRules, policy.MaxPortsPerRule), so a
// request the parent accepts is one the pf planner can load.
const (
	MaxTenants              = pf.MaxTables
	MaxPeers                = pf.MaxAddrs
	MaxRulesPerTenant       = policy.MaxRules
	MaxPortsPerRule         = policy.MaxPortsPerRule
	wireProtoTCP      uint8 = 1
	wireProtoUDP      uint8 = 2
	wireProtoAny      uint8 = 3 // a routes-only tenant: every protocol and port, no port list
)

// validateRule is policy.Rule.Validate, plus the legacy "any" rule of a tenant
// configured with routes only: an IPv4 destination and no ports.
func validateRule(r policy.Rule) error {
	if r.Proto != policy.ProtoAny {
		return r.Validate()
	}
	if p, err := netip.ParsePrefix(r.CIDR); err != nil || !p.Addr().Is4() {
		return fmt.Errorf("rule cidr %q: want an IPv4 CIDR such as 10.0.0.0/24", r.CIDR)
	}
	if len(r.Ports) != 0 {
		return fmt.Errorf("rule %s any: ports are not allowed", r.CIDR)
	}
	return nil
}

// A Request is one of the five messages a child may send. Its encoding names
// IPv4 addresses as four bytes: there is no way to say another family.
type Request interface {
	Type() Type
	encode() ([]byte, error)
}

// AddPeer adds, or replaces, the peer Key, whose only allowed IP is IP/32.
type AddPeer struct {
	Key [KeySize]byte
	IP  netip.Addr
}

// RemovePeer removes the peer Key, which this session added.
type RemovePeer struct{ Key [KeySize]byte }

// Sweep removes the peers a previous run of the server left on the device.
type Sweep struct{}

// SetMTU sets the tunnel MTU; 0 asks the parent to derive it from the uplink.
type SetMTU struct{ MTU uint32 }

// Apply installs the firewall of these tenants. Tenant IDs never cross the
// boundary (they are text the child's clients chose): the parent numbers the
// tenants in the order they come, which is the order Build sorts them in.
type Apply struct{ Tenants []fw.Tenant }

func (AddPeer) Type() Type    { return TypeAddPeer }
func (RemovePeer) Type() Type { return TypeRemovePeer }
func (Sweep) Type() Type      { return TypeSweep }
func (SetMTU) Type() Type     { return TypeSetMTU }
func (Apply) Type() Type      { return TypeApply }

func (m AddPeer) encode() ([]byte, error) {
	if !m.IP.Is4() {
		return nil, errors.New("privsep: add-peer: the address is not IPv4")
	}
	b := append(make([]byte, 0, KeySize+4), m.Key[:]...)
	ip := m.IP.As4()
	return append(b, ip[:]...), nil
}

func (m RemovePeer) encode() ([]byte, error) { return append([]byte(nil), m.Key[:]...), nil }
func (Sweep) encode() ([]byte, error)        { return nil, nil }
func (m SetMTU) encode() ([]byte, error)     { return binary.BigEndian.AppendUint32(nil, m.MTU), nil }

func (m Apply) encode() ([]byte, error) {
	if len(m.Tenants) > MaxTenants {
		return nil, fmt.Errorf("privsep: apply: %d tenants exceed the limit of %d", len(m.Tenants), MaxTenants)
	}
	b := binary.BigEndian.AppendUint16(nil, uint16(len(m.Tenants)))
	for _, t := range m.Tenants {
		if len(t.Rules) > MaxRulesPerTenant {
			return nil, fmt.Errorf("privsep: apply: %d rules exceed the limit of %d", len(t.Rules), MaxRulesPerTenant)
		}
		b = binary.BigEndian.AppendUint32(b, uint32(len(t.Peers)))
		for _, a := range t.Peers {
			if !a.Is4() {
				return nil, fmt.Errorf("privsep: apply: peer %v is not IPv4", a)
			}
			a4 := a.As4()
			b = append(b, a4[:]...)
		}
		b = binary.BigEndian.AppendUint16(b, uint16(len(t.Rules)))
		for _, r := range t.Rules {
			if err := validateRule(r); err != nil {
				return nil, fmt.Errorf("privsep: apply: %w", err)
			}
			p := r.Prefix()
			a4 := p.Addr().As4()
			proto := wireProtoTCP
			switch r.Proto {
			case policy.ProtoUDP:
				proto = wireProtoUDP
			case policy.ProtoAny:
				proto = wireProtoAny
			}
			b = append(b, a4[:]...)
			b = append(b, byte(p.Bits()), proto, byte(len(r.Ports)))
			for _, pt := range r.Ports {
				b = binary.BigEndian.AppendUint16(b, pt.Lo)
				b = binary.BigEndian.AppendUint16(b, pt.Hi)
			}
		}
	}
	return b, nil
}

// cursor reads a body; every read is bounded by what is left.
type cursor struct{ b []byte }

func (c *cursor) left() int { return len(c.b) }

func (c *cursor) take(n int) ([]byte, error) {
	if n < 0 || n > len(c.b) {
		return nil, errors.New("body ends early")
	}
	out := c.b[:n]
	c.b = c.b[n:]
	return out, nil
}

func (c *cursor) u8() (uint8, error) {
	b, err := c.take(1)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}

func (c *cursor) u16() (uint16, error) {
	b, err := c.take(2)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b), nil
}

func (c *cursor) u32() (uint32, error) {
	b, err := c.take(4)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(b), nil
}

func (c *cursor) addr4() (netip.Addr, error) {
	b, err := c.take(4)
	if err != nil {
		return netip.Addr{}, err
	}
	return netip.AddrFrom4([4]byte(b)), nil
}

func (c *cursor) done() error {
	if len(c.b) != 0 {
		return fmt.Errorf("%d trailing bytes", len(c.b))
	}
	return nil
}

// Decode reads the body of a request of type t. It judges the SHAPE (lengths,
// counts against the bytes left, codes) and the structural bounds; whether the
// request is allowed is Limits.Check's question. A type that is not one of the
// five is an error, never a guess.
func Decode(t Type, body []byte) (Request, error) {
	c := &cursor{b: body}
	switch t {
	case TypeAddPeer:
		if len(body) != KeySize+4 {
			return nil, fmt.Errorf("add-peer: body of %d bytes, want %d", len(body), KeySize+4)
		}
		var m AddPeer
		k, _ := c.take(KeySize)
		copy(m.Key[:], k)
		m.IP, _ = c.addr4()
		return m, nil
	case TypeRemovePeer:
		if len(body) != KeySize {
			return nil, fmt.Errorf("remove-peer: body of %d bytes, want %d", len(body), KeySize)
		}
		var m RemovePeer
		copy(m.Key[:], body)
		return m, nil
	case TypeSweep:
		if len(body) != 0 {
			return nil, fmt.Errorf("sweep: body of %d bytes, want none", len(body))
		}
		return Sweep{}, nil
	case TypeSetMTU:
		if len(body) != 4 {
			return nil, fmt.Errorf("set-mtu: body of %d bytes, want 4", len(body))
		}
		v, _ := c.u32()
		return SetMTU{MTU: v}, nil
	case TypeApply:
		return decodeApply(c)
	}
	return nil, fmt.Errorf("message type %d is not one the parent serves", uint8(t))
}

func decodeApply(c *cursor) (Request, error) {
	nt, err := c.u16()
	if err != nil {
		return nil, fmt.Errorf("apply: %w", err)
	}
	if int(nt) > MaxTenants {
		return nil, fmt.Errorf("apply: %d tenants exceed the limit of %d", nt, MaxTenants)
	}
	var m Apply
	peers := 0
	for i := 0; i < int(nt); i++ {
		np, err := c.u32()
		if err != nil {
			return nil, fmt.Errorf("apply: tenant %d: %w", i, err)
		}
		// The count is checked against the bytes that are there BEFORE the slice
		// is made: a count is the sender's claim, the bytes are the evidence.
		if uint64(np)*4 > uint64(c.left()) {
			return nil, fmt.Errorf("apply: tenant %d announces %d peers, the body holds fewer", i, np)
		}
		peers += int(np)
		if peers > MaxPeers {
			return nil, fmt.Errorf("apply: more than %d peers", MaxPeers)
		}
		t := fw.Tenant{ID: fmt.Sprintf("%08d", i), Peers: make([]netip.Addr, np)}
		for j := range t.Peers {
			t.Peers[j], _ = c.addr4()
		}
		nr, err := c.u16()
		if err != nil {
			return nil, fmt.Errorf("apply: tenant %d: %w", i, err)
		}
		if int(nr) > MaxRulesPerTenant {
			return nil, fmt.Errorf("apply: tenant %d: %d rules exceed the limit of %d", i, nr, MaxRulesPerTenant)
		}
		if int(nr)*7 > c.left() { // a rule is at least 7 bytes: an "any" rule has no ports
			return nil, fmt.Errorf("apply: tenant %d announces %d rules, the body holds fewer", i, nr)
		}
		for j := 0; j < int(nr); j++ {
			r, err := decodeRule(c)
			if err != nil {
				return nil, fmt.Errorf("apply: tenant %d rule %d: %w", i, j, err)
			}
			t.Rules = append(t.Rules, r)
		}
		m.Tenants = append(m.Tenants, t)
	}
	if err := c.done(); err != nil {
		return nil, fmt.Errorf("apply: %w", err)
	}
	return m, nil
}

func decodeRule(c *cursor) (policy.Rule, error) {
	// The fixed part of a rule: address, prefix length, protocol code, number
	// of port ranges.
	h, err := c.take(7)
	if err != nil {
		return policy.Rule{}, err
	}
	a := netip.AddrFrom4([4]byte(h[:4]))
	bits, pc, np := h[4], h[5], h[6]
	if bits > 32 {
		return policy.Rule{}, fmt.Errorf("prefix length %d", bits)
	}
	r := policy.Rule{CIDR: netip.PrefixFrom(a, int(bits)).String()}
	switch pc {
	case wireProtoTCP:
		r.Proto = policy.ProtoTCP
	case wireProtoUDP:
		r.Proto = policy.ProtoUDP
	case wireProtoAny:
		r.Proto = policy.ProtoAny
		if np != 0 {
			return policy.Rule{}, fmt.Errorf("an any rule with %d port ranges", np)
		}
	default:
		return policy.Rule{}, fmt.Errorf("protocol code %d", pc)
	}
	if r.Proto != policy.ProtoAny && (np == 0 || int(np) > MaxPortsPerRule) {
		return policy.Rule{}, fmt.Errorf("%d port ranges (want 1 to %d)", np, MaxPortsPerRule)
	}
	for k := 0; k < int(np); k++ {
		pb, err := c.take(4)
		if err != nil {
			return policy.Rule{}, err
		}
		r.Ports = append(r.Ports, policy.Port{Lo: binary.BigEndian.Uint16(pb), Hi: binary.BigEndian.Uint16(pb[2:])})
	}
	return r, nil
}

// Limits is what the parent allows, fixed at its start from its own
// configuration and never from a request.
type Limits struct {
	// Pool is the VPN address pool: a peer's address, and an address in a
	// tenant's table, is inside it.
	Pool netip.Prefix
	// MinMTU and MaxMTU bound the tunnel MTU.
	MinMTU, MaxMTU int
}

// Check says whether a decoded request is allowed. An error is a refusal.
func (l Limits) Check(r Request) error {
	switch m := r.(type) {
	case AddPeer:
		if m.Key == ([KeySize]byte{}) {
			return errors.New("add-peer: the key is all zero")
		}
		return l.peerAddr("add-peer", m.IP)
	case RemovePeer:
		if m.Key == ([KeySize]byte{}) {
			return errors.New("remove-peer: the key is all zero")
		}
	case Sweep:
	case SetMTU:
		if m.MTU != 0 && (int64(m.MTU) < int64(l.MinMTU) || int64(m.MTU) > int64(l.MaxMTU)) {
			return fmt.Errorf("set-mtu: %d is outside %d to %d", m.MTU, l.MinMTU, l.MaxMTU)
		}
	case Apply:
		for i, t := range m.Tenants {
			for _, a := range t.Peers {
				if err := l.peerAddr(fmt.Sprintf("apply: tenant %d", i), a); err != nil {
					return err
				}
			}
			for j, r := range t.Rules {
				if err := validateRule(r); err != nil {
					return fmt.Errorf("apply: tenant %d rule %d: %w", i, j, err)
				}
				// Build masks a destination; a prefix with host bits set is the
				// child saying something other than what will be enforced.
				p, _ := netip.ParsePrefix(r.CIDR)
				if p != p.Masked() {
					return fmt.Errorf("apply: tenant %d rule %d: %s has host bits set", i, j, r.CIDR)
				}
			}
		}
	default:
		return fmt.Errorf("request %T is not in the allowlist", r)
	}
	return nil
}

func (l Limits) peerAddr(what string, a netip.Addr) error {
	if !a.Is4() || a.IsUnspecified() || !l.Pool.Contains(a) {
		return fmt.Errorf("%s: address %v is not a host of the pool %v", what, a, l.Pool)
	}
	if a == l.Pool.Masked().Addr() {
		return fmt.Errorf("%s: address %v is the pool's network address", what, a)
	}
	return nil
}
