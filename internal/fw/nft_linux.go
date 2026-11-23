//go:build linux

package fw

import (
	"fmt"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"

	"github.com/claimward/claimward-vpn-server/internal/policy"
)

// NFT installs a Ruleset with nftables, over netlink.
//
// Needs CAP_NET_ADMIN in the network namespace of the wg interface.
type NFT struct {
	// NetNSFd, when non-zero, is a file descriptor of the network namespace
	// to program instead of the caller's own (tests).
	NetNSFd int
}

// NewNFT is the production Applier.
func NewNFT() *NFT { return &NFT{} }

func (n *NFT) conn() (*nftables.Conn, error) {
	if n.NetNSFd != 0 {
		return nftables.New(nftables.WithNetNSFd(n.NetNSFd))
	}
	return nftables.New()
}

// Apply replaces the table in ONE netlink transaction: create-if-absent,
// delete, create, fill. The kernel commits all of it or none of it, and a
// packet sees either the old table or the new one.
func (n *NFT) Apply(rs Ruleset) error {
	c, err := n.conn()
	if err != nil {
		return fmt.Errorf("nftables: open netlink: %w", err)
	}
	defer c.CloseLasting() //nolint:errcheck

	t := &nftables.Table{Family: nftables.TableFamilyINet, Name: rs.Table}
	c.AddTable(t) // so that the delete below cannot fail on a first run
	c.DelTable(t)
	c.AddTable(t)

	sets := map[string]*nftables.Set{}
	for _, s := range rs.Sets {
		set := &nftables.Set{Table: t, Name: s.Name, KeyType: nftables.TypeIPAddr}
		els := make([]nftables.SetElement, 0, len(s.Addrs))
		for _, a := range s.Addrs {
			els = append(els, nftables.SetElement{Key: a.AsSlice()})
		}
		if err := c.AddSet(set, els); err != nil {
			return fmt.Errorf("nftables: set %s: %w", s.Name, err)
		}
		sets[s.Name] = set
	}

	accept := nftables.ChainPolicyAccept
	for _, ch := range rs.Chains {
		nc := &nftables.Chain{Name: ch.Name, Table: t}
		switch ch.Hook {
		case "":
		case HookInput, HookForward:
			nc.Type = nftables.ChainTypeFilter
			nc.Hooknum = nftables.ChainHookInput
			if ch.Hook == HookForward {
				nc.Hooknum = nftables.ChainHookForward
			}
			nc.Priority = nftables.ChainPriorityFilter
			// accept: only the rules below drop, and only what arrives on the
			// wg interface. Everything else on the host is not ours to judge.
			nc.Policy = &accept
		default:
			return fmt.Errorf("nftables: chain %s: unknown hook %q", ch.Name, ch.Hook)
		}
		nc = c.AddChain(nc)
		for _, r := range ch.Rules {
			exprs, err := exprsFor(r, sets)
			if err != nil {
				return fmt.Errorf("nftables: chain %s: %w", ch.Name, err)
			}
			c.AddRule(&nftables.Rule{Table: t, Chain: nc, Exprs: exprs})
		}
	}
	if err := c.Flush(); err != nil {
		return fmt.Errorf("nftables: commit: %w", err)
	}
	return nil
}

func exprsFor(r Rule, sets map[string]*nftables.Set) ([]expr.Any, error) {
	var e []expr.Any
	if r.Iface != "" {
		if len(r.Iface) >= unix.IFNAMSIZ {
			return nil, fmt.Errorf("interface name %q is too long", r.Iface)
		}
		name := make([]byte, unix.IFNAMSIZ) // NUL padded, as the kernel compares it
		copy(name, r.Iface)
		e = append(e,
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: name})
	}
	if r.IPv4 || r.SrcSet != "" || r.Dst.IsValid() {
		e = append(e,
			&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV4}})
	}
	if r.SrcSet != "" {
		set, ok := sets[r.SrcSet]
		if !ok {
			return nil, fmt.Errorf("unknown set %q", r.SrcSet)
		}
		e = append(e,
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
			&expr.Lookup{SourceRegister: 1, SetName: set.Name, SetID: set.ID})
	}
	if r.Dst.IsValid() && r.Dst.Bits() > 0 {
		e = append(e, &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4})
		addr := r.Dst.Addr().As4()
		if r.Dst.Bits() < 32 {
			mask := make([]byte, 4)
			for i := 0; i < r.Dst.Bits(); i++ {
				mask[i/8] |= 0x80 >> (i % 8)
			}
			e = append(e, &expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: mask, Xor: make([]byte, 4)})
		}
		e = append(e, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: addr[:]})
	}
	switch r.Proto {
	case "":
	case policy.ProtoTCP, policy.ProtoUDP:
		proto := byte(unix.IPPROTO_TCP)
		if r.Proto == policy.ProtoUDP {
			proto = unix.IPPROTO_UDP
		}
		e = append(e,
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}})
	default:
		return nil, fmt.Errorf("unknown protocol %q", r.Proto)
	}
	if len(r.Ports) > 1 {
		return nil, fmt.Errorf("one port range per rule (got %d)", len(r.Ports))
	}
	for _, p := range r.Ports {
		e = append(e, &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2})
		if p.Lo == p.Hi {
			e = append(e, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(p.Lo)})
		} else {
			e = append(e,
				&expr.Cmp{Op: expr.CmpOpGte, Register: 1, Data: binaryutil.BigEndian.PutUint16(p.Lo)},
				&expr.Cmp{Op: expr.CmpOpLte, Register: 1, Data: binaryutil.BigEndian.PutUint16(p.Hi)})
		}
	}
	switch {
	case r.Jump != "":
		e = append(e, &expr.Verdict{Kind: expr.VerdictJump, Chain: r.Jump})
	case r.Final == Accept:
		e = append(e, &expr.Verdict{Kind: expr.VerdictAccept})
	case r.Final == Drop:
		e = append(e, &expr.Verdict{Kind: expr.VerdictDrop})
	default:
		return nil, fmt.Errorf("rule without a verdict")
	}
	return e, nil
}
