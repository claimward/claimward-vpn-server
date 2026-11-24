// Package pf installs an fw.Ruleset on OpenBSD through /dev/pf ioctls.
//
// This file is the part that needs no OpenBSD: it flattens an fw.Ruleset (which
// is nftables shaped: chains, jumps, hooks) into the ordered list of pf rules
// and tables that say the same thing, and validates every value that will
// later be copied into a kernel structure. The ioctl layer only encodes what
// Plan returns.
package pf

import (
	"fmt"
	"net/netip"
	"reflect"

	"github.com/claimward/claimward-vpn-server/internal/fw"
	"github.com/claimward/claimward-vpn-server/internal/policy"
)

// AnchorName is the one anchor claimward owns. The administrator's pf.conf
// must call it (`anchor "claimward"`); the server only verifies that.
const AnchorName = "claimward"

// Bounds, checked before any ioctl so that a ruleset the kernel would refuse
// half way through a transaction is a configuration error instead. The kernel's
// own limits are PFR_KTABLE_HIWAT 1000 tables and PFR_KENTRY_HIWAT 200000
// addresses over all tables.
const (
	MaxTables = 900
	MaxRules  = 8192
	MaxAddrs  = 150000

	ifNameSize    = 16 // IFNAMSIZ, with its NUL
	tableNameSize = 32 // PF_TABLE_NAME_SIZE, with its NUL
)

// Action of a Spec.
type Action uint8

const (
	Pass Action = iota + 1
	Block
	Match
)

// Spec is one pf rule, independent of the OpenBSD release's struct layout.
type Spec struct {
	Action Action
	// Quick ends evaluation at this rule (pass/block); a match rule is never quick.
	Quick bool
	Iface string
	// AF is 4, 6, or 0 for both families.
	AF int
	// Proto is the IP protocol number: 6 TCP, 17 UDP, 0 any.
	Proto uint8
	// SrcTable names the table the source must be in ("" = any source).
	SrcTable string
	// Dst is the destination prefix; invalid means any.
	Dst netip.Prefix
	// PortLo..PortHi is the destination port range; both 0 means any.
	PortLo, PortHi uint16
	// SynOnly: TCP flags S/SA, only a connection's first packet opens state.
	SynOnly bool
	// MaxMSS, on a match rule, is the max-mss scrub option.
	MaxMSS uint16
}

// Table is a pf table of IPv4 host addresses.
type Table struct {
	Name  string
	Addrs []netip.Addr
}

// Plan is what Apply loads into the anchor, in order.
type Plan struct {
	Tables []Table
	Rules  []Spec
}

const (
	protoTCP = 6
	protoUDP = 17
)

// TableName is the pf table name of an fw set for one load. The generation
// suffix makes every load's tables distinct: the table and rule commits are not
// one atomic step (rule and table become live at slightly different moments),
// and positional names ("t3") could otherwise apply one tenant's rules to
// another tenant's peers during that window.
func TableName(set string, gen uint32) string {
	return fmt.Sprintf("%s_g%08x", set, gen)
}

// BlockAll is the deny-only plan loaded when the real one cannot be verified:
// everything arriving on iface is dropped.
func BlockAll(iface string) (Plan, error) {
	if err := validIface(iface); err != nil {
		return Plan{}, err
	}
	return Plan{Rules: []Spec{{Action: Block, Quick: true, Iface: iface}}}, nil
}

// NewPlan flattens rs. gen is this load's table generation. Anything that rs
// says and pf cannot say exactly is an error, never a silently weaker rule.
func NewPlan(rs fw.Ruleset, gen uint32) (Plan, error) {
	var p Plan
	chains := map[string]fw.Chain{}
	var hooked []fw.Chain
	var mangle []fw.Chain
	for _, c := range rs.Chains {
		chains[c.Name] = c
		switch {
		case c.Hook == "":
		case c.Mangle:
			mangle = append(mangle, c)
		default:
			hooked = append(hooked, c)
		}
	}

	// Tables, in the order of rs.Sets.
	names := map[string]string{}
	addrs := 0
	for _, s := range rs.Sets {
		if _, dup := names[s.Name]; dup {
			return Plan{}, fmt.Errorf("pf: set %q defined twice", s.Name)
		}
		n := TableName(s.Name, gen)
		names[s.Name] = n // its length and characters are checked by Validate
		for _, a := range s.Addrs {
			if !a.Is4() || a.IsUnspecified() {
				return Plan{}, fmt.Errorf("pf: set %q holds %v, which is not an IPv4 host address", s.Name, a)
			}
		}
		addrs += len(s.Addrs)
		p.Tables = append(p.Tables, Table{Name: n, Addrs: append([]netip.Addr(nil), s.Addrs...)})
	}
	if len(p.Tables) > MaxTables {
		return Plan{}, fmt.Errorf("pf: %d tables exceed the limit of %d", len(p.Tables), MaxTables)
	}
	if addrs > MaxAddrs {
		return Plan{}, fmt.Errorf("pf: %d table addresses exceed the limit of %d", addrs, MaxAddrs)
	}

	// MSS clamps come first (match rules, never quick). Only the rules for
	// packets ARRIVING on the interface are written: the state a passed SYN
	// creates carries the max-mss to the reply direction.
	seen := map[Spec]bool{}
	for _, c := range mangle {
		for _, r := range c.Rules {
			if r.ClampMSS <= 0 || r.Proto != policy.ProtoTCP || r.Iface == "" || r.IPv4 == r.IPv6 ||
				r.SrcSet != "" || r.Jump != "" || r.Final != "" || r.Dst.IsValid() || len(r.Ports) != 0 {
				if r.OIface != "" && r.Iface == "" {
					continue // leaving direction: covered by state
				}
				return Plan{}, fmt.Errorf("pf: mangle rule %+v is not an MSS clamp on arrival", r)
			}
			if r.ClampMSS > 65535 {
				return Plan{}, fmt.Errorf("pf: MSS %d out of range", r.ClampMSS)
			}
			af := 4
			if r.IPv6 {
				af = 6
			}
			s := Spec{Action: Match, Iface: r.Iface, AF: af, Proto: protoTCP, MaxMSS: uint16(r.ClampMSS)}
			if !seen[s] {
				seen[s] = true
				p.Rules = append(p.Rules, s)
			}
		}
	}

	// The policy: the hooked chains must say the same thing (pf has one
	// ingress hook for traffic to the host and through it).
	if len(hooked) == 0 {
		return Plan{}, fmt.Errorf("pf: the ruleset has no policy chain")
	}
	var first fw.Chain
	for i, c := range hooked {
		if i == 0 {
			first = c
		} else if !reflect.DeepEqual(c.Rules, first.Rules) {
			return Plan{}, fmt.Errorf("pf: chains %s and %s differ, pf has no separate hooks", first.Name, c.Name)
		}
	}
	sawFinal := false
	for _, r := range first.Rules {
		if sawFinal {
			return Plan{}, fmt.Errorf("pf: a rule follows the final verdict of chain %s", first.Name)
		}
		switch {
		case r.Jump != "":
			if r.SrcSet == "" || !r.IPv4 || r.Iface == "" {
				return Plan{}, fmt.Errorf("pf: jump %+v must match IPv4 from a set on an interface", r)
			}
			tbl, ok := names[r.SrcSet]
			if !ok {
				return Plan{}, fmt.Errorf("pf: jump to a rule set from unknown set %q", r.SrcSet)
			}
			target, ok := chains[r.Jump]
			if !ok {
				return Plan{}, fmt.Errorf("pf: jump to unknown chain %q", r.Jump)
			}
			for _, tr := range target.Rules {
				s, err := specOfAccept(tr, r.Iface, tbl)
				if err != nil {
					return Plan{}, err
				}
				p.Rules = append(p.Rules, s)
			}
		case r.Final == fw.Drop && r.Iface != "" && !r.IPv4 && !r.IPv6 && r.SrcSet == "" && !r.Dst.IsValid() && r.Proto == "":
			p.Rules = append(p.Rules, Spec{Action: Block, Quick: true, Iface: r.Iface})
			sawFinal = true
		default:
			return Plan{}, fmt.Errorf("pf: policy rule %+v has no pf equivalent", r)
		}
	}
	if !sawFinal {
		return Plan{}, fmt.Errorf("pf: the policy has no final drop; refusing a ruleset that would not default-deny")
	}

	if len(p.Rules) > MaxRules {
		return Plan{}, fmt.Errorf("pf: %d rules exceed the limit of %d", len(p.Rules), MaxRules)
	}
	if err := p.Validate(); err != nil {
		return Plan{}, err
	}
	return p, nil
}

// specOfAccept is one rule of a tenant chain, as a pass rule for that tenant's
// table.
func specOfAccept(r fw.Rule, iface, table string) (Spec, error) {
	if r.Final != fw.Accept || !r.Dst.IsValid() || r.Jump != "" || r.SrcSet != "" || r.Iface != "" ||
		r.OIface != "" || r.IPv6 || r.ClampMSS != 0 {
		return Spec{}, fmt.Errorf("pf: tenant rule %+v is not an accept for a destination", r)
	}
	s := Spec{Action: Pass, Quick: true, Iface: iface, AF: 4, SrcTable: table, Dst: r.Dst}
	switch r.Proto {
	case "":
		if len(r.Ports) != 0 {
			return Spec{}, fmt.Errorf("pf: ports without a protocol in %+v", r)
		}
	case policy.ProtoTCP, policy.ProtoUDP:
		if len(r.Ports) != 1 {
			return Spec{}, fmt.Errorf("pf: %+v must hold exactly one port range", r)
		}
		s.PortLo, s.PortHi = r.Ports[0].Lo, r.Ports[0].Hi
		s.Proto = protoUDP
		if r.Proto == policy.ProtoTCP {
			s.Proto = protoTCP
			s.SynOnly = true
		}
	default:
		return Spec{}, fmt.Errorf("pf: unknown protocol %q", r.Proto)
	}
	return s, nil
}

// Validate checks every value of the plan that will be copied into a kernel
// structure, so that nothing depends on the kernel refusing it.
func (p Plan) Validate() error {
	if len(p.Tables) > MaxTables || len(p.Rules) > MaxRules {
		return fmt.Errorf("pf: plan exceeds %d tables / %d rules", MaxTables, MaxRules)
	}
	tables := map[string]bool{}
	for _, t := range p.Tables {
		if err := validTableName(t.Name); err != nil {
			return err
		}
		tables[t.Name] = true
	}
	for i, s := range p.Rules {
		if err := s.validate(tables); err != nil {
			return fmt.Errorf("pf: rule %d: %w", i, err)
		}
	}
	return nil
}

func (s Spec) validate(tables map[string]bool) error {
	switch s.Action {
	case Pass, Block:
		if !s.Quick {
			return fmt.Errorf("a pass or block rule must be quick")
		}
		if s.MaxMSS != 0 {
			return fmt.Errorf("max-mss on a pass or block rule")
		}
	case Match:
		if s.Quick || s.MaxMSS == 0 || s.Proto != protoTCP || s.SrcTable != "" || s.Dst.IsValid() {
			return fmt.Errorf("a match rule must be a non-quick TCP max-mss rule")
		}
	default:
		return fmt.Errorf("unknown action %d", s.Action)
	}
	if err := validIface(s.Iface); err != nil {
		return err
	}
	switch s.AF {
	case 0, 4, 6:
	default:
		return fmt.Errorf("address family %d", s.AF)
	}
	if s.Proto != 0 && s.Proto != protoTCP && s.Proto != protoUDP {
		return fmt.Errorf("protocol %d", s.Proto)
	}
	if s.SrcTable != "" {
		if !tables[s.SrcTable] {
			return fmt.Errorf("source table %q is not defined", s.SrcTable)
		}
		if s.AF != 4 {
			return fmt.Errorf("a source table needs inet")
		}
	}
	if s.Dst.IsValid() && (!s.Dst.Addr().Is4() || s.Dst != s.Dst.Masked() || s.AF != 4) {
		return fmt.Errorf("destination %v is not a masked IPv4 prefix", s.Dst)
	}
	if s.PortLo != 0 || s.PortHi != 0 {
		if s.Proto != protoTCP && s.Proto != protoUDP {
			return fmt.Errorf("ports without tcp or udp")
		}
		if s.PortLo == 0 || s.PortHi < s.PortLo {
			return fmt.Errorf("port range %d:%d", s.PortLo, s.PortHi)
		}
	}
	if s.SynOnly && s.Proto != protoTCP {
		return fmt.Errorf("SYN-only on a non-TCP rule")
	}
	return nil
}

// validIface accepts what an interface name is: letters, digits, and the
// trailing unit, shorter than IFNAMSIZ. No pf syntax can be smuggled in because
// the name goes to the kernel as a field, but a malformed name is an error
// here rather than a half-loaded transaction.
func validIface(n string) error {
	if n == "" || len(n) >= ifNameSize {
		return fmt.Errorf("interface name %q is empty or longer than %d bytes", n, ifNameSize-1)
	}
	for i := 0; i < len(n); i++ {
		c := n[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {
			return fmt.Errorf("interface name %q holds %q", n, c)
		}
	}
	return nil
}

func validTableName(n string) error {
	if n == "" || len(n) >= tableNameSize {
		return fmt.Errorf("table name %q is empty or longer than %d bytes", n, tableNameSize-1)
	}
	for i := 0; i < len(n); i++ {
		c := n[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {
			return fmt.Errorf("table name %q holds %q", n, c)
		}
	}
	return nil
}
