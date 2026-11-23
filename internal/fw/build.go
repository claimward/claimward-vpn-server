// Package fw enforces, on the gateway, what each enrolled peer may reach.
//
// The ruleset is described first as plain data (Ruleset, built by Build, a
// pure function of the tenants' policies and their peers' addresses) and only
// then installed by an Applier. On Linux the Applier speaks nftables over
// netlink (github.com/google/nftables); nothing shells out to nft.
//
// Shape of the single table "claimward" (family inet):
//
//	set    t<N>_src          the /32 of every peer of tenant N
//	chain  t<N>              one accept rule per (destination, proto, port)
//	chain  forward, input    hooked; for traffic that ARRIVES on the wg
//	                         interface: IPv4 from a peer of tenant N jumps to
//	                         t<N>; whatever is left is dropped
//
// Default deny is therefore explicit and scoped to the wg interface: traffic
// that does not arrive on it is never touched. Both forward (peer to the
// networks behind the gateway) and input (peer to the gateway host itself,
// which may be the file server) are covered, so a policy cannot be bypassed by
// aiming at the gateway's own addresses.
package fw

import (
	"fmt"
	"net/netip"
	"sort"

	"github.com/claimward/claimward-vpn-server/internal/policy"
)

// TableName is the one nftables table claimward owns.
const TableName = "claimward"

// Tenant is a tenant's rules and the addresses of its enrolled peers.
type Tenant struct {
	ID    string
	Peers []netip.Addr
	Rules []policy.Rule
}

// Set is a named set of IPv4 addresses.
type Set struct {
	Name  string
	Addrs []netip.Addr
}

// Verdicts and hooks of a Ruleset.
const (
	Accept = "accept"
	Drop   = "drop"

	HookInput   = "input"
	HookForward = "forward"
)

// Rule is one rule. Zero fields are not matched. A rule with a Jump or
// Verdict ends in it.
type Rule struct {
	Iface  string        // arrived on this interface
	IPv4   bool          // the packet is IPv4 (implied by SrcSet and Dst)
	SrcSet string        // source address is in this set
	Dst    netip.Prefix  // destination address is in this prefix
	Proto  string        // policy.ProtoTCP, ProtoUDP, or "" for any
	Ports  []policy.Port // destination port is in one of these ranges
	Jump   string        // continue in this chain
	Final  string        // Accept or Drop
}

// Chain is a chain; Hook is "" for a regular (jump target) chain.
type Chain struct {
	Name  string
	Hook  string
	Rules []Rule
}

// Ruleset is the whole table.
type Ruleset struct {
	Table  string
	Sets   []Set
	Chains []Chain // regular chains first, so every jump target exists
}

// Build is the ruleset that enforces tenants on traffic arriving on iface.
//
// Pure and deterministic: tenants and peers are ordered, so the same input is
// the same output. A rule that cannot be enforced exactly as written (not
// IPv4, a bad prefix) is left out, which only ever means MORE is denied.
func Build(iface string, tenants []Tenant) Ruleset {
	ts := append([]Tenant(nil), tenants...)
	sort.Slice(ts, func(i, j int) bool { return ts[i].ID < ts[j].ID })

	rs := Ruleset{Table: TableName}
	var jumps []Rule
	for _, t := range ts {
		peers := dedupSorted(t.Peers)
		if len(peers) == 0 {
			continue // nobody to route to this chain: not worth a chain
		}
		n := len(jumps)
		set := fmt.Sprintf("t%d_src", n)
		chain := fmt.Sprintf("t%d", n)
		rs.Sets = append(rs.Sets, Set{Name: set, Addrs: peers})
		rs.Chains = append(rs.Chains, Chain{Name: chain, Rules: tenantRules(t.Rules)})
		jumps = append(jumps, Rule{Iface: iface, IPv4: true, SrcSet: set, Jump: chain})
	}
	for _, hook := range []string{HookForward, HookInput} {
		rules := append([]Rule(nil), jumps...)
		rules = append(rules, Rule{Iface: iface, Final: Drop})
		rs.Chains = append(rs.Chains, Chain{Name: hook, Hook: hook, Rules: rules})
	}
	return rs
}

// tenantRules is one accept rule per (rule, port range).
func tenantRules(rules []policy.Rule) []Rule {
	var out []Rule
	for _, r := range rules {
		p, err := netip.ParsePrefix(r.CIDR)
		if err != nil || !p.Addr().Is4() {
			continue
		}
		p = p.Masked()
		switch r.Proto {
		case policy.ProtoAny:
			out = append(out, Rule{Dst: p, Final: Accept})
		case policy.ProtoTCP, policy.ProtoUDP:
			for _, pt := range r.Ports {
				if pt.Lo == 0 || pt.Hi < pt.Lo {
					continue
				}
				out = append(out, Rule{Dst: p, Proto: r.Proto, Ports: []policy.Port{pt}, Final: Accept})
			}
		}
	}
	return out
}

func dedupSorted(in []netip.Addr) []netip.Addr {
	out := make([]netip.Addr, 0, len(in))
	for _, a := range in {
		if a.Is4() {
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })
	w := 0
	for i, a := range out {
		if i == 0 || a != out[w-1] {
			out[w] = a
			w++
		}
	}
	return out[:w]
}

// An Applier installs a Ruleset, replacing whatever it installed before, all
// at once: no packet is ever evaluated against a half-built table.
//
// ⛔ There is deliberately no "remove on exit": a gateway whose process died
// keeps denying (the table stays, and the next start replaces it) rather than
// forwarding everything.
type Applier interface {
	Apply(Ruleset) error
}
