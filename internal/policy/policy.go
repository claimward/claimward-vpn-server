// Package policy is what a tenant's peers may reach through the gateway:
// a list of rules, each a destination CIDR, a protocol and ports.
//
// It is the single source of truth. The gateway's firewall (internal/fw) is
// built from it, and the routes pushed to clients (AllowedIPs) are derived
// from it, so what a client is told it can reach and what the gateway lets
// through cannot drift apart.
//
// A policy only ever ALLOWS; everything it does not name is dropped.
package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// Protocols a rule can name. ProtoAny exists only for the legacy
// "allowed_ips without a policy" form and is refused by Parse and Validate.
const (
	ProtoTCP = "tcp"
	ProtoUDP = "udp"
	ProtoAny = "any"
)

// Bounds: a policy comes from a file or the admin API, and becomes kernel
// rules, so it is not allowed to be arbitrarily large.
const (
	MaxRules         = 1024
	MaxPortsPerRule  = 64
	maxPolicyBytes   = 1 << 20
	maxPortSpecBytes = 16
)

// Port is an inclusive port range; a single port has Lo == Hi.
type Port struct{ Lo, Hi uint16 }

func (p Port) String() string {
	if p.Lo == p.Hi {
		return strconv.Itoa(int(p.Lo))
	}
	return fmt.Sprintf("%d-%d", p.Lo, p.Hi)
}

// MarshalJSON writes a single port as a number and a range as "lo-hi".
func (p Port) MarshalJSON() ([]byte, error) {
	if p.Lo == p.Hi {
		return json.Marshal(int(p.Lo))
	}
	return json.Marshal(p.String())
}

// UnmarshalJSON accepts 445, "445" and "1024-2048".
func (p *Port) UnmarshalJSON(b []byte) error {
	s := strings.TrimSpace(string(b))
	if strings.HasPrefix(s, `"`) {
		var str string
		if err := json.Unmarshal(b, &str); err != nil {
			return err
		}
		s = str
	}
	if len(s) == 0 || len(s) > maxPortSpecBytes {
		return fmt.Errorf("invalid port %q", s)
	}
	lo, hi, isRange := strings.Cut(s, "-")
	l, err := parsePort(lo)
	if err != nil {
		return err
	}
	h := l
	if isRange {
		if h, err = parsePort(hi); err != nil {
			return err
		}
	}
	if h < l {
		return fmt.Errorf("port range %q is backwards", s)
	}
	*p = Port{l, h}
	return nil
}

func parsePort(s string) (uint16, error) {
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil || n == 0 {
		return 0, fmt.Errorf("invalid port %q (want 1-65535)", s)
	}
	return uint16(n), nil
}

// Rule allows traffic from the peer to CIDR on Proto and Ports.
type Rule struct {
	CIDR  string `json:"cidr"`
	Proto string `json:"proto"`
	Ports []Port `json:"ports,omitempty"`
}

// Prefix is the rule's destination, masked. Call after Validate.
func (r Rule) Prefix() netip.Prefix {
	p, _ := netip.ParsePrefix(r.CIDR)
	return p.Masked()
}

// Validate refuses a rule that could not be enforced exactly as written.
func (r Rule) Validate() error {
	p, err := netip.ParsePrefix(strings.TrimSpace(r.CIDR))
	if err != nil {
		return fmt.Errorf("rule cidr %q: %w", r.CIDR, err)
	}
	if !p.Addr().Is4() {
		// The VPN pool is IPv4; an IPv6 rule would enforce nothing.
		return fmt.Errorf("rule cidr %q: only IPv4 is supported", r.CIDR)
	}
	switch r.Proto {
	case ProtoTCP, ProtoUDP:
		if len(r.Ports) == 0 {
			return fmt.Errorf("rule %s %s: ports are required", r.CIDR, r.Proto)
		}
		if len(r.Ports) > MaxPortsPerRule {
			return fmt.Errorf("rule %s %s: more than %d ports", r.CIDR, r.Proto, MaxPortsPerRule)
		}
		for _, pt := range r.Ports {
			if pt.Lo == 0 || pt.Hi < pt.Lo {
				return fmt.Errorf("rule %s %s: invalid port range %v", r.CIDR, r.Proto, pt)
			}
		}
	default:
		return fmt.Errorf("rule %s: proto %q (want %q or %q)", r.CIDR, r.Proto, ProtoTCP, ProtoUDP)
	}
	return nil
}

// Validate checks every rule of a policy.
func Validate(rules []Rule) error {
	if len(rules) > MaxRules {
		return fmt.Errorf("policy has %d rules, the limit is %d", len(rules), MaxRules)
	}
	for i, r := range rules {
		if err := r.Validate(); err != nil {
			return fmt.Errorf("rule %d: %w", i, err)
		}
	}
	return nil
}

// Parse reads a JSON array of rules, refusing unknown fields, trailing data
// and anything Validate refuses.
func Parse(data []byte) ([]Rule, error) {
	if len(data) > maxPolicyBytes {
		return nil, fmt.Errorf("policy is larger than %d bytes", maxPolicyBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var rules []Rule
	if err := dec.Decode(&rules); err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("policy: trailing data")
	}
	if err := Validate(rules); err != nil {
		return nil, err
	}
	return rules, nil
}

// Legacy is the policy of a tenant configured with routes only, as before
// policies existed: every protocol and port to those CIDRs.
func Legacy(cidrs []string) []Rule {
	out := make([]Rule, 0, len(cidrs))
	for _, c := range cidrs {
		out = append(out, Rule{CIDR: c, Proto: ProtoAny})
	}
	return out
}

// Routes is the AllowedIPs a client is pushed for these rules: each distinct
// destination CIDR, in order of first appearance, normalised.
func Routes(rules []Rule) []string {
	seen := map[netip.Prefix]bool{}
	var out []string
	for _, r := range rules {
		p, err := netip.ParsePrefix(strings.TrimSpace(r.CIDR))
		if err != nil {
			continue
		}
		p = p.Masked()
		if !seen[p] {
			seen[p] = true
			out = append(out, p.String())
		}
	}
	return out
}
