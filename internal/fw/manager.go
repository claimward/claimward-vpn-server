package fw

import (
	"log/slog"
	"net/netip"
	"sync"

	"github.com/claimward/claimward-vpn-server/internal/store"
	"github.com/claimward/claimward-vpn-server/internal/tenant"
)

// Manager keeps the installed ruleset equal to what the tenants' policies and
// the enrolled peers say it should be.
type Manager struct {
	iface string
	ap    Applier
	src   func() []Tenant
	log   *slog.Logger
	mtu   int // tunnel MTU to clamp the MSS to; 0 = no clamp

	mu sync.Mutex
}

// NewManager builds a Manager. src is read at every Sync.
func NewManager(iface string, ap Applier, src func() []Tenant, log *slog.Logger) *Manager {
	return &Manager{iface: iface, ap: ap, src: src, log: log}
}

// ClampMSS makes every ruleset the Manager installs lower the MSS of TCP SYNs
// crossing the interface to what mtu carries (see WithMSSClamp). It is part of
// the same atomic table, so it is replaced with the policy and survives the
// deny-all fallback. Call it before the first Sync; mtu 0 clamps nothing.
func (m *Manager) ClampMSS(mtu int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mtu = mtu
}

func (m *Manager) build(ts []Tenant) Ruleset {
	rs := Build(m.iface, ts)
	if m.mtu > 0 {
		rs = WithMSSClamp(rs, m.iface, m.mtu)
	}
	return rs
}

// Sync rebuilds and installs the ruleset.
//
// ⛔ Fails closed: if the new ruleset cannot be installed, the old one may be
// MORE permissive than what is now configured (a rule was removed, a peer
// moved tenant), so it is replaced by deny-all before the error is returned.
// Callers do not bring a peer up on an error.
func (m *Manager) Sync() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	err := m.ap.Apply(m.build(m.src()))
	if err == nil {
		return nil
	}
	if e2 := m.ap.Apply(m.build(nil)); e2 != nil {
		m.log.Error("firewall: cannot install deny-all either; the previous ruleset still stands", "err", e2)
	}
	return err
}

// FromStores is the source of a Manager: every tenant's effective rules, and
// the address of every enrolled peer under the tenant it chose.
func FromStores(ts *tenant.Store, st *store.Store) func() []Tenant {
	return func() []Tenant {
		byID := map[string]*Tenant{}
		var out []*Tenant
		for _, t := range ts.List() {
			x := &Tenant{ID: t.ID, Rules: t.Rules()}
			byID[t.ID] = x
			out = append(out, x)
		}
		for _, p := range st.List() {
			// A peer whose tenant is gone is in no set, so it is dropped.
			x, ok := byID[p.Tenant]
			if !ok {
				continue
			}
			if a, ok := netip.AddrFromSlice(p.IP.To4()); ok {
				x.Peers = append(x.Peers, a)
			}
		}
		res := make([]Tenant, len(out))
		for i, x := range out {
			res[i] = *x
		}
		return res
	}
}

// Discard is the Applier of WG_DRYRUN: it logs and installs nothing.
type Discard struct{ Log *slog.Logger }

// Apply logs the size of the ruleset.
func (d Discard) Apply(rs Ruleset) error {
	d.Log.Info("dry-run firewall", "sets", len(rs.Sets), "chains", len(rs.Chains))
	return nil
}
