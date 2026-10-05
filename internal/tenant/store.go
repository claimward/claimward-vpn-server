// Package tenant is the multi-tenant route store: each tenant owns a set of
// WireGuard routes (AllowedIPs/DNS) and a broadcast channel so gRPC watchers of
// that tenant get pushed updates.
//
// A person may belong to several tenants, and chooses one per session (the
// enrollment names it). Membership is by any of: the verified email's domain,
// a group the identity provider says they are in, or the institution that
// vouched for them (a go-authn provider's "idp"). Somebody who matches no
// tenant belongs to the default one, and only then.
//
// State is in-memory (MVP), mirroring the rest of the server.
package tenant

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

// DefaultID is the tenant used for identities that match no domain.
const DefaultID = "default"

// Tenant is the persisted configuration of a tenant.
type Tenant struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Domains    []string `json:"domains"` // verified email domains that are members
	Groups     []string `json:"groups"`  // groups (token "groups" claim, GitHub orgs) that are members
	IdPs       []string `json:"idps"`    // institutions (go-authn "idp", a SAML entity ID) that are members
	AllowedIPs []string `json:"allowed_ips"`
	DNS        []string `json:"dns"`
	Serial     uint64   `json:"serial"`
}

// RouteSet is what a watcher receives.
type RouteSet struct {
	AllowedIPs []string
	DNS        []string
	Serial     uint64
}

type tenantState struct {
	t    Tenant
	subs map[int]chan RouteSet
}

// Store holds all tenants and their watchers.
type Store struct {
	mu      sync.Mutex
	tenants map[string]*tenantState
	nextSub int
}

// New creates a Store seeded with a default tenant carrying the given routes.
func New(defaultAllowedIPs, defaultDNS []string) *Store {
	s := &Store{tenants: map[string]*tenantState{}}
	s.tenants[DefaultID] = &tenantState{
		t:    Tenant{ID: DefaultID, Name: "Default", AllowedIPs: defaultAllowedIPs, DNS: defaultDNS, Serial: 1},
		subs: map[int]chan RouteSet{},
	}
	return s
}

// Member is what tenants are matched on: who somebody is, as their token says.
type Member struct {
	Email         string
	EmailVerified bool
	Groups        []string
	IdP           string
}

// has is whether m belongs to t.
//
// ⛔ Only a VERIFIED address's domain counts: an unverified one is a string
// the person typed, and typing somebody else's domain would be joining their
// tenant.
func (t Tenant) has(m Member) bool {
	if m.EmailVerified {
		if at := strings.LastIndex(m.Email, "@"); at >= 0 {
			domain := m.Email[at+1:]
			for _, d := range t.Domains {
				if strings.EqualFold(strings.TrimSpace(d), domain) {
					return true
				}
			}
		}
	}
	for _, g := range t.Groups {
		for _, mg := range m.Groups {
			if strings.TrimSpace(g) != "" && strings.TrimSpace(g) == mg {
				return true
			}
		}
	}
	if m.IdP != "" {
		for _, idp := range t.IdPs {
			if strings.TrimSpace(idp) == m.IdP {
				return true
			}
		}
	}
	return false
}

// For is every tenant m belongs to, by ID; the default tenant alone when m
// matches none.
func (s *Store) For(m Member) []Tenant {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Tenant
	for _, st := range s.tenants {
		if st.t.has(m) {
			out = append(out, st.t)
		}
	}
	if len(out) == 0 {
		return []Tenant{s.tenants[DefaultID].t}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// IsMember is whether m may connect to tenant id.
func (s *Store) IsMember(id string, m Member) bool {
	for _, t := range s.For(m) {
		if t.ID == id {
			return true
		}
	}
	return false
}

// Routes returns the current route set for a tenant (default if unknown).
func (s *Store) Routes(tenantID string) RouteSet {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.tenants[tenantID]
	if st == nil {
		st = s.tenants[DefaultID]
	}
	return RouteSet{AllowedIPs: st.t.AllowedIPs, DNS: st.t.DNS, Serial: st.t.Serial}
}

// List returns all tenants, sorted by ID.
func (s *Store) List() []Tenant {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Tenant, 0, len(s.tenants))
	for _, st := range s.tenants {
		out = append(out, st.t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Get returns one tenant.
func (s *Store) Get(id string) (Tenant, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.tenants[id]
	if !ok {
		return Tenant{}, false
	}
	return st.t, true
}

// Create adds a new tenant.
func (s *Store) Create(t Tenant) (Tenant, error) {
	t.ID = slug(t.ID)
	if t.ID == "" {
		t.ID = slug(t.Name)
	}
	if t.ID == "" {
		return Tenant{}, fmt.Errorf("tenant id or name required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.tenants[t.ID]; exists {
		return Tenant{}, fmt.Errorf("tenant %q already exists", t.ID)
	}
	t.Serial = 1
	s.tenants[t.ID] = &tenantState{t: t, subs: map[int]chan RouteSet{}}
	return t, nil
}

// Update replaces a tenant's metadata and routes, bumps the serial, and pushes
// the new route set to that tenant's watchers.
func (s *Store) Update(id string, in Tenant) (Tenant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.tenants[id]
	if !ok {
		return Tenant{}, fmt.Errorf("tenant %q not found", id)
	}
	st.t.Name = in.Name
	st.t.Domains = in.Domains
	st.t.Groups = in.Groups
	st.t.IdPs = in.IdPs
	st.t.AllowedIPs = in.AllowedIPs
	st.t.DNS = in.DNS
	st.t.Serial++
	s.broadcastLocked(st)
	return st.t, nil
}

// Delete removes a tenant (not the default one).
func (s *Store) Delete(id string) error {
	if id == DefaultID {
		return fmt.Errorf("cannot delete the default tenant")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.tenants[id]
	if !ok {
		return fmt.Errorf("tenant %q not found", id)
	}
	for _, ch := range st.subs {
		close(ch)
	}
	delete(s.tenants, id)
	return nil
}

// Subscribe registers a watcher for a tenant; returns an id, a channel of future
// updates, and the current set to send immediately.
func (s *Store) Subscribe(tenantID string) (int, <-chan RouteSet, RouteSet) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.tenants[tenantID]
	if st == nil {
		st = s.tenants[DefaultID]
	}
	id := s.nextSub
	s.nextSub++
	ch := make(chan RouteSet, 1)
	st.subs[id] = ch
	return id, ch, RouteSet{AllowedIPs: st.t.AllowedIPs, DNS: st.t.DNS, Serial: st.t.Serial}
}

// Unsubscribe removes a watcher.
func (s *Store) Unsubscribe(tenantID string, id int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.tenants[tenantID]
	if st == nil {
		st = s.tenants[DefaultID]
	}
	if ch, ok := st.subs[id]; ok {
		delete(st.subs, id)
		close(ch)
	}
}

// WatcherCount returns the total number of active watchers across tenants.
func (s *Store) WatcherCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, st := range s.tenants {
		n += len(st.subs)
	}
	return n
}

func (s *Store) broadcastLocked(st *tenantState) {
	set := RouteSet{AllowedIPs: st.t.AllowedIPs, DNS: st.t.DNS, Serial: st.t.Serial}
	for _, ch := range st.subs {
		select {
		case <-ch:
		default:
		}
		ch <- set
	}
}

func slug(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == ' ' || r == '_' || r == '-' || r == '.':
			b.WriteRune('-')
		}
	}
	return strings.Trim(b.String(), "-")
}
