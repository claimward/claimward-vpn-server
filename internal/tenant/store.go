// Package tenant is the multi-tenant route store: each tenant owns a set of
// WireGuard routes (AllowedIPs/DNS) and a broadcast channel so gRPC watchers of
// that tenant get pushed updates. Clients are mapped to a tenant by the email
// domain of their OIDC identity, falling back to the default tenant.
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
	Domains    []string `json:"domains"` // email domains mapped to this tenant
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

// TenantIDForEmail returns the tenant whose domains include the email's domain,
// or DefaultID.
func (s *Store) TenantIDForEmail(email string) string {
	at := strings.LastIndex(email, "@")
	if at < 0 {
		return DefaultID
	}
	domain := strings.ToLower(email[at+1:])
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, st := range s.tenants {
		for _, d := range st.t.Domains {
			if strings.EqualFold(strings.TrimSpace(d), domain) {
				return id
			}
		}
	}
	return DefaultID
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
func (s *Store) Update(id string, name string, domains, allowedIPs, dns []string) (Tenant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.tenants[id]
	if !ok {
		return Tenant{}, fmt.Errorf("tenant %q not found", id)
	}
	st.t.Name = name
	st.t.Domains = domains
	st.t.AllowedIPs = allowedIPs
	st.t.DNS = dns
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
