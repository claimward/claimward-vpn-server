// Package tenant is the multi-tenant route store: each tenant owns a set of
// WireGuard routes (AllowedIPs/DNS) and a broadcast channel so gRPC watchers of
// that tenant get pushed updates. A user may belong to several tenants; access
// is by explicit membership — an admin invites the user by email — and the user
// chooses which tenant to connect to.
//
// State is kept in memory and, when a file path is configured, mirrored to a
// JSON file so tenants and memberships survive restarts.
package tenant

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
)

// DefaultID is the built-in tenant. With membership-based access it is a regular
// tenant (it still cannot be deleted); a user sees it only if invited to it.
const DefaultID = "default"

// Tenant is the persisted configuration of a tenant.
type Tenant struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Domains    []string `json:"domains"`     // legacy; retained but no longer grants access
	Members    []string `json:"members"`     // invited user emails — the access list
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
	path    string // JSON file to persist tenants to; "" disables persistence
}

// New creates a Store. If path is non-empty and the file exists, tenants are
// loaded from it; otherwise the store is seeded with a default tenant carrying
// the given routes. When path is set, mutations are mirrored back to the file.
func New(path string, defaultAllowedIPs, defaultDNS []string) *Store {
	s := &Store{tenants: map[string]*tenantState{}, path: path}
	if path != "" {
		if data, err := os.ReadFile(path); err == nil {
			var loaded []Tenant
			if json.Unmarshal(data, &loaded) == nil {
				for _, t := range loaded {
					s.tenants[t.ID] = &tenantState{t: t, subs: map[int]chan RouteSet{}}
				}
			}
		}
	}
	if _, ok := s.tenants[DefaultID]; !ok {
		s.tenants[DefaultID] = &tenantState{
			t:    Tenant{ID: DefaultID, Name: "Default", AllowedIPs: defaultAllowedIPs, DNS: defaultDNS, Serial: 1},
			subs: map[int]chan RouteSet{},
		}
	}
	return s
}

// TenantsForEmail returns the tenants the user is a member of (invited to),
// sorted by ID. Membership is by exact, case-insensitive email match.
func (s *Store) TenantsForEmail(email string) []Tenant {
	email = strings.ToLower(strings.TrimSpace(email))
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Tenant
	for _, st := range s.tenants {
		if memberOf(st.t.Members, email) {
			out = append(out, st.t)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// IsMember reports whether email is a member of the given tenant.
func (s *Store) IsMember(tenantID, email string) bool {
	email = strings.ToLower(strings.TrimSpace(email))
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.tenants[tenantID]
	if !ok {
		return false
	}
	return memberOf(st.t.Members, email)
}

// memberOf reports whether email (already normalized) is in the member list.
func memberOf(members []string, email string) bool {
	for _, m := range members {
		if strings.EqualFold(strings.TrimSpace(m), email) {
			return true
		}
	}
	return false
}

// saveLocked writes the current tenants to the configured file. The caller must
// hold s.mu. No-op when persistence is disabled. Errors are returned so callers
// can log them.
func (s *Store) saveLocked() error {
	if s.path == "" {
		return nil
	}
	out := make([]Tenant, 0, len(s.tenants))
	for _, st := range s.tenants {
		out = append(out, st.t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
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
	if err := s.saveLocked(); err != nil {
		return Tenant{}, err
	}
	return t, nil
}

// Update replaces a tenant's metadata and routes, bumps the serial, and pushes
// the new route set to that tenant's watchers.
func (s *Store) Update(id string, name string, domains, members, allowedIPs, dns []string) (Tenant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.tenants[id]
	if !ok {
		return Tenant{}, fmt.Errorf("tenant %q not found", id)
	}
	st.t.Name = name
	st.t.Domains = domains
	st.t.Members = members
	st.t.AllowedIPs = allowedIPs
	st.t.DNS = dns
	st.t.Serial++
	s.broadcastLocked(st)
	if err := s.saveLocked(); err != nil {
		return Tenant{}, err
	}
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
	return s.saveLocked()
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
