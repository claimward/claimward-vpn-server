// Package tenant is the multi-tenant route store: each tenant owns a set of
// WireGuard routes (AllowedIPs/DNS) and a broadcast channel so gRPC watchers of
// that tenant get pushed updates.
//
// A person may belong to several tenants, and chooses one per session (the
// enrollment names it). Membership is by any of: the verified email's domain,
// a group the identity provider says they are in, the institution that
// vouched for them (a go-authn provider's "idp"), or being NAMED: a GitHub
// login the tenant lists, pinned to the account's numeric ID. Somebody who
// matches no tenant belongs to none, and is refused: there is no fallback.
//
// State is in-memory (MVP), mirroring the rest of the server.
package tenant

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/claimward/claimward-vpn-server/internal/policy"
)

// DefaultID is the tenant used for identities that match no domain.
const DefaultID = "default"

// Tenant is the persisted configuration of a tenant.
type Tenant struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Domains []string `json:"domains"` // verified email domains that are members
	Groups  []string `json:"groups"`  // groups (token "groups" claim, GitHub orgs) that are members
	IdPs    []string `json:"idps"`    // institutions (go-authn "idp", a SAML entity ID) that are members
	// Members are GitHub LOGINS, named one by one. A login can be renamed and
	// then claimed by somebody else, so the store never matches on it: it
	// resolves each to the account's numeric ID when the tenant is saved and
	// matches the token's subject ("github:<id>") against that.
	Members []string `json:"members,omitempty"`
	// Pinned is the login -> numeric ID of each member, as resolved. Read-only:
	// whatever a client sends here is replaced.
	Pinned map[string]int64 `json:"pinned,omitempty"`
	// Policy is what the tenant's peers may reach: the gateway ENFORCES it
	// (internal/fw) and the routes pushed to clients derive from it. When it
	// is set, AllowedIPs is overwritten with those routes.
	Policy []policy.Rule `json:"policy,omitempty"`
	// AllowedIPs, with no Policy, is the legacy form: every protocol and port
	// to those CIDRs.
	AllowedIPs []string `json:"allowed_ips"`
	DNS        []string `json:"dns"`
	Serial     uint64   `json:"serial"`
}

// Rules is the tenant's effective policy: Policy, or the legacy form of
// AllowedIPs. A tenant with neither reaches nothing.
func (t Tenant) Rules() []policy.Rule {
	if len(t.Policy) > 0 {
		return t.Policy
	}
	return policy.Legacy(t.AllowedIPs)
}

// normalize validates the policy and derives the routes from it.
func (t *Tenant) normalize() error {
	if err := policy.Validate(t.Policy); err != nil {
		return err
	}
	if len(t.Policy) > 0 {
		t.AllowedIPs = policy.Routes(t.Policy)
	}
	return nil
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

	onChange func() // after a tenant's policy or existence changes
	resolver Resolver
}

// Resolver turns a GitHub login into the account's numeric ID, or fails: an
// unknown login is an error, never a guess.
type Resolver func(ctx context.Context, login string) (int64, error)

// SetResolver registers how member logins are pinned. Without one, a tenant
// naming members is refused.
func (s *Store) SetResolver(r Resolver) {
	s.mu.Lock()
	s.resolver = r
	s.mu.Unlock()
}

// ErrUnknownTenant is returned for a tenant ID that does not exist.
var ErrUnknownTenant = errors.New("unknown tenant")

var loginRE = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$`)

// resolveTimeout bounds the resolution of one tenant's members.
const resolveTimeout = 30 * time.Second

// pin validates t.Members and pins each login to its numeric ID. The network
// calls run without the store's lock held.
func (s *Store) pin(t *Tenant) error {
	t.Pinned = nil
	if len(t.Members) == 0 {
		t.Members = nil
		return nil
	}
	s.mu.Lock()
	r := s.resolver
	s.mu.Unlock()
	if r == nil {
		return fmt.Errorf("members need a GitHub resolver, and none is configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), resolveTimeout)
	defer cancel()
	seen := map[string]bool{}
	var logins []string
	pinned := map[string]int64{}
	for _, l := range t.Members {
		l = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(l), "@"))
		if !loginRE.MatchString(l) {
			return fmt.Errorf("member %q is not a GitHub login", l)
		}
		key := strings.ToLower(l)
		if seen[key] {
			continue
		}
		seen[key] = true
		id, err := r(ctx, l)
		if err != nil {
			return fmt.Errorf("member %q: %w", l, err)
		}
		if id <= 0 {
			return fmt.Errorf("member %q: no account ID", l)
		}
		logins = append(logins, l)
		pinned[key] = id
	}
	t.Members, t.Pinned = logins, pinned
	return nil
}

// NamedMember is whether subject ("github:<id>") is pinned by any tenant.
func (s *Store) NamedMember(subject string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, st := range s.tenants {
		if st.t.names(subject) {
			return true
		}
	}
	return false
}

// HasNamedMembers is whether any tenant names a member.
func (s *Store) HasNamedMembers() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, st := range s.tenants {
		if len(st.t.Pinned) > 0 {
			return true
		}
	}
	return false
}

// names is whether subject is one of the tenant's pinned accounts.
func (t Tenant) names(subject string) bool {
	if subject == "" {
		return false
	}
	for _, id := range t.Pinned {
		if subject == "github:"+strconv.FormatInt(id, 10) {
			return true
		}
	}
	return false
}

// SetOnChange registers fn, called (outside the store's lock) after a tenant
// is created, updated or deleted: the gateway re-installs its firewall.
func (s *Store) SetOnChange(fn func()) {
	s.mu.Lock()
	s.onChange = fn
	s.mu.Unlock()
}

func (s *Store) changed() {
	s.mu.Lock()
	fn := s.onChange
	s.mu.Unlock()
	if fn != nil {
		fn()
	}
}

// Seed creates tenant t, or replaces the configuration of the one with that
// ID (the default tenant, from a tenants file). Startup only: no watcher is
// told and no callback runs.
func (s *Store) Seed(t Tenant) error {
	t.ID = slug(t.ID)
	if t.ID == "" {
		t.ID = slug(t.Name)
	}
	if t.ID == "" {
		return fmt.Errorf("tenant id or name required")
	}
	if err := t.normalize(); err != nil {
		return fmt.Errorf("tenant %q: %w", t.ID, err)
	}
	if err := s.pin(&t); err != nil {
		return fmt.Errorf("tenant %q: %w", t.ID, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	t.Serial = 1
	if old, ok := s.tenants[t.ID]; ok {
		t.Serial = old.t.Serial + 1
		old.t = t
		return nil
	}
	s.tenants[t.ID] = &tenantState{t: t, subs: map[int]chan RouteSet{}}
	return nil
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
	Subject       string // provider-scoped ID, "github:<id>": what named members are matched on
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
	if t.names(m.Subject) {
		return true
	}
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

// For is every tenant m belongs to, by ID; none when m matches none. There is
// no fallback: the default tenant receives only those it names.
func (s *Store) For(m Member) []Tenant {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Tenant
	for _, st := range s.tenants {
		if st.t.has(m) {
			out = append(out, st.t)
		}
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

// Routes returns the current route set for a tenant; an unknown tenant is
// ErrUnknownTenant, never the default tenant's routes.
func (s *Store) Routes(tenantID string) (RouteSet, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.tenants[tenantID]
	if st == nil {
		return RouteSet{}, fmt.Errorf("%w %q", ErrUnknownTenant, tenantID)
	}
	return RouteSet{AllowedIPs: st.t.AllowedIPs, DNS: st.t.DNS, Serial: st.t.Serial}, nil
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
	if err := t.normalize(); err != nil {
		return Tenant{}, err
	}
	if err := s.pin(&t); err != nil {
		return Tenant{}, err
	}
	s.mu.Lock()
	if _, exists := s.tenants[t.ID]; exists {
		s.mu.Unlock()
		return Tenant{}, fmt.Errorf("tenant %q already exists", t.ID)
	}
	t.Serial = 1
	s.tenants[t.ID] = &tenantState{t: t, subs: map[int]chan RouteSet{}}
	s.mu.Unlock()
	s.changed()
	return t, nil
}

// Update replaces a tenant's metadata and routes, bumps the serial, and pushes
// the new route set to that tenant's watchers.
func (s *Store) Update(id string, in Tenant) (Tenant, error) {
	if err := in.normalize(); err != nil {
		return Tenant{}, err
	}
	if err := s.pin(&in); err != nil {
		return Tenant{}, err
	}
	s.mu.Lock()
	st, ok := s.tenants[id]
	if !ok {
		s.mu.Unlock()
		return Tenant{}, fmt.Errorf("tenant %q not found", id)
	}
	st.t.Name = in.Name
	st.t.Domains = in.Domains
	st.t.Groups = in.Groups
	st.t.IdPs = in.IdPs
	st.t.Members = in.Members
	st.t.Pinned = in.Pinned
	st.t.Policy = in.Policy
	st.t.AllowedIPs = in.AllowedIPs
	st.t.DNS = in.DNS
	st.t.Serial++
	s.broadcastLocked(st)
	out := st.t
	s.mu.Unlock()
	s.changed()
	return out, nil
}

// Delete removes a tenant (not the default one).
func (s *Store) Delete(id string) error {
	if id == DefaultID {
		return fmt.Errorf("cannot delete the default tenant")
	}
	s.mu.Lock()
	st, ok := s.tenants[id]
	if !ok {
		s.mu.Unlock()
		return fmt.Errorf("tenant %q not found", id)
	}
	for _, ch := range st.subs {
		close(ch)
	}
	delete(s.tenants, id)
	s.mu.Unlock()
	s.changed()
	return nil
}

// Subscribe registers a watcher for a tenant; returns an id, a channel of future
// updates, and the current set to send immediately.
// An unknown tenant is ErrUnknownTenant, never the default tenant's routes.
func (s *Store) Subscribe(tenantID string) (int, <-chan RouteSet, RouteSet, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.tenants[tenantID]
	if st == nil {
		return 0, nil, RouteSet{}, fmt.Errorf("%w %q", ErrUnknownTenant, tenantID)
	}
	id := s.nextSub
	s.nextSub++
	ch := make(chan RouteSet, 1)
	st.subs[id] = ch
	return id, ch, RouteSet{AllowedIPs: st.t.AllowedIPs, DNS: st.t.DNS, Serial: st.t.Serial}, nil
}

// Unsubscribe removes a watcher; an unknown tenant has none.
func (s *Store) Unsubscribe(tenantID string, id int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.tenants[tenantID]
	if st == nil {
		return
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
