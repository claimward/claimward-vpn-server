package ipam

import (
	"net"
	"sync"
)

// Manager hands out tunnel addresses per tenant: each tenant is addressed from
// its own subnet (derived from its routes), so a peer connected to tenant "test"
// gets an IP inside that tenant's network rather than a shared global pool.
//
// Tenants whose routes don't yield a usable host subnet fall back to a single
// shared pool (the server's global VPN CIDR), preserving the old behaviour.
//
// State is in-memory only, like the underlying Allocator: a restart starts fresh
// (the peer store is in-memory too, so both reset together and clients re-enroll).
type Manager struct {
	mu       sync.Mutex
	fallback *Allocator       // shared pool for tenants without a usable subnet
	byTenant map[string]*pool // per-tenant pools, keyed by tenant ID
}

type pool struct {
	alloc *Allocator
	cidr  string // the CIDR this pool was built for; rebuilt if the tenant's changes
}

// NewManager creates a Manager. fallbackCIDR is the shared pool used for tenants
// that have no usable addressing subnet of their own.
func NewManager(fallbackCIDR string) (*Manager, error) {
	fb, err := New(fallbackCIDR)
	if err != nil {
		return nil, err
	}
	return &Manager{fallback: fb, byTenant: map[string]*pool{}}, nil
}

// allocFor returns the allocator backing (tenantID, subnetCIDR). An empty
// subnetCIDR uses the shared fallback pool. A tenant whose subnet changed gets a
// freshly built allocator (old in-memory allocations are dropped — peers
// re-enroll). The caller must hold m.mu.
func (m *Manager) allocFor(tenantID, subnetCIDR string) (*Allocator, error) {
	if subnetCIDR == "" {
		return m.fallback, nil
	}
	if p := m.byTenant[tenantID]; p != nil && p.cidr == subnetCIDR {
		return p.alloc, nil
	}
	a, err := New(subnetCIDR)
	if err != nil {
		return nil, err
	}
	m.byTenant[tenantID] = &pool{alloc: a, cidr: subnetCIDR}
	return a, nil
}

// Allocate hands out a free address from the tenant's subnet (or the fallback
// pool when subnetCIDR is empty).
func (m *Manager) Allocate(tenantID, subnetCIDR string) (net.IP, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, err := m.allocFor(tenantID, subnetCIDR)
	if err != nil {
		return nil, err
	}
	return a.Allocate()
}

// Reserve marks a specific address as used in the tenant's pool (used to keep a
// device's existing IP across a re-enroll). Returns false if it's already taken
// or outside the pool.
func (m *Manager) Reserve(tenantID, subnetCIDR string, ip net.IP) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, err := m.allocFor(tenantID, subnetCIDR)
	if err != nil {
		return false
	}
	return a.Reserve(ip)
}

// Release returns an address to the tenant's pool (falling back to the shared
// pool when the tenant has no dedicated one or the IP belongs to the fallback).
func (m *Manager) Release(tenantID string, ip net.IP) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if p := m.byTenant[tenantID]; p != nil && p.alloc.network.Contains(ip) {
		p.alloc.Release(ip)
		return
	}
	m.fallback.Release(ip)
}
