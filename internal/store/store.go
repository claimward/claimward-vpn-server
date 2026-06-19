// Package store keeps the registry of enrolled peers in memory.
package store

import (
	"net"
	"sync"
	"time"

	"github.com/claimward/claimward-vpn-client/pkg/protocol"
)

// Peer is an enrolled device.
type Peer struct {
	PublicKey   string // wg base64
	Subject     string // OIDC sub
	Email       string
	Tenant      string // tenant ID assigned at enroll (by email domain)
	IP          net.IP
	Device      protocol.DeviceInfo
	EnrolledAt  time.Time
	LeaseExpiry time.Time
}

// Store is an in-memory peer registry, safe for concurrent use.
type Store struct {
	mu    sync.RWMutex
	peers map[string]*Peer // key: PublicKey
}

// New returns an empty Store.
func New() *Store {
	return &Store{peers: map[string]*Peer{}}
}

// Get returns the peer for a public key, or nil.
func (s *Store) Get(pubKey string) *Peer {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.peers[pubKey]
}

// Put inserts or replaces a peer.
func (s *Store) Put(p *Peer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.peers[p.PublicKey] = p
}

// Delete removes a peer and returns it (or nil if absent).
func (s *Store) Delete(pubKey string) *Peer {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.peers[pubKey]
	delete(s.peers, pubKey)
	return p
}

// Renew extends a peer's lease. Returns false if the peer is unknown.
func (s *Store) Renew(pubKey string, expiry time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.peers[pubKey]
	if !ok {
		return false
	}
	p.LeaseExpiry = expiry
	return true
}

// Expired returns peers whose lease ended at or before now.
func (s *Store) Expired(now time.Time) []*Peer {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*Peer
	for _, p := range s.peers {
		if !p.LeaseExpiry.After(now) {
			out = append(out, p)
		}
	}
	return out
}

// List returns a snapshot of all peers.
func (s *Store) List() []*Peer {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Peer, 0, len(s.peers))
	for _, p := range s.peers {
		out = append(out, p)
	}
	return out
}
