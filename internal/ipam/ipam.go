// Package ipam is a tiny in-memory IP address manager that hands out host
// addresses from a CIDR pool to enrolled peers.
package ipam

import (
	"fmt"
	"net"
	"sync"
)

// Allocator allocates IPv4 host addresses from a pool. It is safe for
// concurrent use. State is in-memory only (MVP) — restarts start fresh, which
// is fine because clients re-enroll and the allocator is re-seeded from the
// peer store on startup via Reserve.
type Allocator struct {
	mu       sync.Mutex
	network  *net.IPNet
	serverIP net.IP
	used     map[string]bool // key: ip.String()
}

// New creates an Allocator for the given CIDR. The first usable host address is
// reserved for the gateway itself and returned as ServerIP.
func New(cidr string) (*Allocator, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("parse VPN CIDR %q: %w", cidr, err)
	}
	if ip.To4() == nil {
		return nil, fmt.Errorf("only IPv4 pools are supported: %q", cidr)
	}
	a := &Allocator{network: ipnet, used: map[string]bool{}}
	a.serverIP = a.firstHost()
	a.used[a.serverIP.String()] = true
	return a, nil
}

// ServerIP is the gateway's address inside the VPN (first host of the pool).
func (a *Allocator) ServerIP() net.IP { return a.serverIP }

// Allocate returns the next free host address.
func (a *Allocator) Allocate() (net.IP, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for ip := a.firstHost(); a.network.Contains(ip); ip = next(ip) {
		if isBroadcast(ip, a.network) {
			break
		}
		if !a.used[ip.String()] {
			a.used[ip.String()] = true
			return dup(ip), nil
		}
	}
	return nil, fmt.Errorf("address pool %s exhausted", a.network)
}

// Reserve marks a specific address as used (used to re-seed from the store on
// startup, or to keep a peer's existing IP). Returns false if already taken by
// someone else.
func (a *Allocator) Reserve(ip net.IP) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.network.Contains(ip) {
		return false
	}
	if a.used[ip.String()] {
		return false
	}
	a.used[ip.String()] = true
	return true
}

// Release returns an address to the pool.
func (a *Allocator) Release(ip net.IP) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.used, ip.String())
}

func (a *Allocator) firstHost() net.IP {
	ip := dup(a.network.IP.To4())
	return next(ip) // skip network address
}

func next(ip net.IP) net.IP {
	out := dup(ip.To4())
	for i := len(out) - 1; i >= 0; i-- {
		out[i]++
		if out[i] != 0 {
			break
		}
	}
	return out
}

func isBroadcast(ip net.IP, n *net.IPNet) bool {
	bc := dup(n.IP.To4())
	for i := range bc {
		bc[i] |= ^n.Mask[i]
	}
	return ip.Equal(bc)
}

func dup(ip net.IP) net.IP {
	out := make(net.IP, len(ip))
	copy(out, ip)
	return out
}
