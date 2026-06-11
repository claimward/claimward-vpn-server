// Package routes holds the current set of routes (WireGuard AllowedIPs) the
// server advertises, and broadcasts changes to gRPC watchers.
package routes

import "sync"

// Set is a snapshot of the advertised routes.
type Set struct {
	AllowedIPs []string
	DNS        []string
	Serial     uint64
}

// Manager stores the current route set and fans out updates to subscribers.
type Manager struct {
	mu   sync.Mutex
	cur  Set
	subs map[int]chan Set
	next int
}

// New seeds the manager with the initial routes (serial 1).
func New(allowedIPs, dns []string) *Manager {
	return &Manager{
		cur:  Set{AllowedIPs: allowedIPs, DNS: dns, Serial: 1},
		subs: map[int]chan Set{},
	}
}

// Current returns the current route set.
func (m *Manager) Current() Set {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cur
}

// Set replaces the routes (bumping the serial) and notifies all subscribers.
func (m *Manager) Set(allowedIPs, dns []string) Set {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cur = Set{AllowedIPs: allowedIPs, DNS: dns, Serial: m.cur.Serial + 1}
	for _, ch := range m.subs {
		// Coalesce: keep only the latest value in each 1-deep buffer.
		select {
		case <-ch:
		default:
		}
		ch <- m.cur
	}
	return m.cur
}

// Subscribe registers a watcher; it returns an id, a channel of future updates,
// and the current set to send immediately.
func (m *Manager) Subscribe() (int, <-chan Set, Set) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id := m.next
	m.next++
	ch := make(chan Set, 1)
	m.subs[id] = ch
	return id, ch, m.cur
}

// Unsubscribe removes a watcher.
func (m *Manager) Unsubscribe(id int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ch, ok := m.subs[id]; ok {
		delete(m.subs, id)
		close(ch)
	}
}
