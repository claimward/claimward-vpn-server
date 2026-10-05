// Package peers is the WireGuard keys people registered with a go-authn
// provider, as this gateway last read them (go-authn/wireguard).
//
// With AUTH_PROVIDER=go-authn a valid token is not enough to enroll: the
// device's public key must be one its owner registered at the provider,
// under the same subject. And when the provider takes a key back -- the
// person or their institution was disabled, or they removed the device --
// the next list no longer has it, and the gateway drops the peer.
package peers

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/go-authn/wireguard"
)

// A Source is where lists come from: a *wireguard.Source in production.
type Source interface {
	Fetch(ctx context.Context) (*wireguard.List, error)
}

// Registry holds the newest list. Safe for concurrent use.
type Registry struct {
	src Source
	now func() time.Time

	mu    sync.RWMutex
	list  *wireguard.List
	byKey map[string]wireguard.Peer
}

// New is a registry with no list yet: it admits nobody until Refresh.
func New(src Source) *Registry {
	return &Registry{src: src, now: time.Now}
}

// Refresh fetches the list and keeps it. On error the previous one stays,
// until it expires.
func (r *Registry) Refresh(ctx context.Context) (*wireguard.List, error) {
	l, err := r.src.Fetch(ctx)
	if err != nil {
		return nil, err
	}
	by := make(map[string]wireguard.Peer, len(l.Peers))
	for _, p := range l.Peers {
		by[p.Key.String()] = p
	}
	r.mu.Lock()
	r.list, r.byKey = l, by
	r.mu.Unlock()
	return l, nil
}

// Lookup is the registration of key, if the current list has it.
//
// ⛔ Fails closed: with no list, or one past its expiry -- the provider has
// been unreachable since -- nothing new is admitted, since a key taken back
// in the meantime would be admitted too. Peers already up are not torn down
// for it; they end with their leases.
func (r *Registry) Lookup(key string) (wireguard.Peer, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.list == nil || !r.now().Before(r.list.Expires) {
		return wireguard.Peer{}, false
	}
	p, ok := r.byKey[key]
	if !ok || !r.now().Before(p.Expires) {
		return wireguard.Peer{}, false
	}
	return p, true
}

// Allowed is whether key is registered to subject in the current list.
func (r *Registry) Allowed(key, subject string) bool {
	p, ok := r.Lookup(key)
	return ok && p.Subject == subject
}

// Run refreshes every interval until ctx ends, and after each list that
// arrives calls onList -- where the gateway drops what it no longer allows.
// A refresh can also be asked for now, through kick.
func (r *Registry) Run(ctx context.Context, interval time.Duration, kick <-chan struct{}, onList func(*wireguard.List), log *slog.Logger) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if l, err := r.Refresh(ctx); err != nil {
			log.Warn("go-authn peer list", "err", err)
		} else {
			onList(l)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-kick:
		}
	}
}
