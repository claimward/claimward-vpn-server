package peers

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/claimward/claimward-vpn-server/internal/fakeauthn"
	"github.com/go-authn/wireguard"
)

const (
	laptop = "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw="
	phone  = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="
)

func key(t *testing.T, s string) wireguard.Key {
	t.Helper()
	k, err := wireguard.ParseKey(s)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func registry(t *testing.T, p *fakeauthn.Provider) *Registry {
	t.Helper()
	src, err := wireguard.NewSource(context.Background(), wireguard.SourceConfig{Issuer: p.Issuer(), ClientID: fakeauthn.GatewayID, ClientSecret: fakeauthn.GatewaySecret})
	if err != nil {
		t.Fatal(err)
	}
	return New(src)
}

func TestARegistryAdmitsWhatTheListHas(t *testing.T) {
	p := fakeauthn.New(t)
	exp := time.Now().Add(time.Hour)
	p.SetPeers(1, wireguard.Peer{Key: key(t, laptop), Subject: "sub-alice", Expires: exp})
	r := registry(t, p)
	// Before any list: nobody.
	if _, ok := r.Lookup(laptop); ok {
		t.Error("a key was admitted before any list")
	}
	if _, err := r.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !r.Allowed(laptop, "sub-alice") {
		t.Error("alice's laptop is not allowed")
	}
	if r.Allowed(laptop, "sub-bob") {
		t.Error("alice's laptop is allowed to bob")
	}
	if r.Allowed(phone, "sub-alice") {
		t.Error("a key nobody registered is allowed")
	}
	// The list takes the laptop back: the next refresh says so.
	p.SetPeers(2)
	if _, err := r.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r.Allowed(laptop, "sub-alice") {
		t.Error("a key taken back is still allowed")
	}
}

// ⛔ Fails closed: a list past its expiry admits nobody new, and so does a
// registration past its lease.
func TestAnOldListAdmitsNobody(t *testing.T) {
	p := fakeauthn.New(t)
	p.SetPeers(1,
		wireguard.Peer{Key: key(t, laptop), Subject: "sub-alice", Expires: time.Now().Add(time.Hour)},
		wireguard.Peer{Key: key(t, phone), Subject: "sub-alice", Expires: time.Now().Add(-time.Minute)})
	r := registry(t, p)
	if _, err := r.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r.Allowed(phone, "sub-alice") {
		t.Error("a registration past its lease is allowed")
	}
	r.now = func() time.Time { return time.Now().Add(10 * time.Minute) } // the list lives five
	if r.Allowed(laptop, "sub-alice") {
		t.Error("a list past its expiry still admits")
	}
	// And a failed refresh keeps the previous list, until then.
	r.now = time.Now
	r.src = failing{}
	if _, err := r.Refresh(context.Background()); err == nil {
		t.Error("a failing source refreshed")
	}
	if !r.Allowed(laptop, "sub-alice") {
		t.Error("a failed refresh dropped the list it had")
	}
}

type failing struct{}

func (failing) Fetch(context.Context) (*wireguard.List, error) { return nil, io.ErrUnexpectedEOF }

// Run refreshes at once, on its ticker, and when kicked; and calls onList
// after each list -- not after a failure.
func TestRunRefreshesAndReports(t *testing.T) {
	p := fakeauthn.New(t)
	p.SetPeers(1)
	r := registry(t, p)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	kick := make(chan struct{})
	lists := make(chan *wireguard.List, 10)
	go r.Run(ctx, time.Hour, kick, func(l *wireguard.List) { lists <- l }, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if l := <-lists; l.Version != 1 {
		t.Fatalf("the first list is version %d", l.Version)
	}
	p.SetPeers(3, wireguard.Peer{Key: key(t, laptop), Subject: "sub-alice", Expires: time.Now().Add(time.Hour)})
	kick <- struct{}{}
	select {
	case l := <-lists:
		if l.Version != 3 || len(l.Peers) != 1 {
			t.Errorf("after a kick: version %d, %d peers", l.Version, len(l.Peers))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a kick fetched nothing")
	}
	// A failing source reports nothing, and Run carries on.
	r.src = failing{}
	kick <- struct{}{}
	select {
	case l := <-lists:
		t.Errorf("a failure reported a list: %+v", l)
	case <-time.After(200 * time.Millisecond):
	}
}
