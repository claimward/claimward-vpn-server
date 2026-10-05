package ssfpoll

import (
	"context"
	"io"
	"log/slog"
	"slices"
	"testing"

	"github.com/claimward/claimward-vpn-server/internal/fakeauthn"
)

func poller(p *fakeauthn.Provider, kick chan struct{}) *Poller {
	return New(Config{Issuer: p.Issuer(), ClientID: fakeauthn.GatewayID, ClientSecret: fakeauthn.GatewaySecret},
		kick, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

// An event kicks a fetch of the list, once however many arrive together,
// and is acknowledged at the next poll.
func TestAnEventKicksAFetch(t *testing.T) {
	p := fakeauthn.New(t)
	kick := make(chan struct{}, 1)
	r := poller(p, kick)
	ctx := context.Background()
	if err := r.Once(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-kick:
		t.Fatal("a kick with no event")
	default:
	}
	p.Event("e1")
	p.Event("e2")
	if err := r.Once(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-kick:
	default:
		t.Fatal("two events kicked nothing")
	}
	if err := r.Once(ctx); err != nil {
		t.Fatal(err)
	}
	slices.Sort(p.Acked)
	if !slices.Equal(p.Acked, []string{"e1", "e2"}) {
		t.Errorf("acknowledged %v", p.Acked)
	}
}

// One stream, reused: a receiver that made one per start would run out of
// the streams a provider allows it.
func TestTheStreamIsReused(t *testing.T) {
	p := fakeauthn.New(t)
	for range 3 {
		if err := poller(p, make(chan struct{}, 1)).Once(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if n := p.Streams(); n != 1 {
		t.Errorf("%d streams for three starts", n)
	}
}

// Wrong credentials, a provider in the clear, a provider not there: errors,
// not panics, and nothing kicked.
func TestWhatStopsAPoll(t *testing.T) {
	p := fakeauthn.New(t)
	kick := make(chan struct{}, 1)
	bad := New(Config{Issuer: p.Issuer(), ClientID: fakeauthn.GatewayID, ClientSecret: "wrong"}, kick, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := bad.Once(context.Background()); err == nil {
		t.Error("a wrong secret polled")
	}
	clear := New(Config{Issuer: "http://login.example.org", ClientID: "x", ClientSecret: "y"}, kick, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := clear.Once(context.Background()); err == nil {
		t.Error("a provider in the clear was asked")
	}
	nowhere := New(Config{Issuer: "http://127.0.0.1:1", ClientID: "x", ClientSecret: "y"}, kick, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := nowhere.Once(context.Background()); err == nil {
		t.Error("a provider that is not there was polled")
	}
	if len(kick) != 0 {
		t.Error("a failure kicked")
	}
}

// The receiver's secret and token cross only protected links; loopback has
// none to listen on. (The integration test above cannot tell: a cleartext
// host that does not resolve fails either way.)
func TestOnlyProtectedURLs(t *testing.T) {
	for raw, ok := range map[string]bool{
		"https://login.example.org/token": true,
		"http://127.0.0.1:8080/token":     true,
		"http://[::1]:8080/token":         true,
		"http://localhost/token":          true,
		"http://login.example.org/token":  false,
		"http://127.0.0.1.evil.example/":  false,
		"ftp://login.example.org/token":   false,
		"://":                             false,
	} {
		if err := protected(raw); (err == nil) != ok {
			t.Errorf("%q: %v", raw, err)
		}
	}
}
