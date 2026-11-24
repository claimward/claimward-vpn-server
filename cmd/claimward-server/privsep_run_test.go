package main

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/claimward/claimward-vpn-server/internal/fw"
	"github.com/claimward/claimward-vpn-server/internal/privsep"
)

// linkBackend is the privileged side of a run, with the failures chosen.
type linkBackend struct{ sweepErr, mtuErr error }

func (linkBackend) AddPeer([privsep.KeySize]byte, netip.Addr) error { return nil }
func (linkBackend) RemovePeer([privsep.KeySize]byte) error          { return nil }
func (b linkBackend) Sweep() (int, error)                           { return 0, b.sweepErr }
func (b linkBackend) SetTunnelMTU(int) (int, error)                 { return 1420, b.mtuErr }
func (linkBackend) ApplyTenants([]fw.Tenant, int) error             { return nil }

// runOverALink runs the unprivileged side against a real parent session.
func runOverALink(t *testing.T, b linkBackend) error {
	t.Helper()
	runEnv(t)
	c, s := net.Pipe()
	srv := privsep.NewServer(b, privsep.Limits{Pool: netip.MustParsePrefix("10.80.0.0/24"), MinMTU: 1280, MaxMTU: 9000}, quiet)
	go func() { _ = srv.Serve(s) }()
	link := privsep.NewClient(c)
	t.Cleanup(func() { _ = link.Close() })
	// Were a guard gone, run would serve: end it rather than hang the suite.
	stop := time.AfterFunc(3*time.Second, func() {
		if p, err := os.FindProcess(os.Getpid()); err == nil {
			_ = p.Signal(os.Interrupt)
		}
	})
	defer stop.Stop()
	return run(quiet, link)
}

func TestRunStopsWhenTheParentCannotSweepThePeers(t *testing.T) {
	err := runOverALink(t, linkBackend{sweepErr: errors.New("EPERM")})
	if err == nil || !strings.Contains(err.Error(), "previous run") {
		t.Fatalf("err = %v, want the sweep failure", err)
	}
}

func TestRunStopsWhenTheParentCannotSetTheMTU(t *testing.T) {
	err := runOverALink(t, linkBackend{mtuErr: errors.New("EPERM")})
	if err == nil || !strings.Contains(err.Error(), "EPERM") {
		t.Fatalf("err = %v, want the MTU failure", err)
	}
}

// ⛔ Fail closed: an unprivileged process that could not restrict itself does
// not serve. Where lockdown can succeed (OpenBSD) this is proven by rcproof.
func TestRunStopsWhenTheProcessCannotRestrictItself(t *testing.T) {
	if runtime.GOOS == "openbsd" {
		t.Skip("lockdown succeeds here; rcproof covers the refusal")
	}
	err := runOverALink(t, linkBackend{})
	if err == nil || !strings.Contains(err.Error(), "restrict") {
		t.Fatalf("err = %v, want the lockdown failure", err)
	}
}
