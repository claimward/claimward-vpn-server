package main

import (
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/claimward/claimward-vpn-server/internal/fw"
	"github.com/claimward/claimward-vpn-server/internal/store"
	"github.com/claimward/claimward-vpn-server/internal/tenant"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

type applier struct {
	calls int
	err   error
}

func (a *applier) Apply(fw.Ruleset) error { a.calls++; return a.err }

func writeFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "tenants.json")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadTenants(t *testing.T) {
	ts := tenant.New([]string{"10.0.0.0/8"}, nil)
	if err := loadTenants(ts, "", quiet); err != nil {
		t.Fatalf("no file configured: %v", err)
	}
	if err := loadTenants(ts, filepath.Join(t.TempDir(), "absent.json"), quiet); err == nil {
		t.Error("a missing tenants file was ignored")
	}
	if err := loadTenants(ts, writeFile(t, `[{"id":"x","policy":[{"cidr":"10.0.0.1/32","proto":"tcp"}]}]`), quiet); err == nil {
		t.Error("an invalid policy was loaded")
	}
	if err := loadTenants(ts, writeFile(t, `[{"id":"","name":""}]`), quiet); err == nil {
		t.Error("a tenant with no id was loaded")
	}
	good := writeFile(t, `[{"id":"default","policy":[{"cidr":"10.20.0.5/32","proto":"tcp","ports":[445]}]}]`)
	if err := loadTenants(ts, good, quiet); err != nil {
		t.Fatal(err)
	}
	if got := ts.Routes(tenant.DefaultID).AllowedIPs; len(got) != 1 || got[0] != "10.20.0.5/32" {
		t.Fatalf("default routes = %v", got)
	}
}

// ⛔ No ruleset, no server.
func TestStartFirewallFailsClosed(t *testing.T) {
	ts, st := tenant.New(nil, nil), store.New()
	if _, err := startFirewall("wg0", &applier{err: errors.New("EPERM")}, ts, st, quiet); err == nil {
		t.Fatal("the server would start without a firewall")
	}
	ap := &applier{}
	if _, err := startFirewall("wg0", ap, ts, st, quiet); err != nil {
		t.Fatal(err)
	}
	if ap.calls != 1 {
		t.Fatalf("installed %d times at start", ap.calls)
	}
	// A tenant change re-installs it.
	if _, err := ts.Create(tenant.Tenant{ID: "x"}); err != nil {
		t.Fatal(err)
	}
	if ap.calls != 2 {
		t.Fatalf("installed %d times after a tenant was created", ap.calls)
	}
}
