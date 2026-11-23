package main

import (
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
	if err := loadTenants(ts, filepath.Join(t.TempDir(), "absent.json"), quiet); err == nil || !strings.Contains(err.Error(), "read TENANTS_FILE") {
		t.Errorf("a missing tenants file: %v", err)
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

func runEnv(t *testing.T) {
	t.Helper()
	t.Setenv("WG_DRYRUN", "true")
	t.Setenv("WG_ENDPOINT", "vpn.example.org:51820")
	t.Setenv("WG_PRIVATE_KEY", "YPnXq6Z6cBZ7bmF3ZyYh8mEYV0Q1qS6mQH2k6jH6s3A=")
	t.Setenv("LISTEN_ADDR", "127.0.0.1:0")
	t.Setenv("GRPC_ADDR", "127.0.0.1:0")
	t.Setenv("METRICS_ADDR", "127.0.0.1:0")
	t.Setenv("GITHUB_ALLOWED_ORGS", "claimward")
}

func TestRunRefusesABadTenantsFile(t *testing.T) {
	runEnv(t)
	t.Setenv("TENANTS_FILE", filepath.Join(t.TempDir(), "absent.json"))
	stop := time.AfterFunc(3*time.Second, func() {
		if p, err := os.FindProcess(os.Getpid()); err == nil {
			_ = p.Signal(os.Interrupt)
		}
	})
	defer stop.Stop()
	if err := run(quiet); err == nil {
		t.Fatal("run went on with an unreadable tenants file")
	}
}

// ⛔ No ruleset, no server -- through run itself.
func TestRunDoesNotStartWithoutAFirewall(t *testing.T) {
	runEnv(t)
	old := newApplier
	t.Cleanup(func() { newApplier = old })
	newApplier = func(bool, *slog.Logger) fw.Applier { return &applier{err: errors.New("EPERM")} }
	// Were the guard gone, run would serve: end it rather than hang the suite.
	stop := time.AfterFunc(3*time.Second, func() {
		if p, err := os.FindProcess(os.Getpid()); err == nil {
			_ = p.Signal(os.Interrupt)
		}
	})
	defer stop.Stop()
	if err := run(quiet); err == nil {
		t.Fatal("run started without a firewall")
	}
}

func TestNewApplier(t *testing.T) {
	if _, ok := newApplier(true, quiet).(fw.Discard); !ok {
		t.Error("dry run must not touch the kernel")
	}
	if _, ok := newApplier(false, quiet).(fw.Discard); ok {
		t.Error("a real run must not discard the ruleset")
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
