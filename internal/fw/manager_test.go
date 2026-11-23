package fw

import (
	"errors"
	"io"
	"log/slog"
	"reflect"
	"testing"
)

type failing struct {
	applied []Ruleset
	failOn  int // 1-based call that fails; 0 never
	failAll bool
}

func (f *failing) Apply(rs Ruleset) error {
	n := len(f.applied) + 1
	f.applied = append(f.applied, rs)
	if f.failAll || n == f.failOn {
		return errors.New("boom")
	}
	return nil
}

// ⛔ A failed install must not leave the previous (possibly broader) ruleset
// standing: deny-all replaces it, and the error is returned.
func TestSyncFailsClosed(t *testing.T) {
	ap := &failing{failOn: 1}
	m := NewManager("wg0", ap, func() []Tenant {
		return []Tenant{{ID: "a", Peers: addrs("10.80.0.2")}}
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := m.Sync(); err == nil {
		t.Fatal("Sync hid the failure")
	}
	if len(ap.applied) != 2 {
		t.Fatalf("applied %d rulesets, want the real one then deny-all", len(ap.applied))
	}
	if !reflect.DeepEqual(ap.applied[1], Build("wg0", nil)) {
		t.Fatalf("fallback is not deny-all: %+v", ap.applied[1])
	}
}

func TestSyncSucceeds(t *testing.T) {
	ap := &failing{}
	m := NewManager("wg0", ap, func() []Tenant { return nil }, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := m.Sync(); err != nil || len(ap.applied) != 1 {
		t.Fatalf("err=%v applied=%d", err, len(ap.applied))
	}
}
