package tenant

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// Each guard in pin refuses on its own: the resolver is asked only for logins
// that are well formed, and an error or a non-positive ID from it is an error.
func TestPinRefusesWhatItCannotTrust(t *testing.T) {
	calls := 0
	count := func(id int64, err error) Resolver {
		return func(context.Context, string) (int64, error) { calls++; return id, err }
	}

	for _, bad := range []string{"bad login", "-lead", "a_b", "", strings.Repeat("a", 40), "x/../y"} {
		calls = 0
		s := New(nil, nil)
		s.SetResolver(count(7, nil))
		if _, err := s.Create(Tenant{ID: "lab", Members: []string{bad}}); err == nil {
			t.Errorf("login %q accepted", bad)
		}
		if calls != 0 {
			t.Errorf("login %q reached the resolver", bad)
		}
	}
	// 39 characters is the longest login GitHub allows.
	s := New(nil, nil)
	s.SetResolver(count(7, nil))
	if _, err := s.Create(Tenant{ID: "lab", Members: []string{strings.Repeat("a", 39)}}); err != nil {
		t.Errorf("a 39-character login refused: %v", err)
	}

	s = New(nil, nil)
	s.SetResolver(count(0, errors.New("boom")))
	if _, err := s.Create(Tenant{ID: "lab", Members: []string{"alice"}}); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Errorf("a resolver error was lost: %v", err)
	}
	for _, id := range []int64{0, -5} {
		s = New(nil, nil)
		s.SetResolver(count(id, nil))
		if _, err := s.Create(Tenant{ID: "lab", Members: []string{"alice"}}); err == nil {
			t.Errorf("ID %d accepted", id)
		}
	}
}

func TestMembersWithoutAResolverAreAnError(t *testing.T) {
	s := New(nil, nil)
	if _, err := s.Create(Tenant{ID: "lab", Members: []string{"alice"}}); err == nil || !strings.Contains(err.Error(), "resolver") {
		t.Errorf("err = %v", err)
	}
}

// An empty subject names nobody, even for a tenant that has pinned accounts.
func TestNamesNeverMatchesAnEmptySubject(t *testing.T) {
	tn := Tenant{Pinned: map[string]int64{"a": 1}}
	if tn.names("") || tn.names("github:") || !tn.names("github:1") {
		t.Error("names mismatch")
	}
}
