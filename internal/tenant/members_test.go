package tenant

import (
	"context"
	"errors"
	"testing"
)

// directory is a Resolver over a fixed login -> ID table; a missing login is
// an error, as GitHub's 404 is.
func directory(ids map[string]int64) Resolver {
	return func(_ context.Context, login string) (int64, error) {
		if id, ok := ids[login]; ok {
			return id, nil
		}
		return 0, errors.New("no such user")
	}
}

func TestNamedMemberIsMatchedOnTheNumericID(t *testing.T) {
	s := New(nil, nil)
	s.SetResolver(directory(map[string]int64{"Octocat": 583231}))
	out, err := s.Create(Tenant{ID: "lab", Members: []string{" @Octocat ", "octocat"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Members) != 1 || out.Pinned["octocat"] != 583231 {
		t.Fatalf("members %v pinned %v", out.Members, out.Pinned)
	}
	if !s.IsMember("lab", Member{Subject: "github:583231"}) {
		t.Error("the pinned account is not a member")
	}
	if !s.NamedMember("github:583231") || !s.HasNamedMembers() {
		t.Error("the entry gate does not see the named member")
	}
	// ⛔ A renamed login, re-registered by somebody else, has another ID.
	if s.IsMember("lab", Member{Subject: "github:999999"}) || s.NamedMember("github:999999") {
		t.Error("an account that only has the same login was admitted")
	}
	if s.IsMember("lab", Member{Subject: ""}) || s.IsMember("lab", Member{Subject: "github:0"}) {
		t.Error("an empty subject matched")
	}
}

func TestAnUnresolvableLoginIsAnError(t *testing.T) {
	s := New(nil, nil)
	s.SetResolver(directory(map[string]int64{"alice": 1}))
	if _, err := s.Create(Tenant{ID: "lab", Members: []string{"alice", "ghost"}}); err == nil {
		t.Error("Create accepted an unresolvable login")
	}
	if err := s.Seed(Tenant{ID: "lab", Members: []string{"ghost"}}); err == nil {
		t.Error("Seed accepted an unresolvable login")
	}
	if _, err := s.Create(Tenant{ID: "ok", Members: []string{"alice"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Update("ok", Tenant{Members: []string{"ghost"}}); err == nil {
		t.Error("Update accepted an unresolvable login")
	}
	if got, _ := s.Get("ok"); got.Pinned["alice"] != 1 {
		t.Error("a refused update changed the tenant")
	}
	for _, bad := range []string{"../x", "a/b", "a b", "", "a?b"} {
		if _, err := s.Create(Tenant{ID: "bad", Members: []string{bad}}); err == nil {
			t.Errorf("login %q was accepted", bad)
		}
	}
}

func TestMembersNeedAResolver(t *testing.T) {
	s := New(nil, nil)
	if _, err := s.Create(Tenant{ID: "lab", Members: []string{"alice"}}); err == nil {
		t.Error("members were accepted with nobody to pin them")
	}
}

// Whatever a client sends as Pinned is replaced by what the resolver says.
func TestClientSuppliedPinsAreIgnored(t *testing.T) {
	s := New(nil, nil)
	s.SetResolver(directory(map[string]int64{"alice": 1}))
	out, err := s.Create(Tenant{ID: "lab", Members: []string{"alice"}, Pinned: map[string]int64{"mallory": 66}})
	if err != nil {
		t.Fatal(err)
	}
	if s.NamedMember("github:66") || len(out.Pinned) != 1 {
		t.Errorf("pinned = %v", out.Pinned)
	}
	// Dropping the members unpins them.
	if _, err := s.Update("lab", Tenant{Pinned: map[string]int64{"mallory": 66}}); err != nil {
		t.Fatal(err)
	}
	if s.HasNamedMembers() || s.NamedMember("github:1") || s.NamedMember("github:66") {
		t.Error("a removed member is still named")
	}
}

// ⛔ No fallback: a person matching no tenant belongs to none, the default one
// included, and an unknown tenant ID is an error, not the default's routes.
func TestNoDefaultFallback(t *testing.T) {
	s := New([]string{"10.0.0.0/8"}, nil)
	if got := s.For(Member{Email: "x@y.z", EmailVerified: true}); len(got) != 0 {
		t.Errorf("For = %v, want none", ids(got))
	}
	if s.IsMember(DefaultID, Member{}) {
		t.Error("the empty member belongs to the default tenant")
	}
	if _, err := s.Routes("nope"); !errors.Is(err, ErrUnknownTenant) {
		t.Errorf("Routes(unknown) err = %v", err)
	}
	if _, _, _, err := s.Subscribe("nope"); !errors.Is(err, ErrUnknownTenant) {
		t.Errorf("Subscribe(unknown) err = %v", err)
	}
	s.Unsubscribe("nope", 1) // must not panic
	if _, err := s.Routes(DefaultID); err != nil {
		t.Error(err)
	}
}

// The default tenant receives those it names, like any other.
func TestDefaultTenantTakesWhomItNames(t *testing.T) {
	s := New(nil, nil)
	if err := s.Seed(Tenant{ID: DefaultID, Domains: []string{"example.org"}}); err != nil {
		t.Fatal(err)
	}
	if got := ids(s.For(Member{Email: "a@example.org", EmailVerified: true})); !eq(got, []string{"default"}) {
		t.Errorf("For = %v", got)
	}
}
