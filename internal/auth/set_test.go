package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/claimward/claimward-vpn-server/internal/fakeauthn"
)

// stub accepts one bearer and counts how often it was asked.
type stub struct {
	token string
	asked int
}

func (s *stub) Verify(_ context.Context, bearer string) (*Claims, error) {
	s.asked++
	if bearer != s.token {
		return nil, errors.New("bad token")
	}
	return &Claims{Subject: "sub", Groups: []string{"g"}}, nil
}

func TestSetVerifiesWithTheNamedProviderOnly(t *testing.T) {
	a, b := &stub{token: "token-of-a"}, &stub{token: "token-of-b"}
	s := NewSet()
	if err := s.Add("a", a); err != nil {
		t.Fatal(err)
	}
	if err := s.Add("b", b); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	c, err := s.Verify(ctx, "a", "token-of-a")
	if err != nil || c.Provider != "a" {
		t.Fatalf("a's token at a: %+v, %v", c, err)
	}
	// ⛔ The token of A, with the request naming B: refused, and A is never asked
	// (a token is never tried against another provider).
	if _, err := verifyNoPanic(t, s, "b", "token-of-a"); err == nil {
		t.Error("the token of A was accepted for B")
	}
	if a.asked != 1 {
		t.Errorf("provider a was asked %d times, want only the first", a.asked)
	}
	if c, err := s.Verify(ctx, "b", "token-of-b"); err != nil || c.Provider != "b" {
		t.Errorf("b's token at b: %+v, %v", c, err)
	}
}

func TestSetRefusesAMissingOrUnknownProvider(t *testing.T) {
	a := &stub{token: "t"}
	s := NewSet()
	if err := s.Add("a", a); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Verify(context.Background(), "", "t"); !errors.Is(err, ErrMissingProvider) {
		t.Errorf("no provider named: %v", err)
	}
	for _, id := range []string{"nope", "A", "a ", "a/../b"} {
		if _, err := verifyNoPanic(t, s, id, "t"); !errors.Is(err, ErrUnknownProvider) {
			t.Errorf("provider %q: %v", id, err)
		}
	}
	if a.asked != 0 {
		t.Errorf("a token was checked although no known provider was named (%d)", a.asked)
	}
	if err := s.Add("a", a); err == nil {
		t.Error("an id added twice")
	}
	if _, ok := s.Get("a"); !ok {
		t.Error("Get does not find a")
	}
	if _, ok := s.Get("nope"); ok {
		t.Error("Get finds nope")
	}
}

// ⛔ Two issuers may both have a person whose "sub" is the same: they are two
// identities, and the ISSUER (not the local provider id) namespaces them.
func TestTheSameSubFromTwoIssuersIsTwoIdentities(t *testing.T) {
	ctx := context.Background()
	p1, p2 := fakeauthn.New(t), fakeauthn.New(t)
	if p1.Issuer() == p2.Issuer() {
		t.Fatal("the fake providers share an issuer")
	}
	v1, err := NewGoAuthnVerifier(ctx, p1.Issuer(), fakeauthn.Audience)
	if err != nil {
		t.Fatal(err)
	}
	v2, err := NewGoAuthnVerifier(ctx, p2.Issuer(), fakeauthn.Audience)
	if err != nil {
		t.Fatal(err)
	}
	s := NewSet()
	if err := s.Add("one", v1); err != nil {
		t.Fatal(err)
	}
	if err := s.Add("two", v2); err != nil {
		t.Fatal(err)
	}
	c1, err := s.Verify(ctx, "one", p1.AccessToken("42", "alice", nil))
	if err != nil {
		t.Fatal(err)
	}
	c2, err := s.Verify(ctx, "two", p2.AccessToken("42", "alice", nil))
	if err != nil {
		t.Fatal(err)
	}
	if c1.Subject == c2.Subject {
		t.Fatalf("one identity for two issuers: %q", c1.Subject)
	}
	if c1.Subject != p1.Issuer()+"#42" || c2.Subject != p2.Issuer()+"#42" {
		t.Errorf("subjects %q and %q", c1.Subject, c2.Subject)
	}
	if c1.Native != "42" || c2.Native != "42" {
		t.Errorf("native subjects %q and %q", c1.Native, c2.Native)
	}
	// And the token of one issuer, shown to the other provider, is no identity.
	if _, err := verifyNoPanic(t, s, "two", p1.AccessToken("42", "alice", nil)); err == nil {
		t.Error("the token of issuer one was accepted by provider two")
	}
	// Renaming a provider's id changes no identity: the subject names the issuer.
	r := NewSet()
	if err := r.Add("renamed", v1); err != nil {
		t.Fatal(err)
	}
	c3, err := r.Verify(ctx, "renamed", p1.AccessToken("42", "alice", nil))
	if err != nil || c3.Subject != c1.Subject {
		t.Errorf("renamed provider: %+v, %v (want %q)", c3, err, c1.Subject)
	}
}

// Groups reach the tenants scoped by the provider that vouched for them.
func TestTenancyScopesGroupsByProvider(t *testing.T) {
	c := &Claims{Provider: "campus", Subject: "s", Groups: []string{"hpc", "chem"}}
	m := c.Tenancy()
	if m.Provider != "campus" || len(m.Groups) != 2 || m.Groups[0] != "campus:hpc" || m.Groups[1] != "campus:chem" {
		t.Errorf("tenancy: %+v", m)
	}
}

// verifyNoPanic calls s.Verify and fails the test, as an assertion, if it
// panics: a refusal that is missing must read as a wrong answer, not a crash.
func verifyNoPanic(t *testing.T, s *Set, id, bearer string) (c *Claims, err error) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Verify(%q) crashed instead of answering: %v", id, r)
			err = errors.New("crashed")
		}
	}()
	return s.Verify(context.Background(), id, bearer)
}

func TestSetUnknownProviderAndFailedTokenAreRefusedNotCrashed(t *testing.T) {
	s := NewSet()
	if err := s.Add("a", &stub{token: "good"}); err != nil {
		t.Fatal(err)
	}
	c, err := verifyNoPanic(t, s, "nope", "good")
	if c != nil || !errors.Is(err, ErrUnknownProvider) {
		t.Errorf("unknown provider: %+v, %v", c, err)
	}
	c, err = verifyNoPanic(t, s, "a", "bad")
	if c != nil || err == nil || err.Error() != "bad token" {
		t.Errorf("failed token: %+v, %v", c, err)
	}
}
