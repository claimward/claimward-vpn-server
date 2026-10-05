package auth

import (
	"context"
	"testing"
	"time"

	"github.com/claimward/claimward-vpn-server/internal/fakeauthn"
)

// The verifier takes access tokens from the provider, addressed here, and
// nothing else that provider signs.
func TestGoAuthnTakesAccessTokensOnly(t *testing.T) {
	p := fakeauthn.New(t)
	ctx := context.Background()
	v, err := NewGoAuthnVerifier(ctx, p.Issuer(), fakeauthn.Audience)
	if err != nil {
		t.Fatal(err)
	}
	c, err := v.Verify(ctx, p.AccessToken("sub-alice", "alice@univ.example", map[string]any{"email": "alice@univ.example", "email_verified": true}))
	if err != nil {
		t.Fatal(err)
	}
	if c.Subject != "sub-alice" || c.Login != "alice@univ.example" || c.Email != "alice@univ.example" {
		t.Errorf("claims: %+v", c)
	}
	// The groups and the institution, which tenants are matched on.
	c, err = v.Verify(ctx, p.AccessToken("sub-alice", "alice@univ.example", map[string]any{"groups": []string{"urn:mace:univ.example:hpc"}, "idp": "https://idp.univ.example/idp"}))
	if err != nil || len(c.Groups) != 1 || c.Groups[0] != "urn:mace:univ.example:hpc" || c.IdP != "https://idp.univ.example/idp" {
		t.Errorf("groups and idp: %+v, %v", c, err)
	}
	// An address the provider did not verify is not used.
	c, err = v.Verify(ctx, p.AccessToken("sub-bob", "bob", map[string]any{"email": "boss@univ.example", "email_verified": false}))
	if err != nil || c.Email != "" {
		t.Errorf("an unverified email: %+v, %v", c, err)
	}

	now := time.Now()
	idToken := p.Sign("JWT", map[string]any{"iss": p.Issuer(), "aud": fakeauthn.Audience, "sub": "sub-alice", "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()})
	for name, tok := range map[string]string{
		"an ID token, addressed to the client":      idToken,
		"an access token for another audience":      p.AccessToken("sub-alice", "alice", map[string]any{"aud": "elsewhere"}),
		"an access token addressed to the provider": p.AccessToken("sub-alice", "alice", map[string]any{"aud": p.Issuer()}),
		"an expired access token":                   p.AccessToken("sub-alice", "alice", map[string]any{"exp": now.Add(-time.Hour).Unix()}),
		"an access token with no subject":           p.AccessToken("", "alice", nil),
		"not a token":                               "alice",
	} {
		if _, err := v.Verify(ctx, tok); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestGoAuthnIsAProvider(t *testing.T) {
	p := fakeauthn.New(t)
	v, err := New(context.Background(), Options{Provider: "go-authn", Issuer: p.Issuer(), ClientID: fakeauthn.Audience})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := v.(*GoAuthnVerifier); !ok {
		t.Errorf("AUTH_PROVIDER=go-authn built a %T", v)
	}
	if _, err := New(context.Background(), Options{Provider: "go-authn", Issuer: "http://127.0.0.1:1", ClientID: "x"}); err == nil {
		t.Error("a provider that is not there was taken")
	}
}
