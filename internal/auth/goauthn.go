package auth

import (
	"context"
	"fmt"

	"github.com/go-authn/oidc"
)

// GoAuthnVerifier validates access tokens from a go-authn provider
// (go-authn/bridge): JWTs of type at+jwt, addressed to this server.
//
// ⛔ Access tokens, not ID tokens. An ID token is addressed to the client, and
// this server is usually configured with the client's id as its audience,
// so a verifier that took either would take a token the provider never
// meant for a resource server. RFC 9068 4: a resource server MUST check that
// typ is at+jwt -- which go-authn/oidc does when it is asked to.
type GoAuthnVerifier struct {
	v *oidc.Verifier
}

// NewGoAuthnVerifier discovers the issuer. audience is what the provider
// addresses this server's tokens to: the client's id, unless the provider
// was configured with another audience for it.
func NewGoAuthnVerifier(ctx context.Context, issuer, audience string) (*GoAuthnVerifier, error) {
	v, err := oidc.New(ctx, oidc.Config{Issuer: issuer, Audience: audience, Type: "at+jwt"})
	if err != nil {
		return nil, fmt.Errorf("go-authn discovery for %q: %w", issuer, err)
	}
	return &GoAuthnVerifier{v: v}, nil
}

// Verify checks the token and names the person. The subject is what a
// go-authn provider's WireGuard list calls them, for this client.
func (g *GoAuthnVerifier) Verify(ctx context.Context, bearer string) (*Claims, error) {
	tok, err := g.v.Verify(ctx, bearer)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}
	if tok.Subject() == "" {
		return nil, fmt.Errorf("invalid token: no subject")
	}
	c := &Claims{Subject: tok.Subject(), Login: tok.Username(), EmailVerified: tok.EmailVerified(), Groups: tok.Groups()}
	_ = tok.Claim("idp", &c.IdP)
	// An unverified address is a string the person typed: tenant mapping is
	// by email, so only one the provider verified is used.
	if c.EmailVerified {
		c.Email = tok.Email()
	}
	return c, nil
}
