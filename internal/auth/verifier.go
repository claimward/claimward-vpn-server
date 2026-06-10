// Package auth verifies OIDC ID tokens presented by clients and extracts the
// identity claims used for authorization.
package auth

import (
	"context"
	"fmt"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
)

// Claims is the subset of token claims claimward cares about.
type Claims struct {
	Subject       string
	Email         string
	EmailVerified bool
}

// Verifier validates ID tokens against an OIDC issuer for a given audience.
type Verifier struct {
	verifier       *oidc.IDTokenVerifier
	allowedDomains []string
}

// New builds a Verifier by discovering the issuer's configuration.
func New(ctx context.Context, issuer, clientID string, allowedDomains []string) (*Verifier, error) {
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery for %q: %w", issuer, err)
	}
	return &Verifier{
		verifier:       provider.Verifier(&oidc.Config{ClientID: clientID}),
		allowedDomains: allowedDomains,
	}, nil
}

// Verify checks the token signature/claims and applies the email-domain
// allowlist (if configured). It returns the extracted claims on success.
func (v *Verifier) Verify(ctx context.Context, rawIDToken string) (*Claims, error) {
	tok, err := v.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}
	var raw struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
	}
	if err := tok.Claims(&raw); err != nil {
		return nil, fmt.Errorf("decode claims: %w", err)
	}
	claims := &Claims{Subject: tok.Subject, Email: raw.Email, EmailVerified: raw.EmailVerified}

	if len(v.allowedDomains) > 0 {
		if !v.domainAllowed(claims.Email) {
			return nil, fmt.Errorf("email domain not allowed: %q", claims.Email)
		}
	}
	return claims, nil
}

func (v *Verifier) domainAllowed(email string) bool {
	at := strings.LastIndex(email, "@")
	if at < 0 {
		return false
	}
	domain := strings.ToLower(email[at+1:])
	for _, d := range v.allowedDomains {
		if strings.EqualFold(strings.TrimSpace(d), domain) {
			return true
		}
	}
	return false
}
