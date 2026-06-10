package auth

import (
	"context"
	"fmt"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
)

// OIDCVerifier validates OIDC ID tokens against an issuer for a given audience.
type OIDCVerifier struct {
	verifier       *oidc.IDTokenVerifier
	allowedDomains []string
}

// NewOIDCVerifier builds an OIDCVerifier by discovering the issuer configuration.
func NewOIDCVerifier(ctx context.Context, issuer, clientID string, allowedDomains []string) (*OIDCVerifier, error) {
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery for %q: %w", issuer, err)
	}
	return &OIDCVerifier{
		verifier:       provider.Verifier(&oidc.Config{ClientID: clientID}),
		allowedDomains: allowedDomains,
	}, nil
}

// Verify checks the token signature/claims and applies the email-domain
// allowlist (if configured).
func (v *OIDCVerifier) Verify(ctx context.Context, rawIDToken string) (*Claims, error) {
	tok, err := v.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}
	var raw struct {
		Email             string `json:"email"`
		EmailVerified     bool   `json:"email_verified"`
		PreferredUsername string `json:"preferred_username"`
	}
	if err := tok.Claims(&raw); err != nil {
		return nil, fmt.Errorf("decode claims: %w", err)
	}
	claims := &Claims{
		Subject:       tok.Subject,
		Email:         raw.Email,
		EmailVerified: raw.EmailVerified,
		Login:         raw.PreferredUsername,
	}

	if len(v.allowedDomains) > 0 && !domainAllowed(claims.Email, v.allowedDomains) {
		return nil, fmt.Errorf("email domain not allowed: %q", claims.Email)
	}
	return claims, nil
}

func domainAllowed(email string, allowed []string) bool {
	at := strings.LastIndex(email, "@")
	if at < 0 {
		return false
	}
	domain := strings.ToLower(email[at+1:])
	for _, d := range allowed {
		if strings.EqualFold(strings.TrimSpace(d), domain) {
			return true
		}
	}
	return false
}
