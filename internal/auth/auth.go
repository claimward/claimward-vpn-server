// Package auth authenticates the bearer credential presented by clients and
// extracts the identity claims used for authorization.
//
// Claimward supports pluggable identity providers behind the Verifier interface:
//
//   - github (default): the bearer is a GitHub OAuth access token; it is validated
//     by calling the GitHub API, with optional org-membership authorization.
//   - oidc: the bearer is an OIDC ID token; it is verified against the issuer.
//
// Add a provider by implementing Verifier and wiring it into New.
package auth

import (
	"context"
	"fmt"
)

// Claims is the subset of identity we care about, normalized across providers.
type Claims struct {
	// Subject is a stable, provider-scoped identifier, e.g. "github:1234" or the
	// OIDC "sub". It is what peer ownership is keyed on.
	Subject       string
	Email         string
	EmailVerified bool
	Login         string // human handle (GitHub login / OIDC preferred_username), best-effort
}

// Verifier validates a bearer credential and returns its claims.
type Verifier interface {
	Verify(ctx context.Context, bearer string) (*Claims, error)
}

// Options configures the verifier factory. Fields are provider-specific.
type Options struct {
	Provider string // "github" (default) or "oidc"

	// OIDC
	Issuer         string
	ClientID       string
	AllowedDomains []string

	// GitHub
	GitHubAPIURL      string // default https://api.github.com
	GitHubAllowedOrgs []string
}

// New builds the configured Verifier.
func New(ctx context.Context, opts Options) (Verifier, error) {
	switch opts.Provider {
	case "", "github":
		return NewGitHubVerifier(opts.GitHubAPIURL, opts.GitHubAllowedOrgs), nil
	case "oidc":
		return NewOIDCVerifier(ctx, opts.Issuer, opts.ClientID, opts.AllowedDomains)
	default:
		return nil, fmt.Errorf("unknown AUTH_PROVIDER %q (want \"github\" or \"oidc\")", opts.Provider)
	}
}
