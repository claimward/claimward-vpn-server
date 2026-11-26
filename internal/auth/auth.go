// Package auth authenticates the bearer credential presented by clients and
// extracts the identity claims used for authorization.
//
// Claimward supports pluggable identity providers behind the Verifier interface:
//
//   - github (default): the bearer is a GitHub OAuth access token; it is validated
//     by calling the GitHub API, with optional org-membership authorization.
//   - oidc: the bearer is an OIDC ID token; it is verified against the issuer.
//   - go-authn: the bearer is an access token (at+jwt) from a go-authn
//     provider, and the device's WireGuard key must be one the person
//     registered there (internal/peers).
//
// Add a provider by implementing Verifier and wiring it into New.
package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/claimward/claimward-vpn-server/internal/tenant"
)

// Claims is the subset of identity we care about, normalized across providers.
type Claims struct {
	// Provider is the id (PROVIDERS_FILE) of the provider that verified the
	// token; Set.Verify fills it in.
	Provider string
	// Subject is a stable, provider-scoped identifier: "github:1234" for GitHub,
	// "<issuer>#<sub>" for an OIDC or go-authn issuer. It is namespaced so that
	// one identity provider can never speak for another's people (two issuers
	// may both have a "sub" of "42"), and by the ISSUER, not the local id, so
	// renaming a provider's id changes no identity. It is what peer ownership
	// is keyed on.
	Subject string
	// Native is the provider's own subject, un-namespaced: what a go-authn
	// provider's list of registered keys calls the person. Empty otherwise.
	Native        string
	Email         string
	EmailVerified bool
	Login         string // human handle (GitHub login / OIDC preferred_username), best-effort

	// Groups are what tenants are matched on beside the email domain: the
	// token's "groups" claim (OIDC, go-authn: eduPerson entitlements), or the
	// GitHub organisations the person belongs to.
	Groups []string
	// IdP is the institution that vouched for the person, when the provider
	// says (go-authn's "idp": a SAML entity ID).
	IdP string
	// Expires is when the credential stops being valid (the token's "exp");
	// zero when the provider has no such notion (GitHub access tokens).
	Expires time.Time
}

// Verifier validates a bearer credential and returns its claims.
type Verifier interface {
	Verify(ctx context.Context, bearer string) (*Claims, error)
}

// Options configures the verifier factory. Fields are provider-specific.
type Options struct {
	Provider string // "github" (default), "oidc" or "go-authn"

	// OIDC
	Issuer         string
	ClientID       string
	AllowedDomains []string

	// GitHub
	GitHubAPIURL      string // default https://api.github.com
	GitHubAllowedOrgs []string
	// GitHubClientID and GitHubClientSecret are Claimward's OAuth app: only
	// tokens that app minted are admitted.
	GitHubClientID     string
	GitHubClientSecret string
}

// New builds the configured Verifier.
func New(ctx context.Context, opts Options) (Verifier, error) {
	switch opts.Provider {
	case "", "github":
		v := NewGitHubVerifier(opts.GitHubAPIURL, opts.GitHubAllowedOrgs).WithApp(opts.GitHubClientID, opts.GitHubClientSecret)
		if opts.GitHubAPIURL != "" && strings.TrimRight(opts.GitHubAPIURL, "/") != "https://api.github.com" {
			v.WithEnterprise(opts.GitHubAPIURL)
		}
		return v, nil
	case "oidc":
		return NewOIDCVerifier(ctx, opts.Issuer, opts.ClientID, opts.AllowedDomains)
	case "go-authn":
		return NewGoAuthnVerifier(ctx, opts.Issuer, opts.ClientID)
	default:
		return nil, fmt.Errorf("unknown provider kind %q (want \"github\", \"oidc\" or \"go-authn\")", opts.Provider)
	}
}

// Tenancy is what tenants are matched on, from these claims.
func (c *Claims) Tenancy() tenant.Member {
	// ⛔ Groups are scoped by the provider: "acme" the GitHub organisation and
	// "acme" a group of another provider are two groups. A tenant names one as
	// "<provider id>:<group>".
	groups := make([]string, len(c.Groups))
	for i, g := range c.Groups {
		groups[i] = c.Provider + ":" + g
	}
	return tenant.Member{Subject: c.Subject, Provider: c.Provider, Email: c.Email, EmailVerified: c.EmailVerified, Groups: groups, IdP: c.IdP}
}

// Errors of Set.Verify that name the provider, not the token.
var (
	ErrMissingProvider = errors.New("no provider named: send the Claimward-Provider header")
	ErrUnknownProvider = errors.New("unknown provider")
)

// Set is the providers a server accepts, by id.
type Set struct {
	byID map[string]Verifier
}

// NewSet returns an empty Set.
func NewSet() *Set { return &Set{byID: map[string]Verifier{}} }

// Add registers v under id; an id used twice is an error.
func (s *Set) Add(id string, v Verifier) error {
	if _, dup := s.byID[id]; dup {
		return fmt.Errorf("provider %q added twice", id)
	}
	s.byID[id] = v
	return nil
}

// Get is the verifier of provider id.
func (s *Set) Get(id string) (Verifier, bool) { v, ok := s.byID[id]; return v, ok }

// Verify checks bearer with the provider id ONLY. ⛔ It never tries the token
// against the others: that would send a GitHub token to an OIDC endpoint, and
// let the token of a weaker provider be tried as another's.
func (s *Set) Verify(ctx context.Context, id, bearer string) (*Claims, error) {
	if id == "" {
		return nil, ErrMissingProvider
	}
	v, ok := s.byID[id]
	if !ok {
		return nil, ErrUnknownProvider
	}
	c, err := v.Verify(ctx, bearer)
	if err != nil {
		return nil, err
	}
	// Stamp a copy: a verifier may hand the same *Claims to concurrent calls.
	out := *c
	out.Provider = id
	return &out, nil
}

// Authenticator verifies a bearer token issued by the named provider.
type Authenticator interface {
	Verify(ctx context.Context, provider, bearer string) (*Claims, error)
}
