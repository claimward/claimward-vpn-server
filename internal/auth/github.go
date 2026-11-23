package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// GitHubVerifier validates a GitHub OAuth access token by calling the GitHub API
// and, if configured, requires the user to belong to one of the allowed orgs.
//
// GitHub is not an OIDC provider: there is no ID token to verify cryptographically.
// Instead we treat the access token as a capability and resolve identity through
// the API. The org-membership check is the real authorization gate.
type GitHubVerifier struct {
	apiURL      string
	allowedOrgs []string
	http        *http.Client
	members     MemberSet
}

// MemberSet is the tenants' named members, as the entry gate sees them.
type MemberSet interface {
	NamedMember(subject string) bool
	HasNamedMembers() bool
}

// WithMembers admits the people the tenants name, beside the allowed orgs.
func (v *GitHubVerifier) WithMembers(m MemberSet) *GitHubVerifier {
	v.members = m
	return v
}

// NewGitHubVerifier returns a verifier for the given API base URL (empty =
// https://api.github.com, set this for GitHub Enterprise) and optional org allowlist.
func NewGitHubVerifier(apiURL string, allowedOrgs []string) *GitHubVerifier {
	if apiURL == "" {
		apiURL = "https://api.github.com"
	}
	return &GitHubVerifier{
		apiURL:      strings.TrimRight(apiURL, "/"),
		allowedOrgs: allowedOrgs,
		http:        &http.Client{Timeout: 10 * time.Second},
	}
}

func (v *GitHubVerifier) Verify(ctx context.Context, token string) (*Claims, error) {
	// ⛔ Fail closed: with no allowlist every GitHub account would be admitted,
	// an open relay. Config.Load refuses this too; here it holds for any
	// caller that builds a verifier by hand.
	if !v.hasAllowedOrg() && (v.members == nil || !v.members.HasNamedMembers()) {
		return nil, fmt.Errorf("github authentication needs an organisation allowlist (GITHUB_ALLOWED_ORGS) or tenants with named members")
	}
	var user struct {
		ID    int64  `json:"id"`
		Login string `json:"login"`
		Email string `json:"email"`
	}
	if err := v.get(ctx, token, "/user", &user); err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}
	if user.ID == 0 || user.Login == "" {
		return nil, fmt.Errorf("invalid token: empty GitHub identity")
	}

	claims := &Claims{
		Subject:       fmt.Sprintf("github:%d", user.ID),
		Login:         user.Login,
		Email:         user.Email,
		EmailVerified: user.Email != "", // GitHub only exposes verified emails on /user
	}
	// The organisations are the person's groups, for tenant membership:
	// /user/orgs lists the ones the token may see (read:org shows private
	// memberships too).
	var orgs []struct {
		Login string `json:"login"`
	}
	if err := v.get(ctx, token, "/user/orgs", &orgs); err != nil {
		return nil, fmt.Errorf("listing the GitHub organisations: %w", err)
	}
	for _, o := range orgs {
		claims.Groups = append(claims.Groups, o.Login)
	}

	// Admitted: a named member of a tenant (matched on the pinned numeric ID,
	// never the login), or a member of an allowed organisation.
	named := v.members != nil && v.members.NamedMember(claims.Subject)
	if !named && !(v.hasAllowedOrg() && v.inAllowedOrg(ctx, token)) {
		return nil, fmt.Errorf("user %q is neither a named tenant member nor in an allowed org", user.Login)
	}
	return claims, nil
}

// hasAllowedOrg is whether the allowlist names at least one organisation (a
// list of blanks names none).
func (v *GitHubVerifier) hasAllowedOrg() bool {
	for _, o := range v.allowedOrgs {
		if strings.TrimSpace(o) != "" {
			return true
		}
	}
	return false
}

// inAllowedOrg reports whether the user is an active member of any allowed org,
// using the user's own token (requires the read:org scope).
func (v *GitHubVerifier) inAllowedOrg(ctx context.Context, token string) bool {
	for _, org := range v.allowedOrgs {
		org = strings.TrimSpace(org)
		if org == "" {
			continue
		}
		var m struct {
			State string `json:"state"`
		}
		err := v.get(ctx, token, "/user/memberships/orgs/"+org, &m)
		if err == nil && m.State == "active" {
			return true
		}
	}
	return false
}

func (v *GitHubVerifier) get(ctx context.Context, token, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.apiURL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := v.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("github API %s -> %d", path, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
