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

	if len(v.allowedOrgs) > 0 {
		ok, err := v.inAllowedOrg(ctx, token, user.Login)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("user %q is not a member of an allowed org", user.Login)
		}
	}
	return claims, nil
}

// inAllowedOrg reports whether the user is an active member of any allowed org,
// using the user's own token (requires the read:org scope).
func (v *GitHubVerifier) inAllowedOrg(ctx context.Context, token, login string) (bool, error) {
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
			return true, nil
		}
	}
	return false, nil
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
