package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
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

	clientID     string // OAuth app client ID (public)
	clientSecret string // OAuth app client secret, from a credential file
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
	// ⛔ Fail closed: a token is only taken from Claimward's own OAuth app.
	if v.clientID == "" || v.clientSecret == "" {
		return nil, fmt.Errorf("github authentication needs the OAuth app (GITHUB_CLIENT_ID and the github-client-secret credential)")
	}
	checkedID, err := v.checkApp(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
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
	if checkedID != user.ID {
		return nil, fmt.Errorf("invalid token: the checked token's user is not the user it authenticates")
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

// maxCheckBody caps what is read of a check-a-token answer.
const maxCheckBody = 64 << 10

// WithApp binds the verifier to Claimward's OAuth app: only tokens that app
// minted are admitted. The secret is the app's client secret, read from a
// credential file by the caller.
func (v *GitHubVerifier) WithApp(clientID, clientSecret string) *GitHubVerifier {
	v.clientID, v.clientSecret = clientID, clientSecret
	return v
}

// checkApp proves that token was minted by our OAuth app and returns the ID of
// the user it belongs to.
//
// Without this any token from ANY OAuth app a member authorised with read:org
// would enrol a peer: /user and the org lookups only say who the token is, not
// which app holds it.
//
// GitHub REST, "Check a token" (REST API > OAuth authorizations / OAuth
// applications): https://docs.github.com/en/rest/apps/oauth-applications#check-a-token
// POST /applications/{client_id}/token, HTTP basic auth client_id:client_secret
// (not a bearer), JSON body {"access_token": ...}. 200 = valid for that app,
// with an "app" object (client_id, name, url) and the "user"; 404 = invalid
// token; 422 = validation failed or the endpoint was spammed. The page states
// no numeric rate limit, only that it lets apps check validity "without
// exceeding the normal rate limits for failed login attempts". Anything but
// a 200 naming our client_id refuses.
func (v *GitHubVerifier) checkApp(ctx context.Context, token string) (int64, error) {
	if u, err := url.Parse(v.apiURL); err != nil || (u.Scheme != "https" && !isLoopback(u.Hostname())) {
		return 0, fmt.Errorf("the GitHub API URL %q: the client secret is only sent over https (or to loopback)", v.apiURL)
	}
	body, _ := json.Marshal(map[string]string{"access_token": token}) // a string map cannot fail
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.apiURL+"/applications/"+url.PathEscape(v.clientID)+"/token", bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.SetBasicAuth(v.clientID, v.clientSecret)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	resp, err := v.http.Do(req)
	if err != nil {
		return 0, fmt.Errorf("checking the token with GitHub: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("GitHub refused to vouch for the token (HTTP %d)", resp.StatusCode)
	}
	var out struct {
		App struct {
			ClientID string `json:"client_id"`
		} `json:"app"`
		User struct {
			ID int64 `json:"id"`
		} `json:"user"`
	}
	// A body that does not decode leaves out zero (or short of our client_id),
	// and the check below refuses it; the caller refuses a user ID of zero by
	// comparing it with /user's, which is never zero there.
	_ = json.NewDecoder(io.LimitReader(resp.Body, maxCheckBody)).Decode(&out)
	if out.App.ClientID != v.clientID {
		return 0, fmt.Errorf("the token was not minted by this server's OAuth app")
	}
	return out.User.ID, nil
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
