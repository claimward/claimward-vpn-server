package config

import "testing"

func githubEnv(t *testing.T, orgs string) {
	t.Helper()
	credsDir(t, map[string]string{"wg-private-key": "c2VydmVy"})
	t.Setenv("WG_ENDPOINT", "vpn.example.org:51820")
	t.Setenv("AUTH_PROVIDER", "")
	t.Setenv("GITHUB_ALLOWED_ORGS", orgs)
}

// The allowlist is optional when tenants name members, so Load accepts none;
// the entry gate (cmd/claimward-server) refuses the case of no members either.
func TestGitHubAllowlistIsOptionalAtLoad(t *testing.T) {
	githubEnv(t, "")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(c.GitHubAllowedOrgs) != 0 {
		t.Errorf("orgs = %v", c.GitHubAllowedOrgs)
	}
}

func TestGitHubWithOrgsIsAccepted(t *testing.T) {
	githubEnv(t, "acme, other")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(c.GitHubAllowedOrgs) != 2 {
		t.Errorf("orgs = %v", c.GitHubAllowedOrgs)
	}
}

// Other providers are not subject to the GitHub rule.
func TestOIDCNeedsNoGitHubAllowlist(t *testing.T) {
	githubEnv(t, "")
	t.Setenv("AUTH_PROVIDER", "oidc")
	t.Setenv("OIDC_ISSUER", "https://idp.example.org")
	t.Setenv("OIDC_CLIENT_ID", "claimward")
	if _, err := Load(); err != nil {
		t.Fatal(err)
	}
}
