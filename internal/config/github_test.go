package config

import "testing"

func githubEnv(t *testing.T, orgs string) {
	t.Helper()
	credsDir(t, map[string]string{"wg-private-key": "c2VydmVy", "github-client-secret": "app-secret"})
	t.Setenv("GITHUB_CLIENT_ID", "Iv1.ourapp")
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

// ⛔ The OAuth app is mandatory with the github provider, no opt-out: without
// the client ID, or without the secret file, Load refuses.
func TestGitHubRequiresTheOAuthApp(t *testing.T) {
	githubEnv(t, "acme")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.GitHubClientID != "Iv1.ourapp" || c.GitHubClientSecret != "app-secret" {
		t.Errorf("app = %q / secret read = %v", c.GitHubClientID, c.GitHubClientSecret != "")
	}

	githubEnv(t, "acme")
	t.Setenv("GITHUB_CLIENT_ID", "")
	loadErr(t, "GITHUB_CLIENT_ID")

	credsDir(t, map[string]string{"wg-private-key": "c2VydmVy"})
	t.Setenv("GITHUB_CLIENT_ID", "Iv1.ourapp")
	loadErr(t, "github-client-secret")
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
