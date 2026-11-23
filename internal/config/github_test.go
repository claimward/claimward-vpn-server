package config

import "testing"

func githubEnv(t *testing.T, orgs, anyAccount string) {
	t.Helper()
	t.Setenv("WG_ENDPOINT", "vpn.example.org:51820")
	t.Setenv("WG_PRIVATE_KEY", "c2VydmVy")
	t.Setenv("WG_PRIVATE_KEY_FILE", "")
	t.Setenv("AUTH_PROVIDER", "")
	t.Setenv("GITHUB_ALLOWED_ORGS", orgs)
	t.Setenv("GITHUB_ALLOW_ANY_ACCOUNT", anyAccount)
}

// With the default provider (GitHub) and no org allowlist every GitHub
// account could enroll: Load refuses, unless that is asked for on purpose.
func TestDefaultGitHubConfigRequiresAnAllowlist(t *testing.T) {
	githubEnv(t, "", "")
	if c, err := Load(); err == nil {
		t.Errorf("Load accepted provider %q with allowed orgs %v: any GitHub account may enroll", c.AuthProvider, c.GitHubAllowedOrgs)
	}
}

func TestGitHubWithOrgsIsAccepted(t *testing.T) {
	githubEnv(t, "acme, other", "")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(c.GitHubAllowedOrgs) != 2 {
		t.Errorf("orgs = %v", c.GitHubAllowedOrgs)
	}
}

func TestGitHubAnyAccountNeedsTheExplicitOptIn(t *testing.T) {
	githubEnv(t, "", "true")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !c.GitHubAllowAnyAccount {
		t.Error("GITHUB_ALLOW_ANY_ACCOUNT=true was not read")
	}
	githubEnv(t, "", "false")
	if _, err := Load(); err == nil {
		t.Error("GITHUB_ALLOW_ANY_ACCOUNT=false with no orgs must be refused")
	}
}

// Other providers are not subject to the GitHub rule.
func TestOIDCNeedsNoGitHubAllowlist(t *testing.T) {
	githubEnv(t, "", "")
	t.Setenv("AUTH_PROVIDER", "oidc")
	t.Setenv("OIDC_ISSUER", "https://idp.example.org")
	t.Setenv("OIDC_CLIENT_ID", "claimward")
	if _, err := Load(); err != nil {
		t.Fatal(err)
	}
}
