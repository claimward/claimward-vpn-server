package config

import (
	"strings"
	"testing"
)

const githubProvider = `{"providers":[{"id":"gh","kind":"github","name":"GitHub","github_client_id":"Iv1.ourapp","allowed_orgs":[%s]}]}`

func githubEnv(t *testing.T, orgs string) {
	t.Helper()
	credsDir(t, map[string]string{"wg-private-key": "c2VydmVy", "provider-gh-secret": "app-secret"})
	t.Setenv("WG_ENDPOINT", "vpn.example.org:51820")
	providersFile(t, strings.Replace(githubProvider, "%s", orgs, 1))
}

// The allowlist is optional when tenants name members, so Load accepts none;
// the entry gate (cmd/claimward-server) refuses the case of no members either.
func TestGitHubAllowlistIsOptionalAtLoad(t *testing.T) {
	githubEnv(t, "")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Providers[0].AllowedOrgs) != 0 {
		t.Errorf("orgs = %v", c.Providers[0].AllowedOrgs)
	}
}

func TestGitHubWithOrgsIsAccepted(t *testing.T) {
	githubEnv(t, `"acme"," other ",""`)
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Providers[0].AllowedOrgs; len(got) != 2 || got[1] != "other" {
		t.Errorf("orgs = %q", got)
	}
}

// ⛔ The OAuth app is mandatory with a github provider, no opt-out: without
// the client ID, or without the secret file, Load refuses.
func TestGitHubRequiresTheOAuthApp(t *testing.T) {
	githubEnv(t, `"acme"`)
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if p := c.Providers[0]; p.GitHubClientID != "Iv1.ourapp" || p.ClientSecret != "app-secret" {
		t.Errorf("app = %q / secret read = %v", p.GitHubClientID, p.ClientSecret != "")
	}

	providersFile(t, `{"providers":[{"id":"gh","kind":"github","name":"GitHub","allowed_orgs":["acme"]}]}`)
	refuses(t, "github_client_id")

	githubEnv(t, `"acme"`)
	credsDir(t, map[string]string{"wg-private-key": "c2VydmVy"})
	refuses(t, "provider-gh-secret")
}

func refuses(t *testing.T, want string) {
	t.Helper()
	c, err := Load()
	if err == nil {
		t.Fatalf("Load accepted it: %+v", c)
	}
	if !strings.Contains(err.Error(), want) {
		t.Errorf("error %q does not name %q", err, want)
	}
}

// Other kinds are not subject to the GitHub rule.
func TestOIDCNeedsNoGitHubAllowlist(t *testing.T) {
	baseEnv(t)
	if _, err := Load(); err != nil {
		t.Fatal(err)
	}
}
