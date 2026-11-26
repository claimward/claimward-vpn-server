//go:build unix

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func loadErr(t *testing.T, want ...string) {
	t.Helper()
	c, err := Load()
	if err == nil {
		t.Fatalf("Load accepted it: %+v", c)
	}
	for _, w := range want {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("error %q does not contain %q", err, w)
		}
	}
}

func TestCredentialsHappyPath(t *testing.T) {
	credsDir(t, map[string]string{
		"wg-private-key": "c2VydmVy\n",
		"admin-token":    "adm\n",
		"github-token":   "ghp\n",

		"provider-gh-secret": "app\n",
	})
	t.Setenv("WG_ENDPOINT", "vpn.example.org:51820")
	providersFile(t, `{"providers":[{"id":"gh","kind":"github","name":"GitHub","github_client_id":"Iv1.ourapp","allowed_orgs":["acme"]}]}`)
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.WGPrivateKey != "c2VydmVy" || c.AdminToken != "adm" || c.GitHubToken != "ghp" {
		t.Errorf("got %q %q %q", c.WGPrivateKey, c.AdminToken, c.GitHubToken)
	}
}

// Every removed variable stops the start, naming the file that replaces it.
func TestRemovedEnvRefused(t *testing.T) {
	for env, file := range map[string]string{
		"ADMIN_TOKEN":                 "admin-token",
		"WG_PRIVATE_KEY":              "wg-private-key",
		"WG_PRIVATE_KEY_FILE":         "wg-private-key",
		"GOAUTHN_GATEWAY_SECRET_FILE": "provider-<id>-gateway-secret",
	} {
		t.Run(env, func(t *testing.T) {
			baseEnv(t)
			t.Setenv(env, "/some/value")
			loadErr(t, env, "CREDENTIALS_DIRECTORY/"+file)
		})
	}
	// An empty variable carries no secret and is not refused.
	baseEnv(t)
	t.Setenv("WG_PRIVATE_KEY_FILE", "")
	if _, err := Load(); err != nil {
		t.Fatal(err)
	}
}

func TestMissingRequiredCredentialNamesTheFile(t *testing.T) {
	baseEnv(t)
	t.Setenv("CREDENTIALS_DIRECTORY", t.TempDir()) // empty directory
	loadErr(t, "wg-private-key")
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	loadErr(t, "CREDENTIALS_DIRECTORY", "wg-private-key")
}

func TestGoAuthnNeedsItsSecret(t *testing.T) {
	baseEnv(t)
	providersFile(t, `{"providers":[{"id":"ga","kind":"go-authn","name":"Campus","oidc_issuer":"https://idp.example.org","oidc_client_id":"claimward","gateway_client_id":"gw"}]}`)
	loadErr(t, "provider-ga-gateway-secret")

	credsDir(t, map[string]string{"wg-private-key": "c2VydmVy", "provider-ga-gateway-secret": "s3\n"})
	c, err := Load()
	if err != nil || c.Providers[0].GatewaySecret != "s3" {
		t.Fatalf("%v %+v", err, c)
	}
}

// Absent admin-token keeps the admin API disabled; present but unsafe is a
// refusal, not a silent disable.
func TestAdminTokenOptionalButChecked(t *testing.T) {
	baseEnv(t)
	c, err := Load()
	if err != nil || c.AdminToken != "" {
		t.Fatalf("%v %q", err, c.AdminToken)
	}
	dir := os.Getenv("CREDENTIALS_DIRECTORY")
	p := filepath.Join(dir, "admin-token")
	if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	loadErr(t, "admin-token", "mode")
}

func TestGitHubTokenOptionalButChecked(t *testing.T) {
	baseEnv(t)
	dir := os.Getenv("CREDENTIALS_DIRECTORY")
	p := filepath.Join(dir, "github-token")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o640); err != nil {
		t.Fatal(err)
	}
	loadErr(t, "github-token", "mode")
}

func TestUnsafeRequiredCredentialRefused(t *testing.T) {
	baseEnv(t)
	dir := os.Getenv("CREDENTIALS_DIRECTORY")
	if err := os.Chmod(filepath.Join(dir, "wg-private-key"), 0o644); err != nil {
		t.Fatal(err)
	}
	loadErr(t, "wg-private-key", "defaultMode: 0440")
}
