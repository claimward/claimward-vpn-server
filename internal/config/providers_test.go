//go:build unix

package config

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	ghJSON   = `{"id":"hub","kind":"github","name":"GitHub","github_client_id":"Iv1.ourapp","allowed_orgs":["acme"]}`
	oidcJSON = `{"id":"campus","kind":"oidc","name":"Campus","oidc_issuer":"https://idp.example.org","oidc_client_id":"claimward","allowed_domains":["example.org"]}`
	gaJSON   = `{"id":"fed","kind":"go-authn","name":"Federation","oidc_issuer":"https://authn.example.org","oidc_client_id":"claimward","gateway_client_id":"gw"}`
)

func wrap(ps ...string) string { return `{"providers":[` + strings.Join(ps, ",") + `]}` }

func secretsDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for name, v := range map[string]string{"provider-hub-secret": "app\n", "provider-fed-gateway-secret": "gw-secret\n"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(v), 0o400); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestSeveralProvidersAreRead(t *testing.T) {
	ps, err := parseProviders([]byte(wrap(ghJSON, oidcJSON, gaJSON)), secretsDir(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 3 || ps[0].ID != "hub" || ps[1].ID != "campus" || ps[2].ID != "fed" {
		t.Fatalf("providers = %+v", ps)
	}
	if ps[0].ClientSecret != "app" || ps[2].GatewaySecret != "gw-secret" {
		t.Errorf("secrets: %q, %q", ps[0].ClientSecret, ps[2].GatewaySecret)
	}
	if ps[0].AllowedOrgs[0] != "acme" || ps[1].AllowedDomains[0] != "example.org" {
		t.Errorf("rules: %+v %+v", ps[0], ps[1])
	}
}

// ⛔ What the discovery document says of a provider is built field by field: a
// secret read into the struct, an admission rule, or the gateway's client are
// never in it.
func TestPublicHoldsNoSecretAndNoRule(t *testing.T) {
	ps, err := parseProviders([]byte(wrap(ghJSON, oidcJSON, gaJSON)), secretsDir(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range ps {
		pub := p.Public()
		if pub.ID != p.ID || pub.Kind != p.Kind || pub.Name != p.Name {
			t.Errorf("%s: %+v", p.ID, pub)
		}
		for _, s := range []string{pub.ID, pub.Kind, pub.Name, pub.GitHubClientID, pub.OIDCIssuer, pub.OIDCClientID} {
			for _, secret := range []string{"app", "gw-secret", "acme", "example.org", "gw"} {
				if s == secret {
					t.Errorf("%s: public says %q", p.ID, s)
				}
			}
		}
	}
	if pub := ps[0].Public(); pub.GitHubClientID != "Iv1.ourapp" || pub.OIDCIssuer != "" || pub.OIDCClientID != "" {
		t.Errorf("github: %+v", pub)
	}
	if pub := ps[1].Public(); pub.GitHubClientID != "" || pub.OIDCIssuer != "https://idp.example.org" || pub.OIDCClientID != "claimward" {
		t.Errorf("oidc: %+v", pub)
	}
}

func TestProvidersFileRefuses(t *testing.T) {
	dir := secretsDir(t)
	for name, tc := range map[string]struct{ doc, want string }{
		"no provider":              {`{"providers":[]}`, "lists no provider"},
		"not json":                 {`nope`, "PROVIDERS_FILE"},
		"unknown field":            {wrap(`{"id":"campus","kind":"oidc","name":"C","oidc_issuer":"https://i","oidc_client_id":"c","oidc_isuer":"x"}`), "unknown field"},
		"unknown top field":        {`{"providers":[` + oidcJSON + `],"extra":1}`, "unknown field"},
		"trailing data":            {wrap(oidcJSON) + `{}`, "trailing data"},
		"two documents":            {wrap(oidcJSON) + wrap(oidcJSON), "trailing data"},
		"bad id":                   {wrap(strings.Replace(oidcJSON, `"campus"`, `"Campus"`, 1)), "id"},
		"id with a colon":          {wrap(strings.Replace(oidcJSON, `"campus"`, `"a:b"`, 1)), "id"},
		"empty id":                 {wrap(strings.Replace(oidcJSON, `"campus"`, `""`, 1)), "id"},
		"dash at the end":          {wrap(strings.Replace(oidcJSON, `"campus"`, `"a-"`, 1)), "id"},
		"id too long":              {wrap(strings.Replace(oidcJSON, `"campus"`, `"`+strings.Repeat("a", 33)+`"`, 1)), "id"},
		"same id twice":            {wrap(oidcJSON, strings.Replace(ghJSON, `"hub"`, `"campus"`, 1)), "listed twice"},
		"no name":                  {wrap(strings.Replace(oidcJSON, `"name":"Campus",`, ``, 1)), "has no name"},
		"control in name":          {wrap(strings.Replace(oidcJSON, `Campus`, `Cam\u0007pus`, 1)), "control character"},
		"name too long":            {wrap(strings.Replace(oidcJSON, `Campus`, strings.Repeat("a", 500), 1)), "longer than"},
		"unknown kind":             {wrap(strings.Replace(oidcJSON, `"oidc"`, `"saml"`, 1)), "kind"},
		"same issuer twice":        {wrap(oidcJSON, strings.Replace(oidcJSON, `"campus"`, `"other"`, 1)), "same oidc_issuer"},
		"two go-authn":             {wrap(gaJSON, strings.Replace(strings.Replace(gaJSON, `"fed"`, `"fed2"`, 1), "authn.example.org", "authn2.example.org", 1)), "both go-authn"},
		"github without app":       {wrap(strings.Replace(ghJSON, `"github_client_id":"Iv1.ourapp",`, ``, 1)), "github_client_id"},
		"github with issuer":       {wrap(strings.Replace(ghJSON, `"allowed_orgs"`, `"oidc_issuer":"https://x","allowed_orgs"`, 1)), "cannot have oidc_issuer"},
		"github with client":       {wrap(strings.Replace(ghJSON, `"allowed_orgs"`, `"oidc_client_id":"x","allowed_orgs"`, 1)), "cannot have oidc_client_id"},
		"github with gateway":      {wrap(strings.Replace(ghJSON, `"allowed_orgs"`, `"gateway_client_id":"x","allowed_orgs"`, 1)), "cannot have gateway_client_id"},
		"github with domains":      {wrap(strings.Replace(ghJSON, `"allowed_orgs"`, `"allowed_domains":["a.org"],"allowed_orgs"`, 1)), "allowed_domains"},
		"oidc with github app":     {wrap(strings.Replace(oidcJSON, `"allowed_domains"`, `"github_client_id":"x","allowed_domains"`, 1)), "cannot have github_client_id"},
		"oidc with api_url":        {wrap(strings.Replace(oidcJSON, `"allowed_domains"`, `"api_url":"https://x","allowed_domains"`, 1)), "cannot have api_url"},
		"oidc with orgs":           {wrap(strings.Replace(oidcJSON, `"allowed_domains"`, `"allowed_orgs":["a"],"allowed_domains"`, 1)), "allowed_orgs"},
		"oidc without issuer":      {wrap(strings.Replace(oidcJSON, `"oidc_issuer":"https://idp.example.org",`, ``, 1)), "oidc_issuer"},
		"oidc without audience":    {wrap(strings.Replace(oidcJSON, `"oidc_client_id":"claimward",`, ``, 1)), "oidc_client_id"},
		"oidc with gateway":        {wrap(strings.Replace(oidcJSON, `"allowed_domains"`, `"gateway_client_id":"g","allowed_domains"`, 1)), "cannot have gateway_client_id"},
		"go-authn with domains":    {wrap(strings.Replace(gaJSON, `"gateway_client_id"`, `"allowed_domains":["a.org"],"gateway_client_id"`, 1)), "allowed_domains"},
		"go-authn with no gateway": {wrap(strings.Replace(gaJSON, `,"gateway_client_id":"gw"`, ``, 1)), "gateway_client_id"},
		"github without secret":    {wrap(strings.Replace(ghJSON, `"hub"`, `"nosecret"`, 1)), "provider-nosecret-secret"},
		"go-authn without secret":  {wrap(strings.Replace(gaJSON, `"fed"`, `"nosecret"`, 1)), "provider-nosecret-gateway-secret"},
	} {
		if _, err := parseProviders([]byte(tc.doc), dir); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want one containing %q", name, err, tc.want)
		}
	}
}

func TestProvidersFileIsRequiredAndBounded(t *testing.T) {
	dir := t.TempDir()
	if _, err := loadProviders("", dir); err == nil || !strings.Contains(err.Error(), "PROVIDERS_FILE") {
		t.Errorf("no file: %v", err)
	}
	if _, err := loadProviders(filepath.Join(dir, "absent.json"), dir); err == nil {
		t.Error("an absent file was read")
	}
	big := filepath.Join(dir, "big.json")
	if err := os.WriteFile(big, []byte(`{"providers":[],"x":"`+strings.Repeat("a", maxProvidersFile)+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadProviders(big, dir); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("an oversized file: %v", err)
	}
	// Exactly the cap is still read (and then refused for what it says, not its size).
	pad := `{"providers":[` + oidcJSON + `]}`
	pad += strings.Repeat(" ", maxProvidersFile-len(pad))
	exact := filepath.Join(dir, "exact.json")
	if err := os.WriteFile(exact, []byte(pad), 0o600); err != nil {
		t.Fatal(err)
	}
	if ps, err := loadProviders(exact, dir); err != nil || len(ps) != 1 {
		t.Errorf("a file of exactly the cap: %v", err)
	}
}

// ⛔ Each single-provider variable stops the start and names itself: no mapping
// is silently guessed.
func TestSingleProviderEnvIsRefused(t *testing.T) {
	for _, k := range removedProviderEnv {
		t.Run(k, func(t *testing.T) {
			baseEnv(t)
			t.Setenv(k, "x")
			loadErr(t, k, "PROVIDERS_FILE")
		})
	}
	baseEnv(t)
	t.Setenv("AUTH_PROVIDER", "")
	if _, err := Load(); err != nil {
		t.Errorf("an empty variable is not a setting: %v", err)
	}
	baseEnv(t)
	t.Setenv("AUTH_PROVIDER", "github")
	t.Setenv("OIDC_ISSUER", "https://x")
	loadErr(t, "these are", "AUTH_PROVIDER", "OIDC_ISSUER")
}

const goodLogo = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1 1"><rect width="1" height="1"/></svg>`

func TestLogoFileIsValidatedAtStart(t *testing.T) {
	baseEnv(t)
	c, err := Load()
	if err != nil || c.Logo != nil || c.LogoSHA256 != "" {
		t.Fatalf("no logo configured: %v %+v", err, c)
	}
	write := func(content string) string {
		p := filepath.Join(t.TempDir(), "logo.svg")
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	t.Setenv("SERVER_LOGO_FILE", write(goodLogo))
	c, err = Load()
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(goodLogo))
	if string(c.Logo) != goodLogo || c.LogoSHA256 != hex.EncodeToString(sum[:]) {
		t.Errorf("logo %q sha %s", c.Logo, c.LogoSHA256)
	}
	for name, doc := range map[string]string{
		"a script":  `<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`,
		"a doctype": `<!DOCTYPE svg [<!ENTITY a "b">]>` + goodLogo,
		"not svg":   `<html/>`,
		"empty":     ``,
	} {
		t.Setenv("SERVER_LOGO_FILE", write(doc))
		loadErr(t, "SERVER_LOGO_FILE")
		_ = name
	}
	t.Setenv("SERVER_LOGO_FILE", filepath.Join(t.TempDir(), "absent.svg"))
	loadErr(t, "SERVER_LOGO_FILE")
}

func FuzzParseProviders(f *testing.F) {
	for _, s := range []string{wrap(ghJSON, oidcJSON, gaJSON), `{}`, `{"providers":null}`, wrap(`{}`), `[`, wrap(ghJSON, ghJSON)} {
		f.Add([]byte(s))
	}
	dir := f.TempDir()
	for _, n := range []string{"provider-hub-secret", "provider-fed-gateway-secret"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("s\n"), 0o400); err != nil {
			f.Fatal(err)
		}
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		ps, err := parseProviders(b, dir)
		if err != nil {
			return
		}
		// What is accepted is coherent: ids unique and well-formed, one issuer per
		// provider, at most one go-authn, and a public form that holds no secret.
		seen, issuers, ga := map[string]bool{}, map[string]bool{}, 0
		for _, p := range ps {
			if !providerID.MatchString(p.ID) || seen[p.ID] {
				t.Fatalf("id %q accepted", p.ID)
			}
			seen[p.ID] = true
			if p.OIDCIssuer != "" {
				if issuers[p.OIDCIssuer] {
					t.Fatalf("issuer %q twice", p.OIDCIssuer)
				}
				issuers[p.OIDCIssuer] = true
			}
			if p.Kind == "go-authn" {
				ga++
			}
			if pub := p.Public(); pub.GitHubClientID == p.ClientSecret && p.ClientSecret != "" || pub.OIDCClientID == p.GatewaySecret && p.GatewaySecret != "" {
				t.Fatalf("public form holds a secret: %+v", pub)
			}
		}
		if ga > 1 || len(ps) == 0 {
			t.Fatalf("%d go-authn, %d providers accepted", ga, len(ps))
		}
	})
}

func TestRemovedEnvMessageNamesEachVariable(t *testing.T) {
	t.Setenv("AUTH_PROVIDER", "oidc")
	err := refuseRemovedProviderEnv()
	if err == nil || !strings.Contains(err.Error(), "AUTH_PROVIDER is no longer read") {
		t.Fatalf("one variable: %v", err)
	}
	if strings.Contains(err.Error(), "these are") {
		t.Fatalf("one variable read as several: %v", err)
	}
	t.Setenv("OIDC_ISSUER", "https://x")
	err = refuseRemovedProviderEnv()
	if err == nil || !strings.Contains(err.Error(), "these are") || !strings.Contains(err.Error(), "AUTH_PROVIDER, OIDC_ISSUER") {
		t.Fatalf("two variables: %v", err)
	}
}

func TestProvidersFileMissingUnreadableOrNotAFile(t *testing.T) {
	dir := secretsDir(t)
	if _, err := loadProviders("", dir); err == nil || !strings.Contains(err.Error(), "missing required config: PROVIDERS_FILE") {
		t.Fatalf("unset path: %v", err)
	}
	gone := filepath.Join(t.TempDir(), "absent.json")
	if _, err := loadProviders(gone, dir); !errors.Is(err, fs.ErrNotExist) || !strings.Contains(err.Error(), "PROVIDERS_FILE") {
		t.Fatalf("absent file: %v", err)
	}
	// A directory opens but cannot be read: the read error is named with the path.
	d := t.TempDir()
	if _, err := loadProviders(d, dir); err == nil || !strings.Contains(err.Error(), d) {
		t.Fatalf("directory: %v", err)
	}
}
