package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/claimward/claimward-vpn-client/pkg/protocol"
	"github.com/claimward/claimward-vpn-server/internal/config"
)

func getDiscovery(t *testing.T, s *Server, method string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest(method, protocol.PathWellKnownConfiguration, nil))
	return w
}

var (
	ghProvider   = config.Provider{ID: "hub", Kind: protocol.KindGitHub, Name: "GitHub", GitHubClientID: "Iv1.ourapp", ClientSecret: "app-client-SECRET", AllowedOrgs: []string{"claimward"}}
	oidcProvider = config.Provider{ID: "campus", Kind: protocol.KindOIDC, Name: "Campus", OIDCIssuer: "https://idp.example.org", OIDCClientID: "claimward", AllowedDomains: []string{"example.org"}}
	gaProvider   = config.Provider{ID: "fed", Kind: protocol.KindGoAuthn, Name: "Federation", OIDCIssuer: "https://authn.example.org", OIDCClientID: "claimward", GatewayClientID: "gw", GatewaySecret: "gateway-SECRET"}
)

// ⛔ The discovery document lists EVERY provider, in order, with the public
// parameters of each and nothing else.
func TestDiscoveryListsEveryProvider(t *testing.T) {
	s, _ := newServer(t)
	s.cfg.Providers = []config.Provider{ghProvider, oidcProvider, gaProvider}
	s.cfg.ServerName = "Lab"
	s.cfg.Exclusive = true

	w := getDiscovery(t, s, http.MethodGet)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}
	if h := w.Header().Get("X-Content-Type-Options"); h != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q (RFC 8615 section 4.2)", h)
	}
	if h := w.Header().Get("Cache-Control"); h != "public, max-age=300" {
		t.Errorf("Cache-Control = %q", h)
	}
	var got protocol.Configuration
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Version != protocol.ConfigurationVersion || got.ServerName != "Lab" || !got.Exclusive || got.Logo != nil {
		t.Errorf("got %+v", got)
	}
	want := []protocol.Provider{
		{ID: "hub", Kind: "github", Name: "GitHub", GitHubClientID: "Iv1.ourapp"},
		{ID: "campus", Kind: "oidc", Name: "Campus", OIDCIssuer: "https://idp.example.org", OIDCClientID: "claimward"},
		{ID: "fed", Kind: "go-authn", Name: "Federation", OIDCIssuer: "https://authn.example.org", OIDCClientID: "claimward"},
	}
	if len(got.Providers) != len(want) {
		t.Fatalf("providers = %+v, want %+v", got.Providers, want)
	}
	for i := range want {
		if got.Providers[i] != want[i] {
			t.Errorf("provider %d = %+v, want %+v", i, got.Providers[i], want[i])
		}
	}
}

// A provider carries only its own kind's fields: no empty github_client_id on
// an oidc provider, no invented server_name.
func TestDiscoveryOmitsWhatIsAbsent(t *testing.T) {
	s, _ := newServer(t)
	s.cfg.Providers = []config.Provider{oidcProvider}
	w := getDiscovery(t, s, http.MethodGet)
	var m struct {
		Providers []map[string]any `json:"providers"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"id": "campus", "kind": "oidc", "name": "Campus", "oidc_issuer": "https://idp.example.org", "oidc_client_id": "claimward"}
	if len(m.Providers) != 1 || len(m.Providers[0]) != len(want) {
		t.Fatalf("%v, want exactly %v", m.Providers, want)
	}
	for k, v := range want {
		if m.Providers[0][k] != v {
			t.Errorf("%s = %v, want %v", k, m.Providers[0][k], v)
		}
	}
	if strings.Contains(w.Body.String(), "server_name") || strings.Contains(w.Body.String(), "logo") {
		t.Errorf("an absent name or logo is in the document: %s", w.Body)
	}
}

// ⛔ The document is public: no secret the server holds may ever be in it.
func TestDiscoveryNeverHoldsASecret(t *testing.T) {
	s, _ := newServer(t)
	s.cfg.Providers = []config.Provider{ghProvider, oidcProvider, gaProvider}
	secrets := []string{"wg-private-SECRET", "admin-SECRET", "gh-token-SECRET", "app-client-SECRET", "gateway-SECRET"}
	s.cfg.WGPrivateKey, s.cfg.AdminToken, s.cfg.GitHubToken = secrets[0], secrets[1], secrets[2]

	w := getDiscovery(t, s, http.MethodGet)
	for _, sec := range secrets {
		if strings.Contains(w.Body.String(), sec) {
			t.Errorf("the document contains %q: %s", sec, w.Body)
		}
	}
	// The admission rules are the server's business, not the client's.
	for _, rule := range []string{"claimward\"]", "allowed_orgs", "allowed_domains", "gateway_client_id", "\"gw\""} {
		if strings.Contains(w.Body.String(), rule) {
			t.Errorf("the document contains %q: %s", rule, w.Body)
		}
	}
	// And the document's keys are exactly the public ones.
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	public := map[string]bool{"version": true, "server_name": true, "providers": true, "exclusive": true, "logo": true}
	for k := range m {
		if !public[k] {
			t.Errorf("unexpected key %q", k)
		}
	}
	providerKeys := map[string]bool{"id": true, "kind": true, "name": true, "github_client_id": true, "oidc_issuer": true, "oidc_client_id": true}
	for _, p := range m["providers"].([]any) {
		for k := range p.(map[string]any) {
			if !providerKeys[k] {
				t.Errorf("unexpected provider key %q", k)
			}
		}
	}
}

func TestDiscoveryRefusesOtherMethods(t *testing.T) {
	s, _ := newServer(t)
	s.cfg.Providers = []config.Provider{ghProvider}
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		w := getDiscovery(t, s, m)
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: status %d, want 405", m, w.Code)
		}
		if w.Body.Len() > 0 && strings.Contains(w.Body.String(), "version") {
			t.Errorf("%s: the refusal carries the document", m)
		}
	}
}

const testLogo = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1 1"><rect width="1" height="1"/></svg>`

func withLogo(s *Server) string {
	sum := sha256.Sum256([]byte(testLogo))
	s.cfg.Logo = []byte(testLogo)
	s.cfg.LogoSHA256 = hex.EncodeToString(sum[:])
	return s.cfg.LogoSHA256
}

func getLogo(s *Server, method string, hdr map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, protocol.PathWellKnownLogo, nil)
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

func TestDiscoveryNamesTheLogo(t *testing.T) {
	s, _ := newServer(t)
	s.cfg.Providers = []config.Provider{ghProvider}
	sum := withLogo(s)
	var got protocol.Configuration
	if err := json.Unmarshal(getDiscovery(t, s, http.MethodGet).Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Logo == nil || got.Logo.Path != protocol.PathWellKnownLogo || got.Logo.SHA256 != sum {
		t.Errorf("logo = %+v, want path %s sha %s", got.Logo, protocol.PathWellKnownLogo, sum)
	}
}

func TestLogoIsServedInertly(t *testing.T) {
	s, _ := newServer(t)
	sum := withLogo(s)
	w := getLogo(s, http.MethodGet, nil)
	if w.Code != http.StatusOK || w.Body.String() != testLogo {
		t.Fatalf("status %d body %q", w.Code, w.Body)
	}
	for k, want := range map[string]string{
		"Content-Type":            "image/svg+xml",
		"X-Content-Type-Options":  "nosniff",
		"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; sandbox",
		"Etag":                    `"` + sum + `"`,
	} {
		if got := w.Header().Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	// A matching validator is a 304 without a body; another one is a 200.
	if w := getLogo(s, http.MethodGet, map[string]string{"If-None-Match": `"` + sum + `"`}); w.Code != http.StatusNotModified || w.Body.Len() != 0 {
		t.Errorf("matching ETag: %d %q", w.Code, w.Body)
	}
	if w := getLogo(s, http.MethodGet, map[string]string{"If-None-Match": `"other"`}); w.Code != http.StatusOK {
		t.Errorf("other ETag: %d", w.Code)
	}
}

func TestNoLogoIs404(t *testing.T) {
	s, _ := newServer(t)
	if w := getLogo(s, http.MethodGet, nil); w.Code != http.StatusNotFound {
		t.Errorf("no logo configured: %d", w.Code)
	}
}
