package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/claimward/claimward-vpn-client/pkg/protocol"
)

func getDiscovery(t *testing.T, s *Server, method string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest(method, protocol.PathWellKnownConfiguration, nil))
	return w
}

func TestDiscoveryGitHub(t *testing.T) {
	s, _ := newServer(t)
	s.cfg.AuthProvider = "github"
	s.cfg.GitHubClientID = "Iv1.ourapp"
	s.cfg.ServerName = "Lab"
	s.cfg.Exclusive = true
	// Everything else configured must stay out of the document.
	s.cfg.OIDCIssuer, s.cfg.OIDCClientID = "https://ignored", "ignored"

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
	want := protocol.Configuration{Version: protocol.ConfigurationVersion, ServerName: "Lab", Provider: "github", GitHubClientID: "Iv1.ourapp", Exclusive: true}
	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestDiscoveryOIDCOmitsWhatIsAbsent(t *testing.T) {
	for _, provider := range []string{"oidc", "go-authn"} {
		s, _ := newServer(t)
		s.cfg.AuthProvider = provider
		s.cfg.OIDCIssuer, s.cfg.OIDCClientID = "https://idp.example.org", "claimward"
		s.cfg.GitHubClientID = "ignored"

		w := getDiscovery(t, s, http.MethodGet)
		var m map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
			t.Fatal(err)
		}
		want := map[string]any{"version": float64(protocol.ConfigurationVersion), "provider": provider, "oidc_issuer": "https://idp.example.org", "oidc_client_id": "claimward", "exclusive": false}
		if len(m) != len(want) {
			t.Errorf("%s: %v, want exactly %v (no invented server_name, no github_client_id)", provider, m, want)
		}
		for k, v := range want {
			if m[k] != v {
				t.Errorf("%s: %s = %v, want %v", provider, k, m[k], v)
			}
		}
	}
}

// ⛔ The document is public: no secret the server holds may ever be in it.
func TestDiscoveryNeverHoldsASecret(t *testing.T) {
	s, _ := newServer(t)
	s.cfg.AuthProvider = "github"
	s.cfg.GitHubClientID = "Iv1.ourapp"
	secrets := []string{"wg-private-SECRET", "admin-SECRET", "gh-token-SECRET", "app-client-SECRET", "gateway-SECRET"}
	s.cfg.WGPrivateKey, s.cfg.AdminToken, s.cfg.GitHubToken, s.cfg.GitHubClientSecret, s.cfg.GatewaySecret = secrets[0], secrets[1], secrets[2], secrets[3], secrets[4]

	w := getDiscovery(t, s, http.MethodGet)
	for _, sec := range secrets {
		if strings.Contains(w.Body.String(), sec) {
			t.Errorf("the document contains %q: %s", sec, w.Body)
		}
	}
	// And the document's keys are exactly the public ones.
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	public := map[string]bool{"version": true, "server_name": true, "provider": true, "github_client_id": true, "oidc_issuer": true, "oidc_client_id": true, "exclusive": true}
	for k := range m {
		if !public[k] {
			t.Errorf("unexpected key %q", k)
		}
	}
}

func TestDiscoveryRefusesOtherMethods(t *testing.T) {
	s, _ := newServer(t)
	s.cfg.AuthProvider = "github"
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
