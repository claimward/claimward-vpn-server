package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type fakeMembers map[string]bool

func (f fakeMembers) NamedMember(s string) bool { return f[s] }
func (f fakeMembers) HasNamedMembers() bool     { return len(f) > 0 }

// A GitHub whose /user is id 42 ("octocat") and that has no organisations.
func loneGitHub(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/user":
			_ = json.NewEncoder(w).Encode(map[string]any{"id": 42, "login": "octocat"})
		case r.URL.Path == "/user/orgs":
			_, _ = w.Write([]byte("[]"))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestNamedMemberIsAdmittedWithoutAnyOrg(t *testing.T) {
	gh := loneGitHub(t)
	v := NewGitHubVerifier(gh.URL, nil).WithMembers(fakeMembers{"github:42": true})
	c, err := v.Verify(context.Background(), "t")
	if err != nil || c.Subject != "github:42" {
		t.Fatalf("claims %+v err %v", c, err)
	}
}

// ⛔ The login "octocat" was renamed and taken by another account: the pin is
// the ID, so the new holder of the name is refused.
func TestARenamedLoginWhoseIDChangedIsRefused(t *testing.T) {
	gh := loneGitHub(t) // the account now called octocat is id 42
	v := NewGitHubVerifier(gh.URL, nil).WithMembers(fakeMembers{"github:583231": true})
	if _, err := v.Verify(context.Background(), "t"); err == nil {
		t.Error("an account with the pinned login but another ID was admitted")
	}
}

// ⛔ Fail closed: no org and no member is not "everybody".
func TestVerifierRefusesWithNeitherOrgsNorMembers(t *testing.T) {
	gh := loneGitHub(t)
	for name, v := range map[string]*GitHubVerifier{
		"nil members":   NewGitHubVerifier(gh.URL, nil),
		"empty members": NewGitHubVerifier(gh.URL, []string{" "}).WithMembers(fakeMembers{}),
	} {
		if _, err := v.Verify(context.Background(), "t"); err == nil {
			t.Errorf("%s: admitted", name)
		}
	}
}

func resolverServer(t *testing.T, h http.HandlerFunc) func(string) (int64, error) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	r := NewGitHubResolver(srv.URL)
	return func(login string) (int64, error) { return r(context.Background(), login) }
}

func TestResolver(t *testing.T) {
	resolve := resolverServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch strings.TrimPrefix(r.URL.Path, "/users/") {
		case "octocat", "Octocat":
			_, _ = w.Write([]byte(`{"id":583231,"login":"octocat","type":"User"}`))
		case "acme":
			_, _ = w.Write([]byte(`{"id":7,"login":"acme","type":"Organization"}`))
		case "swapped":
			_, _ = w.Write([]byte(`{"id":8,"login":"someone-else","type":"User"}`))
		case "zero":
			_, _ = w.Write([]byte(`{"id":0,"login":"zero","type":"User"}`))
		default:
			http.NotFound(w, r)
		}
	})
	if id, err := resolve("Octocat"); err != nil || id != 583231 {
		t.Errorf("octocat: %d %v", id, err)
	}
	for _, bad := range []string{"acme", "swapped", "zero", "ghost"} {
		if id, err := resolve(bad); err == nil {
			t.Errorf("%s resolved to %d", bad, id)
		}
	}
}

func TestResolverBounds(t *testing.T) {
	big := resolverServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"id":1,"login":"a","type":"User","bio":"`))
		_, _ = w.Write([]byte(strings.Repeat("x", 2*maxResolveBody)))
		_, _ = w.Write([]byte(`"}`))
	})
	if _, err := big("a"); err == nil {
		t.Error("an oversized answer was accepted")
	}

	release := make(chan struct{})
	slow := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	t.Cleanup(slow.Close)
	t.Cleanup(func() { close(release) })
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := NewGitHubResolver(slow.URL)(ctx, "a"); err == nil {
		t.Error("a silent server did not stop the resolution")
	}
}
