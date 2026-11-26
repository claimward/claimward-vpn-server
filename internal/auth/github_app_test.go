package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

const (
	testClientID = "Iv1.ourapp"
	testSecret   = "s3cret-of-our-app"
)

// fakeGitHubApp is a GitHub whose "check a token" endpoint knows which app
// minted each token: tokens maps a token to the client_id of its app. A token
// not in the map answers checkStatus (404 by default: GitHub's answer for an
// invalid token). checks counts the check calls; the secret must arrive as
// basic auth.
func fakeGitHubApp(t *testing.T, tokens map[string]string, checkStatus int, checks *atomic.Int64) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/applications/"+testClientID+"/token":
			if checks != nil {
				checks.Add(1)
			}
			id, sec, ok := r.BasicAuth()
			if !ok || id != testClientID || sec != testSecret || r.Header.Get("Authorization") == "" || strings.HasPrefix(r.Header.Get("Authorization"), "Bearer") {
				http.Error(w, "bad credentials", http.StatusUnauthorized)
				return
			}
			var body struct {
				AccessToken string `json:"access_token"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			app, known := tokens[body.AccessToken]
			if !known {
				w.WriteHeader(checkStatus)
				return
			}
			// GitHub only checks tokens of the app named in the path, but a
			// hostile or buggy answer must not be taken on trust either.
			w.Write([]byte(`{"app":{"client_id":"` + app + `"},"user":{"id":424242,"login":"random-stranger"}}`))
		case r.URL.Path == "/user":
			w.Write([]byte(`{"id":424242,"login":"random-stranger"}`))
		case r.URL.Path == "/user/orgs":
			w.Write([]byte(`[]`))
		default:
			w.Write([]byte(`{"state":"active"}`))
		}
	}))
	t.Cleanup(s.Close)
	return s
}

func appVerifier(url string) *GitHubVerifier { return appVerifierOrgs(url, "acme") }

func appVerifierOrgs(url string, orgs ...string) *GitHubVerifier {
	return NewGitHubVerifier(url, orgs).WithApp(testClientID, testSecret)
}

func TestGitHubTokenOfOurAppIsAdmitted(t *testing.T) {
	gh := fakeGitHubApp(t, map[string]string{"ours": testClientID}, http.StatusNotFound, nil)
	if _, err := appVerifier(gh.URL).Verify(context.Background(), "ours"); err != nil {
		t.Fatalf("a token of our own app was refused: %v", err)
	}
}

func TestGitHubTokenOfAnotherAppIsRefused(t *testing.T) {
	// The same person, an active member of the allowed org, with a valid token
	// minted by some other OAuth app: everything else would admit it.
	var checks atomic.Int64
	gh := fakeGitHubApp(t, map[string]string{"theirs": "Iv1.otherapp"}, http.StatusNotFound, &checks)
	if c, err := appVerifier(gh.URL).Verify(context.Background(), "theirs"); err == nil {
		t.Fatalf("a token minted by another OAuth app was admitted: %+v", c)
	}
	if checks.Load() != 1 {
		t.Errorf("check-token calls = %d, want 1", checks.Load())
	}
}

func TestGitHubCheckTokenFailuresRefuse(t *testing.T) {
	for _, status := range []int{http.StatusNotFound, http.StatusUnprocessableEntity, http.StatusInternalServerError, http.StatusBadGateway} {
		gh := fakeGitHubApp(t, nil, status, nil)
		if c, err := appVerifier(gh.URL).Verify(context.Background(), "whatever"); err == nil {
			t.Errorf("check answering %d admitted a token: %+v", status, c)
		}
	}
	// A 200 whose body is not an app description, or is oversized junk.
	for name, body := range map[string]string{
		"empty object": `{}`,
		"not json":     `<html>`,
		"no app":       `{"user":{"id":424242}}`,
		"huge":         `{"app":{"client_id":"` + strings.Repeat("a", 1<<20) + `"}}`,
	} {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/applications/") {
				w.Write([]byte(body))
				return
			}
			w.Write([]byte(`{"id":424242,"login":"x"}`))
		}))
		if _, err := appVerifier(s.URL).Verify(context.Background(), "t"); err == nil {
			t.Errorf("%s: a token was admitted", name)
		}
		s.Close()
	}
}

func TestGitHubCheckTokenUserMustMatchTheUserEndpoint(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/applications/" + testClientID + "/token":
			w.Write([]byte(`{"app":{"client_id":"` + testClientID + `"},"user":{"id":7}}`))
		case "/user":
			w.Write([]byte(`{"id":424242,"login":"x"}`))
		case "/user/orgs":
			w.Write([]byte(`[]`))
		default: // the org membership: everything else would admit the token
			w.Write([]byte(`{"state":"active"}`))
		}
	}))
	defer s.Close()
	if _, err := appVerifier(s.URL).Verify(context.Background(), "t"); err == nil {
		t.Error("a check-token user different from /user was admitted")
	}
}

// Only a 200 vouches: an error status is refused even when its body reads like
// a good answer, and the org membership would admit the person.
func TestGitHubCheckTokenErrorStatusWithAGoodBodyRefuses(t *testing.T) {
	s := httptest.NewServer(appCheckStatus(http.StatusUnprocessableEntity, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/user":
			w.Write([]byte(`{"id":424242,"login":"x"}`))
		case "/user/orgs":
			w.Write([]byte(`[]`))
		default:
			w.Write([]byte(`{"state":"active"}`))
		}
	})))
	defer s.Close()
	if _, err := appVerifier(s.URL).Verify(context.Background(), "t"); err == nil {
		t.Error("a 422 carrying an app and a user admitted a token")
	}
}

func appCheckStatus(status int, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/applications/"+testClientID+"/token" {
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(map[string]any{"app": map[string]any{"client_id": testClientID}, "user": map[string]any{"id": 424242}})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// GitHub unreachable, or no context to ask with: refused, never admitted.
func TestGitHubCheckTokenCannotBeAskedRefuses(t *testing.T) {
	s := httptest.NewServer(http.NotFoundHandler())
	url := s.URL
	s.Close()
	if _, err := appVerifier(url).Verify(context.Background(), "t"); err == nil {
		t.Error("an unreachable GitHub admitted a token")
	}
	var noCtx context.Context
	if _, err := appVerifier("http://127.0.0.1:1").checkApp(noCtx, "t"); err == nil {
		t.Error("a request that cannot be built admitted a token")
	}
}

// A verifier with no app configured refuses everything, before asking GitHub.
func TestGitHubVerifierWithoutAppRefuses(t *testing.T) {
	hits.Store(0)
	gh := fakeGitHub(t, true)
	if c, err := NewGitHubVerifier(gh.URL, []string{"acme"}).Verify(context.Background(), "t"); err == nil {
		t.Errorf("no OAuth app configured, token admitted: %+v", c)
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("%d GitHub requests before refusing", n)
	}
	if _, err := NewGitHubVerifier(gh.URL, []string{"acme"}).WithApp("id", "").Verify(context.Background(), "t"); err == nil {
		t.Error("empty secret admitted")
	}
}

// The client secret is only sent over https, or to loopback.
func TestGitHubAppSecretNotSentOverPlainHTTP(t *testing.T) {
	v := NewGitHubVerifier("http://github.example.org", []string{"acme"}).WithApp(testClientID, testSecret)
	if _, err := v.Verify(context.Background(), "t"); err == nil || !strings.Contains(err.Error(), "https") {
		t.Errorf("err = %v, want a refusal naming https", err)
	}
}

// appCheck makes a fake GitHub vouch, for our app, for every token of user
// userID; every other request goes to next.
func appCheck(userID int64, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/applications/"+testClientID+"/token" {
			_ = json.NewEncoder(w).Encode(map[string]any{"app": map[string]any{"client_id": testClientID}, "user": map[string]any{"id": userID}})
			return
		}
		next.ServeHTTP(w, r)
	})
}
