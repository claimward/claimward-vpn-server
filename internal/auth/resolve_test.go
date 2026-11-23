package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Every way the answer can be wrong is an error, one test per guard.
func TestResolverRefusesWhatIsNotAUserAnswer(t *testing.T) {
	good := `{"id":5,"login":"Alice","type":"User"}`
	cases := []struct {
		name   string
		status int
		body   string
	}{
		{"http error with a valid body", 404, good},
		{"server error", 500, good},
		{"not json", 200, "<html>"},
		{"truncated json", 200, `{"id":5,`},
		{"complete fields, unterminated object", 200, `{"id":5,"login":"alice","type":"User"`},
		{"organisation", 200, `{"id":5,"login":"alice","type":"Organization"}`},
		{"no id", 200, `{"id":0,"login":"alice","type":"User"}`},
		{"other login", 200, `{"id":5,"login":"mallory","type":"User"}`},
	}
	for _, c := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(c.status)
			_, _ = w.Write([]byte(c.body))
		}))
		_, err := NewGitHubResolver(srv.URL, "tok")(context.Background(), "alice")
		srv.Close()
		if err == nil {
			t.Errorf("%s: accepted", c.name)
		}
	}

	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(good))
	}))
	defer ok.Close()
	if id, err := NewGitHubResolver(ok.URL+"/", "tok")(context.Background(), "alice"); err != nil || id != 5 {
		t.Errorf("good answer: %d, %v", id, err)
	}
}

func TestResolverFailsOnATransportOrURLError(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close() // nothing listens any more
	if _, err := NewGitHubResolver(url, "tok")(context.Background(), "alice"); err == nil {
		t.Error("a refused connection was not an error")
	}
	if _, err := NewGitHubResolver("http://bad host", "tok")(context.Background(), "alice"); err == nil {
		t.Error("an invalid base URL was not an error")
	}
	if _, err := NewGitHubResolver("https://x", "tok")(nil, "alice"); err == nil { //nolint:staticcheck // nil ctx is the point
		t.Error("a nil context was not an error")
	}
}

// The resolver sends the github-token as a bearer.
func TestResolverSendsTheBearer(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{"id":5,"login":"alice","type":"User"}`))
	}))
	defer srv.Close()
	if _, err := NewGitHubResolver(srv.URL, "ghp_secret")(context.Background(), "alice"); err != nil {
		t.Fatal(err)
	}
	if got != "Bearer ghp_secret" {
		t.Errorf("Authorization = %q", got)
	}
}

// With no token the resolver refuses without a request, naming the file.
func TestResolverWithoutATokenRefuses(t *testing.T) {
	hit := false
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hit = true }))
	defer srv.Close()
	_, err := NewGitHubResolver(srv.URL, "")(context.Background(), "alice")
	if err == nil || !strings.Contains(err.Error(), "github-token") {
		t.Fatalf("err = %v", err)
	}
	if hit {
		t.Error("a request went out without a token")
	}
}

// The token never travels in clear to a remote host.
func TestResolverSendsTheTokenOnlyOverHTTPSOrLoopback(t *testing.T) {
	_, err := NewGitHubResolver("http://ghe.example.org", "tok")(context.Background(), "alice")
	if err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("err = %v", err)
	}
}
