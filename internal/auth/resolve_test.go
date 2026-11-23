package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
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
		_, err := NewGitHubResolver(srv.URL)(context.Background(), "alice")
		srv.Close()
		if err == nil {
			t.Errorf("%s: accepted", c.name)
		}
	}

	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(good))
	}))
	defer ok.Close()
	if id, err := NewGitHubResolver(ok.URL+"/")(context.Background(), "alice"); err != nil || id != 5 {
		t.Errorf("good answer: %d, %v", id, err)
	}
}

func TestResolverFailsOnATransportOrURLError(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close() // nothing listens any more
	if _, err := NewGitHubResolver(url)(context.Background(), "alice"); err == nil {
		t.Error("a refused connection was not an error")
	}
	if _, err := NewGitHubResolver("http://bad host")(context.Background(), "alice"); err == nil {
		t.Error("an invalid base URL was not an error")
	}
	if _, err := NewGitHubResolver("http://x")(nil, "alice"); err == nil { //nolint:staticcheck // nil ctx is the point
		t.Error("a nil context was not an error")
	}
}
