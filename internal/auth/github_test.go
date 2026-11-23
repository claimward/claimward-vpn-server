package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// hits counts the requests the fake GitHub received.
var hits atomic.Int64

// fakeGitHub answers /user, /user/orgs and the membership check; member is
// whether the user is an active member of any org.
func fakeGitHub(t *testing.T, member bool) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		switch {
		case r.URL.Path == "/user":
			w.Write([]byte(`{"id":424242,"login":"random-stranger"}`))
		case r.URL.Path == "/user/orgs":
			w.Write([]byte(`[]`))
		case member:
			w.Write([]byte(`{"state":"active"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(s.Close)
	return s
}

// With no org allowlist the verifier must refuse everybody: an empty list
// would admit any GitHub account.
func TestGitHubVerifierWithoutAllowlistRefusesStrangers(t *testing.T) {
	gh := fakeGitHub(t, true)
	for _, orgs := range [][]string{nil, {}, {" ", ""}} {
		hits.Store(0)
		v := NewGitHubVerifier(gh.URL, orgs)
		if c, err := v.Verify(context.Background(), "any-token"); err == nil {
			t.Errorf("allowlist %q: a stranger with no org was accepted: %+v", orgs, c)
		}
		// Refused before anything is asked of GitHub: the check does not
		// rest on the membership lookup coming back empty.
		if n := hits.Load(); n != 0 {
			t.Errorf("allowlist %q: %d GitHub requests made before refusing", orgs, n)
		}
	}
}

func TestGitHubVerifierWithAllowlistAdmitsMembersOnly(t *testing.T) {
	if _, err := NewGitHubVerifier(fakeGitHub(t, true).URL, []string{"acme"}).Verify(context.Background(), "t"); err != nil {
		t.Errorf("an active member was refused: %v", err)
	}
	if _, err := NewGitHubVerifier(fakeGitHub(t, false).URL, []string{"acme"}).Verify(context.Background(), "t"); err == nil {
		t.Error("a non-member was accepted")
	}
}
