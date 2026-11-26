package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/claimward/claimward-vpn-client/pkg/protocol"
	"github.com/claimward/claimward-vpn-server/internal/auth"
)

func callAs(h http.Handler, provider, bearer string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, protocol.PathTenants, nil)
	r.Header.Set("Authorization", "Bearer "+bearer)
	if provider != "" {
		r.Header.Set(protocol.HeaderProvider, provider)
	}
	return answer(h, r)
}

// answer is serve without a *testing.T: a crash reads as a 500, which no
// expectation here accepts.
func answer(h http.Handler, r *http.Request) (w *httptest.ResponseRecorder) {
	w = httptest.NewRecorder()
	defer func() {
		if recover() != nil {
			w.Code = http.StatusInternalServerError
		}
	}()
	h.ServeHTTP(w, r)
	return w
}

// ⛔ The request names the provider; the token is judged by it alone, and a
// refusal names the provider problem, not the token.
func TestTheRequestNamesItsProvider(t *testing.T) {
	s, _ := newServer(t)
	other := tokens{"zoe": {Subject: "sub-zoe", Email: "zoe@example.org", EmailVerified: true}}
	set := auth.NewSet()
	if err := set.Add(testProvider, people); err != nil {
		t.Fatal(err)
	}
	if err := set.Add("other", other); err != nil {
		t.Fatal(err)
	}
	s.auth = set
	h := s.Handler()

	if w := callAs(h, testProvider, "alice"); w.Code != http.StatusOK {
		t.Fatalf("alice at her provider: %d %s", w.Code, w.Body)
	}
	if w := callAs(h, "other", "zoe"); w.Code != http.StatusOK {
		t.Fatalf("zoe at hers: %d %s", w.Code, w.Body)
	}
	// The token of one provider, the request naming the other.
	if w := callAs(h, "other", "alice"); w.Code != http.StatusUnauthorized {
		t.Errorf("alice's token at the other provider: %d %s", w.Code, w.Body)
	}
	if w := callAs(h, testProvider, "zoe"); w.Code != http.StatusUnauthorized {
		t.Errorf("zoe's token at the first provider: %d %s", w.Code, w.Body)
	}
	// No provider named: 401 missing_provider; unknown: 401 unknown_provider.
	w := callAs(h, "", "alice")
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), protocol.ErrMissingProvider) {
		t.Errorf("no provider: %d %s", w.Code, w.Body)
	}
	for _, id := range []string{"nope", "TEST", "test ", "other,test"} {
		w := callAs(h, id, "alice")
		if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), protocol.ErrUnknownProvider) {
			t.Errorf("provider %q: %d %s", id, w.Code, w.Body)
		}
	}
}

// ⛔ One person per (issuer, sub): the same "sub" at two providers is two
// identities, so the second cannot take over the first's device.
func TestTheSameSubAtTwoProvidersIsTwoPeople(t *testing.T) {
	s, st := newServer(t)
	a := tokens{"alice": {Subject: "https://one.example#42", Native: "42", Email: "a@example.org", EmailVerified: true}}
	b := tokens{"alice": {Subject: "https://two.example#42", Native: "42", Email: "a@example.org", EmailVerified: true}}
	set := auth.NewSet()
	for id, v := range map[string]auth.Verifier{"one": a, "two": b} {
		if err := set.Add(id, v); err != nil {
			t.Fatal(err)
		}
	}
	s.auth = set
	h := s.Handler()
	enroll := func(provider string) *httptest.ResponseRecorder {
		return callPost(h, protocol.PathEnroll, provider, "alice", `{"public_key":"`+aliceKey+`"}`)
	}
	if w := enroll("one"); w.Code != http.StatusOK {
		t.Fatalf("first provider: %d %s", w.Code, w.Body)
	}
	if w := enroll("two"); w.Code != http.StatusConflict {
		t.Errorf("the same sub at another provider took the key: %d %s", w.Code, w.Body)
	}
	if p := st.Get(aliceKey); p == nil || p.Subject != "https://one.example#42" {
		t.Errorf("the key belongs to %+v", p)
	}
}

func callPost(h http.Handler, path, provider, bearer, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+bearer)
	r.Header.Set(protocol.HeaderProvider, provider)
	return answer(h, r)
}

// ⛔ The registry of WireGuard keys binds the go-authn provider's people ONLY:
// another provider's person enrols as before, and a reconciliation never drops
// a peer whose subject is not that issuer's.
func TestTheRegistryBindsItsOwnProviderOnly(t *testing.T) {
	s, st := newServer(t)
	const issuer = "https://authn.example.org"
	ga := tokens{"gina": {Subject: issuer + "#sub-gina", Native: "sub-gina", Email: "gina@example.org", EmailVerified: true}}
	set := auth.NewSet()
	for id, v := range map[string]auth.Verifier{"fed": ga, "hub": people} {
		if err := set.Add(id, v); err != nil {
			t.Fatal(err)
		}
	}
	s.auth = set
	s.UsePeers(fixed{}, "fed", issuer)
	h := s.Handler()

	// Nothing is registered: the go-authn person is refused, the other is not.
	if w := callPost(h, protocol.PathEnroll, "fed", "gina", `{"public_key":"`+aliceKey+`"}`); w.Code != http.StatusForbidden {
		t.Errorf("an unregistered key at the registry's provider: %d %s", w.Code, w.Body)
	}
	if w := callPost(h, protocol.PathEnroll, "hub", "alice", `{"public_key":"`+aliceKey+`"}`); w.Code != http.StatusOK {
		t.Fatalf("another provider's person: %d %s", w.Code, w.Body)
	}
	// The reconciliation that allows nobody drops only the issuer's peers.
	s.Reconcile(func(string, string) bool { return false })
	if st.Get(aliceKey) == nil {
		t.Error("a peer of another provider was dropped by the registry's reconciliation")
	}
}

// serve calls h and turns a panic into a test failure, so a missing guard
// reads as a wrong answer and not as a crash of the whole test binary.
func serve(t *testing.T, h http.Handler, r *http.Request) (w *httptest.ResponseRecorder) {
	t.Helper()
	w = httptest.NewRecorder()
	defer func() {
		if p := recover(); p != nil {
			t.Errorf("%s %s crashed instead of answering: %v", r.Method, r.URL.Path, p)
			w.Code = http.StatusInternalServerError
		}
	}()
	h.ServeHTTP(w, r)
	return w
}

func TestAnAbsentOrWrongTokenIsRefusedByCode(t *testing.T) {
	s, _ := newServer(t)
	h := s.Handler()

	// The provider is named but there is no bearer at all.
	r := httptest.NewRequest(http.MethodGet, protocol.PathTenants, nil)
	r.Header.Set(protocol.HeaderProvider, testProvider)
	w := serve(t, h, r)
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "missing_token") {
		t.Errorf("no bearer: %d %s", w.Code, w.Body)
	}

	// A bearer the named provider does not know.
	r = httptest.NewRequest(http.MethodGet, protocol.PathTenants, nil)
	r.Header.Set(protocol.HeaderProvider, testProvider)
	r.Header.Set("Authorization", "Bearer nobody")
	w = serve(t, h, r)
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "invalid_token") {
		t.Errorf("unknown bearer: %d %s", w.Code, w.Body)
	}
	if w.Code == http.StatusOK || strings.Contains(w.Body.String(), protocol.ErrUnknownProvider) {
		t.Errorf("a bad token read as another refusal: %s", w.Body)
	}
}

func TestWithoutARegistryEveryKeyMayEnrol(t *testing.T) {
	s, _ := newServer(t)
	lease := time.Now().Add(time.Hour)
	var (
		got time.Time
		ok  bool
	)
	func() {
		defer func() {
			if p := recover(); p != nil {
				t.Errorf("registered crashed with no registry: %v", p)
			}
		}()
		got, ok = s.registered(aliceKey, &auth.Claims{Provider: testProvider, Native: "x"}, lease)
	}()
	if !ok || !got.Equal(lease) {
		t.Errorf("no registry: %v, %v, want the lease %v and true", got, ok, lease)
	}
}
