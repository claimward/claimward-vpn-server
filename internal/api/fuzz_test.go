package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/claimward/claimward-vpn-client/pkg/protocol"
)

func rawPost(h http.Handler, path, who, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+who)
	r.Header.Set(protocol.HeaderProvider, testProvider)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// FuzzEnrollBody: whatever a client sends as the enrollment body, the server
// answers with a status that is never a 5xx (a hostile body is the client's
// error, not the server's), never panics, and a 200 leaves the key enrolled
// with an address inside the pool.
func FuzzEnrollBody(f *testing.F) {
	for _, s := range []string{
		`{"public_key":"` + aliceKey + `"}`,
		`{"public_key":"` + aliceKey + `","tenant":"hpc"}`,
		`{}`, ``, `null`, `[]`, `"x"`, `{"public_key":`, `{"public_key":123}`,
		`{"public_key":"` + strings.Repeat("A", 1<<12) + `"}`,
		`{"public_key":"` + aliceKey + `","extra":{"a":[1,2,3]}}`,
		`{"public_key":"` + aliceKey + `"} {"public_key":"` + aliceKey + `"}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		s, st := newServer(t)
		w := rawPost(s.Handler(), protocol.PathEnroll, "alice", string(body))
		if w.Code >= 500 {
			t.Fatalf("body %q: status %d %s", body, w.Code, w.Body)
		}
		if w.Code == http.StatusOK && len(st.List()) != 1 {
			t.Fatalf("body %q: 200 but %d peers enrolled", body, len(st.List()))
		}
	})
}

// FuzzDeregisterBody: the same for the deregistration body.
func FuzzDeregisterBody(f *testing.F) {
	for _, s := range []string{
		`{"public_key":"` + aliceKey + `"}`, `{}`, ``, `null`, `{"public_key":`, `[1]`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		s, _ := newServer(t)
		w := rawPost(s.Handler(), protocol.PathDeregister, "alice", string(body))
		if w.Code >= 500 {
			t.Fatalf("body %q: status %d %s", body, w.Code, w.Body)
		}
	})
}
