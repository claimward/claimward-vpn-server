package admin

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/claimward/claimward-vpn-server/internal/store"
	"github.com/claimward/claimward-vpn-server/internal/tenant"
)

func memberMux(ts *tenant.Store) *http.ServeMux {
	s := New(ts, store.New(), "secret", fstest.MapFS{"index.html": {Data: []byte("x")}},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	mux := http.NewServeMux()
	s.Register(mux)
	return mux
}

func send(mux *http.ServeMux, method, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer secret")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w
}

// An unresolvable login is a 400 on create and update; a resolvable one is
// pinned and shown with its login.
func TestAdminMembersAreResolved(t *testing.T) {
	ts := tenant.New(nil, nil)
	ts.SetResolver(func(_ context.Context, l string) (int64, error) {
		if l == "alice" {
			return 11, nil
		}
		return 0, errors.New("no such user")
	})
	mux := memberMux(ts)
	if w := send(mux, "POST", "/admin/api/tenants", `{"id":"lab","members":["alice","ghost"]}`); w.Code != http.StatusBadRequest {
		t.Errorf("create with an unresolvable login: %d %s", w.Code, w.Body)
	}
	w := send(mux, "POST", "/admin/api/tenants", `{"id":"lab","members":["alice"]}`)
	if w.Code != http.StatusCreated && w.Code != http.StatusOK {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}
	if !strings.Contains(w.Body.String(), `"members":["alice"]`) || !strings.Contains(w.Body.String(), `"alice":11`) {
		t.Errorf("the tenant shows %s", w.Body)
	}
	if w := send(mux, "PUT", "/admin/api/tenants/lab", `{"members":["ghost"]}`); w.Code != http.StatusBadRequest {
		t.Errorf("update with an unresolvable login: %d %s", w.Code, w.Body)
	}
}
