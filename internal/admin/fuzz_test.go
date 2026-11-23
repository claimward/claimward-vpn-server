package admin

import (
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

func adminMux() *http.ServeMux {
	ts := tenant.New([]string{"10.80.0.0/24"}, nil)
	s := New(ts, store.New(), "secret", fstest.MapFS{"index.html": {Data: []byte("x")}},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	mux := http.NewServeMux()
	s.Register(mux)
	return mux
}

// FuzzAdminTenantBody: the JSON a (token-holding) admin sends to create or
// update a tenant. A hostile body is a 4xx, never a 5xx or a panic.
func FuzzAdminTenantBody(f *testing.F) {
	for _, s := range []string{
		`{"id":"hpc","name":"HPC","groups":["hpc"],"allowed_ips":["10.2.0.0/16"]}`,
		`{"id":"x","policy":[{"cidr":"10.20.0.5/32","proto":"tcp","ports":[445,88]}]}`,
		`{"id":"x","policy":[{"cidr":"::/0","proto":"any"}]}`,
		`{"id":"../../etc","name":"` + strings.Repeat("A", 1<<10) + `"}`,
		`{}`, ``, `null`, `[]`, `{"id":`, `{"allowed_ips":["not a cidr"]}`,
		`{"id":"x","groups":[null,1,{}]}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		mux := adminMux()
		for _, c := range []struct{ method, path string }{
			{"POST", "/admin/api/tenants"},
			{"PUT", "/admin/api/tenants/default"},
		} {
			r := httptest.NewRequest(c.method, c.path, strings.NewReader(string(body)))
			r.Header.Set("Authorization", "Bearer secret")
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, r)
			if w.Code >= 500 {
				t.Fatalf("%s %q: status %d %s", c.method, body, w.Code, w.Body)
			}
		}
	})
}
