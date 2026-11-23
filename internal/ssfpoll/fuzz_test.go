package ssfpoll

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// FuzzProviderAnswers: what a provider answers on its SSF configuration and
// poll endpoints is untrusted input. Whatever it is, one poll returns (an
// error or not) -- it neither panics nor hangs -- and the kick channel, which
// has room for one, is never blocked on.
func FuzzProviderAnswers(f *testing.F) {
	f.Add([]byte(`[{"delivery":{"method":"urn:ietf:rfc:8936","endpoint_url":"POLL"}}]`), []byte(`{"sets":{"a":"jwt"}}`))
	f.Add([]byte(`{"delivery":{"method":"urn:ietf:rfc:8936","endpoint_url":"POLL"}}`), []byte(`{"sets":{}}`))
	f.Add([]byte(`{"delivery":{"endpoint_url":"POLL"}}`), []byte(`{}`))
	f.Add([]byte(`[]`), []byte(`null`))
	f.Add([]byte(`[null,1,"x",{"delivery":3}]`), []byte(`{"sets":[1,2]}`))
	f.Add([]byte(``), []byte(``))
	f.Add([]byte(`{"delivery":{"method":"urn:ietf:rfc:8936","endpoint_url":"http://169.254.169.254/"}}`), []byte(`{"sets":{"":""}}`))
	f.Fuzz(func(t *testing.T, config, poll []byte) {
		var srv *httptest.Server
		mux := http.NewServeMux()
		mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
			fmt.Fprintf(w, `{"token_endpoint":%q}`, srv.URL+"/token")
		})
		mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
			io.WriteString(w, `{"access_token":"t","expires_in":3600}`)
		})
		mux.HandleFunc("/.well-known/ssf-configuration", func(w http.ResponseWriter, _ *http.Request) {
			fmt.Fprintf(w, `{"configuration_endpoint":%q}`, srv.URL+"/config")
		})
		// POLL stands for this provider's own poll endpoint, so that a seed
		// can get past discovery and put the fuzzed bytes through the poll.
		mux.HandleFunc("/config", func(w http.ResponseWriter, _ *http.Request) {
			w.Write(bytes.ReplaceAll(config, []byte("POLL"), []byte(srv.URL+"/poll")))
		})
		mux.HandleFunc("/poll", func(w http.ResponseWriter, _ *http.Request) { w.Write(poll) })
		srv = httptest.NewServer(mux)
		defer srv.Close()

		kick := make(chan struct{}, 1)
		p := New(Config{Issuer: srv.URL, ClientID: "gw", ClientSecret: "s", Client: &http.Client{Timeout: 2 * time.Second}},
			kick, slog.New(slog.NewTextHandler(io.Discard, nil)))
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		done := make(chan struct{})
		go func() { defer close(done); _ = p.Once(ctx); _ = p.Once(ctx) }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatalf("a poll hung on config=%q poll=%q", config, poll)
		}
	})
}
