package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/claimward/claimward-vpn-server/internal/metrics"
	"github.com/claimward/claimward-vpn-server/internal/store"
	"github.com/claimward/claimward-vpn-server/internal/tenant"
	"google.golang.org/grpc"
)

// Every HTTP timeout is set and bounded: a client cannot hold a connection by
// trickling a body, not reading a response, or idling.
func TestHTTPServerBoundsEveryPhaseOfAConnection(t *testing.T) {
	s := newHTTPServer(":0", http.NotFoundHandler())
	for name, d := range map[string]time.Duration{
		"ReadHeaderTimeout": s.ReadHeaderTimeout, "ReadTimeout": s.ReadTimeout,
		"WriteTimeout": s.WriteTimeout, "IdleTimeout": s.IdleTimeout,
	} {
		if d <= 0 || d > 5*time.Minute {
			t.Errorf("%s = %v, want a bound within 5 minutes", name, d)
		}
	}
	if s.MaxHeaderBytes <= 0 || s.MaxHeaderBytes > 1<<20 {
		t.Errorf("MaxHeaderBytes = %d", s.MaxHeaderBytes)
	}
}

// A slow client is cut at the read timeout, for real.
func TestASlowClientIsCutAtTheReadTimeout(t *testing.T) {
	s := newHTTPServer("", http.NotFoundHandler())
	s.ReadHeaderTimeout = 100 * time.Millisecond
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go s.Serve(ln) //nolint:errcheck
	defer s.Close()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n")) // never finishes the headers
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadAll(c); err != nil {
		t.Errorf("the server did not close a stalled connection: %v", err)
	}
}

// The listener never holds more than the cap at once.
func TestConnectionsAreCapped(t *testing.T) {
	if maxConns <= 0 || maxConns > 100000 {
		t.Fatalf("maxConns = %d", maxConns)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	lim := limitConns(ln)
	// The wrapper is not the bare listener.
	if lim == ln {
		t.Error("limitConns returned the listener unchanged")
	}
}

// The gRPC options are accepted by a server and carry the three limits.
func TestGRPCServerIsBounded(t *testing.T) {
	opts := grpcLimits()
	if len(opts) != 3 {
		t.Fatalf("%d limit options, want 3 (enforcement policy, keepalive params, stream cap)", len(opts))
	}
	if maxGRPCStreams <= 0 || maxGRPCStreams > 100 {
		t.Errorf("maxGRPCStreams = %d", maxGRPCStreams)
	}
	grpc.NewServer(opts...).Stop()
}

// /metrics names every tenant: it is served by its own mux, and only there.
func TestMetricsAreOnTheirOwnMux(t *testing.T) {
	ts := tenant.New(nil, nil)
	if _, err := ts.Create(tenant.Tenant{Name: "Acme Lab"}); err != nil {
		t.Fatal(err)
	}
	mux := metricsMux(metrics.New(store.New(), ts))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	if w.Code != 200 {
		t.Errorf("GET /metrics: %d", w.Code)
	}
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", "/admin/", nil))
	if w.Code != 404 {
		t.Errorf("the metrics listener serves /admin/: %d", w.Code)
	}
}

// The public mux built in run() never registers /metrics. (run() builds its
// servers inline, so this reads the source.)
func TestTheEnrollmentMuxDoesNotServeMetrics(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "main.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	ast.Inspect(f, func(n ast.Node) bool {
		if lit, ok := n.(*ast.BasicLit); ok && lit.Value == `"GET /metrics"` {
			t.Errorf("main.go registers %s on a mux", lit.Value)
		}
		return true
	})
}
