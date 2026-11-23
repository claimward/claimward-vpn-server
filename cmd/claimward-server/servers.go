package main

import (
	"net"
	"net/http"
	"time"

	"golang.org/x/net/netutil"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
)

// ⛔ Bounds on what a connection may cost. The HTTP server used to set only
// ReadHeaderTimeout, so a client could hold a connection open forever by
// trickling a body, never reading a response, or idling; the gRPC server had
// no keepalive enforcement, stream limit or connection limit.
const (
	maxConns        = 4096 // simultaneous connections per listener
	maxGRPCStreams  = 8    // concurrent streams on ONE gRPC connection
	httpReadTimeout = 30 * time.Second
	httpWriteTime   = 30 * time.Second
	httpIdleTimeout = 120 * time.Second
)

// newHTTPServer is an http.Server with every timeout set.
func newHTTPServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       httpReadTimeout,
		WriteTimeout:      httpWriteTime,
		IdleTimeout:       httpIdleTimeout,
		MaxHeaderBytes:    64 << 10,
	}
}

// grpcLimits bounds a gRPC connection: clients may not ping faster than
// every 30 s, a connection with no stream is closed after 2 minutes, a dead
// peer is detected, and one connection carries few streams.
func grpcLimits() []grpc.ServerOption {
	return []grpc.ServerOption{
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             30 * time.Second,
			PermitWithoutStream: false,
		}),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			MaxConnectionIdle: 2 * time.Minute,
			Time:              1 * time.Minute,
			Timeout:           20 * time.Second,
		}),
		grpc.MaxConcurrentStreams(maxGRPCStreams),
	}
}

// metricsMux serves the Prometheus exposition, and only that, on its own
// listener: it names every tenant, so it is not on the enrollment mux.
func metricsMux(h interface{ Handler() http.Handler }) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", h.Handler())
	return mux
}

// serveLimited listens on srv.Addr with a connection cap, over TLS when a
// certificate is given.
func serveLimited(srv *http.Server, cert, key string) error {
	ln, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		return err
	}
	ln = limitConns(ln)
	if cert != "" && key != "" {
		return srv.ServeTLS(ln, cert, key)
	}
	return srv.Serve(ln)
}

// limitConns caps the simultaneous connections accepted from ln.
func limitConns(ln net.Listener) net.Listener {
	return netutil.LimitListener(ln, maxConns)
}
