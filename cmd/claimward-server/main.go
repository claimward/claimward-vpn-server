// Command claimward-server is the Claimward VPN control plane.
//
// It authenticates enrolling devices against a pluggable identity provider —
// GitHub by default, any OIDC issuer, or a go-authn provider, where each
// device's WireGuard key is registered by its owner — allocates VPN addresses, and programs
// the local WireGuard gateway (wg0) with one peer per enrolled device. It is
// designed to run co-located on the Linux gateway host.
//
// Alongside the enrollment API it serves a gRPC RouteService (per-tenant route
// pushes), an optional token-guarded admin API + WebUI, and Prometheus metrics.
//
// Required environment:
//
//	WG_ENDPOINT      public host:port of the WireGuard gateway
//	WG_PRIVATE_KEY   base64 server private key (or WG_PRIVATE_KEY_FILE)
//	OIDC_ISSUER      OIDC issuer URL         (AUTH_PROVIDER=oidc or go-authn)
//	OIDC_CLIENT_ID   expected token audience (AUTH_PROVIDER=oidc or go-authn)
//	GOAUTHN_GATEWAY_CLIENT_ID, GOAUTHN_GATEWAY_SECRET_FILE
//	                 the gateway's own client, which reads the list of
//	                 registered keys          (AUTH_PROVIDER=go-authn)
//
// See internal/config for the full list. Set WG_DRYRUN=true to run without a
// real WireGuard device (local development).
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/claimward/claimward-vpn-client/pkg/routespb"
	"github.com/claimward/claimward-vpn-server/internal/admin"
	"github.com/claimward/claimward-vpn-server/internal/adminui"
	"github.com/claimward/claimward-vpn-server/internal/api"
	"github.com/claimward/claimward-vpn-server/internal/auth"
	"github.com/claimward/claimward-vpn-server/internal/config"
	"github.com/claimward/claimward-vpn-server/internal/grpcsrv"
	"github.com/claimward/claimward-vpn-server/internal/ipam"
	"github.com/claimward/claimward-vpn-server/internal/metrics"
	"github.com/claimward/claimward-vpn-server/internal/peers"
	"github.com/claimward/claimward-vpn-server/internal/ssfpoll"
	"github.com/claimward/claimward-vpn-server/internal/store"
	"github.com/claimward/claimward-vpn-server/internal/tenant"
	"github.com/claimward/claimward-vpn-server/internal/wg"
	"github.com/go-authn/wireguard"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel()}))
	if err := run(log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	priv, err := wgtypes.ParseKey(cfg.WGPrivateKey)
	if err != nil {
		return errors.New("WG_PRIVATE_KEY is not a valid WireGuard key")
	}
	serverPub := priv.PublicKey().String()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	verifier, err := auth.New(ctx, auth.Options{
		Provider:          cfg.AuthProvider,
		Issuer:            cfg.OIDCIssuer,
		ClientID:          cfg.OIDCClientID,
		AllowedDomains:    cfg.AllowedDomains,
		GitHubAPIURL:      cfg.GitHubAPIURL,
		GitHubAllowedOrgs: cfg.GitHubAllowedOrgs,
	})
	if err != nil {
		return err
	}

	alloc, err := ipam.New(cfg.VPNCIDR)
	if err != nil {
		return err
	}

	var gw wg.Gateway
	if cfg.DryRun {
		log.Warn("WG_DRYRUN enabled: gateway operations are logged, not applied")
		gw = wg.NewDryRunGateway(log)
	} else {
		gw, err = wg.NewGateway(cfg.WGInterface)
		if err != nil {
			return err
		}
	}
	defer gw.Close()

	st := store.New()
	ts := tenant.New(cfg.PushRoutes, cfg.DNS)
	m := metrics.New(st, ts)
	srv := api.New(cfg, verifier, alloc, st, gw, ts, m, serverPub, log)

	// go-authn: a device's key must be one its owner registered with the
	// provider, and a key the provider takes back is dropped here.
	if cfg.AuthProvider == "go-authn" {
		src, err := wireguard.NewSource(ctx, wireguard.SourceConfig{
			Issuer: cfg.OIDCIssuer, ClientID: cfg.GatewayClientID, ClientSecret: cfg.GatewaySecret,
		})
		if err != nil {
			return err
		}
		reg := peers.New(src)
		// The first list before listening: a gateway that cannot read it
		// admits nobody, and should say so now rather than at the first
		// enrollment.
		if _, err := reg.Refresh(ctx); err != nil {
			return err
		}
		srv.UsePeers(reg)
		// An SSF event -- somebody disabled -- fetches the list now; the
		// list alone decides what it means.
		kick := make(chan struct{}, 1)
		if cfg.SSF {
			go ssfpoll.New(ssfpoll.Config{
				Issuer: cfg.OIDCIssuer, ClientID: cfg.GatewayClientID, ClientSecret: cfg.GatewaySecret,
				Interval: cfg.SSFInterval,
			}, kick, log).Run(ctx)
		}
		go reg.Run(ctx, cfg.PeerListInterval, kick, func(*wireguard.List) { srv.Reconcile(reg.Allowed) }, log)
		log.Info("go-authn WireGuard registry", "issuer", cfg.OIDCIssuer, "gateway_client", cfg.GatewayClientID, "interval", cfg.PeerListInterval)
	}

	// gRPC RouteService: streams per-tenant route pushes to clients.
	grpcLn, err := net.Listen("tcp", cfg.GRPCAddr)
	if err != nil {
		return err
	}
	opts, secure, err := grpcOptions(cfg.TLSCert, cfg.TLSKey)
	if err != nil {
		return err
	}
	if !secure {
		log.Warn("gRPC RouteService without TLS: clients send their bearer token in it, and refuse to except on loopback -- set TLS_CERT/TLS_KEY")
	}
	gs := grpc.NewServer(append(opts, grpc.StreamInterceptor(grpcsrv.AuthStreamInterceptor(verifier)))...)
	routespb.RegisterRouteServiceServer(gs, grpcsrv.New(ts, st))
	go gs.Serve(grpcLn) //nolint:errcheck
	go func() {
		<-ctx.Done()
		gs.GracefulStop()
	}()
	log.Info("gRPC RouteService listening", "addr", cfg.GRPCAddr, "advertised", cfg.GRPCEndpoint)

	// Periodically reap expired leases.
	go reaper(ctx, srv, log)

	// Root mux: enrollment API (catch-all) + Prometheus metrics + admin UI/API.
	root := http.NewServeMux()
	root.Handle("/", srv.Handler())
	root.Handle("GET /metrics", m.Handler())
	adminSrv := admin.New(ts, st, cfg.AdminToken, adminui.FS(), log)
	adminSrv.Register(root)
	log.Info("admin UI", "enabled", adminSrv.Enabled(), "path", "/admin/")

	httpSrv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           root,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutCtx)
	}()

	log.Info("claimward-server listening",
		"addr", cfg.ListenAddr, "interface", cfg.WGInterface,
		"endpoint", cfg.WGEndpoint, "vpn_cidr", cfg.VPNCIDR,
		"auth", cfg.AuthProvider, "server_pubkey", serverPub, "dry_run", cfg.DryRun)

	if cfg.TLSCert != "" && cfg.TLSKey != "" {
		err = httpSrv.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey)
	} else {
		log.Warn("serving plain HTTP — terminate TLS at a proxy or set TLS_CERT/TLS_KEY in production")
		err = httpSrv.ListenAndServe()
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func reaper(ctx context.Context, srv *api.Server, log *slog.Logger) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			srv.ReapExpired()
		}
	}
}

func logLevel() slog.Level {
	if os.Getenv("DEBUG") != "" {
		return slog.LevelDebug
	}
	return slog.LevelInfo
}

// grpcOptions serves the RouteService over TLS when the server has a
// certificate. A watch carries the person's bearer token in its metadata,
// and claimward clients refuse a plaintext watch except on loopback.
func grpcOptions(certFile, keyFile string) ([]grpc.ServerOption, bool, error) {
	if certFile == "" || keyFile == "" {
		return nil, false, nil
	}
	creds, err := credentials.NewServerTLSFromFile(certFile, keyFile)
	if err != nil {
		return nil, false, fmt.Errorf("gRPC TLS: %w", err)
	}
	return []grpc.ServerOption{grpc.Creds(creds)}, true, nil
}
