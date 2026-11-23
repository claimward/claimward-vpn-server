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
//	OIDC_ISSUER      OIDC issuer URL         (AUTH_PROVIDER=oidc or go-authn)
//	OIDC_CLIENT_ID   expected token audience (AUTH_PROVIDER=oidc or go-authn)
//	GOAUTHN_GATEWAY_CLIENT_ID
//	                 the gateway's own client, which reads the list of
//	                 registered keys          (AUTH_PROVIDER=go-authn)
//
// Secrets are files in $CREDENTIALS_DIRECTORY, never environment variables:
//
//	wg-private-key           base64 server private key (always)
//	admin-token              enables the admin API/WebUI (optional)
//	goauthn-gateway-secret   the gateway client's secret (AUTH_PROVIDER=go-authn)
//	github-token             required when a tenant names members
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
		return errors.New("the wg-private-key credential is not a valid WireGuard key")
	}
	serverPub := priv.PublicKey().String()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	ts := tenant.New(cfg.PushRoutes, cfg.DNS)
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
	// Leases are held in memory: the peers a previous run left on the
	// device are nobody's now, and would outlive any revocation.
	_, pool, err := net.ParseCIDR(cfg.VPNCIDR)
	if err != nil {
		return err
	}
	if n, err := wg.Sweep(gw, pool); err != nil {
		return fmt.Errorf("remove the peers a previous run left on %s: %w", cfg.WGInterface, err)
	} else if n > 0 {
		log.Warn("removed peers a previous run left; their devices enroll again", "interface", cfg.WGInterface, "peers", n)
	}

	if err := applyTunnelMTU(cfg, wg.UplinkMTU, wg.SetInterfaceMTU, log); err != nil {
		return err
	}

	st := store.New()
	// Named members are pinned to their GitHub numeric IDs as the tenants are
	// loaded; an unresolvable login stops the start.
	ts.SetResolver(auth.NewGitHubResolver(cfg.GitHubAPIURL, cfg.GitHubToken))
	if err := loadTenants(ts, cfg.TenantsFile, log); err != nil {
		return err
	}
	if err := checkEntryGate(cfg, ts); err != nil {
		return err
	}
	if gv, ok := verifier.(*auth.GitHubVerifier); ok {
		gv.WithMembers(ts)
	}

	// ⛔ Fail closed: what each peer may reach is ENFORCED here, by the
	// kernel's nftables, before any peer can be enrolled. If the ruleset
	// cannot be installed the server does not start.
	fwm, err := startFirewall(cfg.WGInterface, cfg.TunnelMTU, newApplier(cfg.DryRun, log), ts, st, log)
	if err != nil {
		return err
	}

	m := metrics.New(st, ts)
	srv := api.New(cfg, verifier, alloc, st, gw, ts, m, serverPub, log)
	srv.UseFirewall(fwm.Sync)

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
	opts = append(opts, grpcLimits()...)
	grpcLn = limitConns(grpcLn)
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
	// ⛔ /metrics is NOT on this public mux: it names every tenant. It has
	// its own listener, loopback by default (METRICS_ADDR).
	adminSrv := admin.New(ts, st, cfg.AdminToken, adminui.FS(), log)
	adminSrv.Register(root)
	log.Info("admin UI", "enabled", adminSrv.Enabled(), "path", "/admin/")

	httpSrv := newHTTPServer(cfg.ListenAddr, root)

	metricsSrv := newHTTPServer(cfg.MetricsAddr, metricsMux(m))
	metricsLn, err := net.Listen("tcp", cfg.MetricsAddr)
	if err != nil {
		return err
	}
	go metricsSrv.Serve(limitConns(metricsLn)) //nolint:errcheck
	log.Info("metrics listening", "addr", metricsLn.Addr().String())

	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutCtx)
		_ = metricsSrv.Shutdown(shutCtx)
	}()

	log.Info("claimward-server listening",
		"addr", cfg.ListenAddr, "interface", cfg.WGInterface,
		"endpoint", cfg.WGEndpoint, "vpn_cidr", cfg.VPNCIDR,
		"auth", cfg.AuthProvider, "server_pubkey", serverPub, "dry_run", cfg.DryRun)

	if cfg.TLSCert != "" && cfg.TLSKey != "" {
		err = serveLimited(httpSrv, cfg.TLSCert, cfg.TLSKey)
	} else {
		log.Warn("serving plain HTTP — terminate TLS at a proxy or set TLS_CERT/TLS_KEY in production")
		err = serveLimited(httpSrv, "", "")
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
