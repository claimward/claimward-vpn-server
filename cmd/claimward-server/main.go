// Command claimward-server is the Claimward VPN control plane.
//
// It verifies OIDC ID tokens, allocates VPN addresses, and programs the local
// WireGuard gateway (wg0) with one peer per enrolled device. It is designed to
// run co-located on the Linux gateway host.
//
// Required environment:
//
//	OIDC_ISSUER      OIDC issuer URL (discovery)
//	OIDC_CLIENT_ID   expected token audience
//	WG_ENDPOINT      public host:port of the WireGuard gateway
//	WG_PRIVATE_KEY   base64 server private key (or WG_PRIVATE_KEY_FILE)
//
// See internal/config for the full list. Set WG_DRYRUN=true to run without a
// real WireGuard device (local development).
package main

import (
	"context"
	"errors"
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
	"github.com/claimward/claimward-vpn-server/internal/mailer"
	"github.com/claimward/claimward-vpn-server/internal/metrics"
	"github.com/claimward/claimward-vpn-server/internal/settings"
	"github.com/claimward/claimward-vpn-server/internal/store"
	"github.com/claimward/claimward-vpn-server/internal/tenant"
	"github.com/claimward/claimward-vpn-server/internal/wg"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc"
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

	alloc, err := ipam.NewManager(cfg.VPNCIDR)
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
	ts := tenant.New(cfg.TenantsFile, cfg.PushRoutes, cfg.DNS)
	m := metrics.New(st, ts)
	srv := api.New(cfg, verifier, alloc, st, gw, ts, m, serverPub, log)

	// gRPC RouteService: streams per-tenant route pushes to clients.
	grpcLn, err := net.Listen("tcp", cfg.GRPCAddr)
	if err != nil {
		return err
	}
	gs := grpc.NewServer(grpc.StreamInterceptor(grpcsrv.AuthStreamInterceptor(verifier)))
	routespb.RegisterRouteServiceServer(gs, grpcsrv.New(ts, st))
	go gs.Serve(grpcLn) //nolint:errcheck
	go func() {
		<-ctx.Done()
		gs.GracefulStop()
	}()
	log.Info("gRPC RouteService listening", "addr", cfg.GRPCAddr, "advertised", cfg.GRPCEndpoint)

	// Periodically reap expired leases.
	go reaper(ctx, srv, log)

	// Root mux: API (catch-all) + Prometheus metrics + admin UI/API.
	root := http.NewServeMux()
	root.Handle("/", srv.Handler())
	root.Handle("GET /metrics", m.Handler())
	settingsStore := settings.New(cfg.SettingsFile, settings.Settings{
		MailFrom:      cfg.MailFrom,
		SMTPAddr:      cfg.SMTPAddr,
		InviteSubject: mailer.DefaultSubject,
		InviteBody:    mailer.DefaultBody,
	})
	ml := mailer.New(func() mailer.Settings {
		s := settingsStore.Get()
		return mailer.Settings{SMTPAddr: s.SMTPAddr, From: s.MailFrom, Subject: s.InviteSubject, Body: s.InviteBody}
	}, cfg.PortalURL, log)
	adminSrv := admin.New(ts, st, cfg.AdminToken, adminui.FS(), ml, settingsStore, log)
	adminSrv.Register(root)
	log.Info("admin UI", "enabled", adminSrv.Enabled(), "path", "/admin/", "invite_email", ml.Enabled())

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
