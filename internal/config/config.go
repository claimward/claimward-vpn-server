// Package config loads claimward-vpn-server configuration from the environment.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is the fully-resolved server configuration.
type Config struct {
	ListenAddr string // e.g. ":8443"
	TLSCert    string // optional; if set with TLSKey, server serves HTTPS
	TLSKey     string

	// MetricsAddr is where /metrics is served, on its own listener: it names
	// every tenant. Loopback by default.
	MetricsAddr string

	GRPCAddr     string // RouteService gRPC listen address, e.g. ":8444"
	GRPCEndpoint string // host:port advertised to clients for route streaming

	AdminToken string // bearer for the admin WebUI/API; empty disables admin

	AuthProvider string // "github" (default), "oidc" or "go-authn"

	OIDCIssuer     string   // required when AuthProvider is "oidc" or "go-authn"
	OIDCClientID   string   // required when AuthProvider is "oidc" or "go-authn" (token audience)
	AllowedDomains []string // optional email-domain allowlist for authz (oidc)

	// go-authn: the gateway's own client at the provider, which reads the
	// list of registered WireGuard keys. The secret is read from a file
	// only: an environment is copied into every child and every crash dump.
	GatewayClientID  string
	GatewaySecret    string        // filled from GOAUTHN_GATEWAY_SECRET_FILE
	PeerListInterval time.Duration // how often the list is fetched
	// SSF makes the gateway also listen to the provider's Shared Signals,
	// so that a disabling is acted on at once rather than at the next fetch.
	// The gateway's client must be an SSF receiver at the provider.
	SSF         bool
	SSFInterval time.Duration

	GitHubAPIURL      string   // default https://api.github.com (set for GHE)
	GitHubAllowedOrgs []string // org-membership allowlist (github); required with the github provider
	WGInterface       string   // kernel interface managed via wgctrl, e.g. "wg0"
	WGEndpoint        string   // public host:port advertised to clients (required)
	WGPrivateKey      string   // base64 server private key (or use WGPrivateKeyFile)
	WGServerPrivKey   string   // resolved private key (internal, filled by Load)
	DryRun            bool     // if true, don't touch a real device — log peer ops

	VPNCIDR    string   // pool, e.g. "10.80.0.0/24"; server takes the first host
	PushRoutes []string // AllowedIPs pushed to clients; defaults to [VPNCIDR]
	// TenantsFile is a JSON file of tenants with their access policies
	// (see internal/tenant ParseFile). Tenant "default" overrides PUSH_ROUTES.
	TenantsFile string
	DNS         []string      // optional DNS servers pushed to clients
	Keepalive   int           // persistent keepalive seconds advertised to clients
	LeaseTTL    time.Duration // how long an enrollment lasts without a heartbeat

	// MaxDevicesPerSubject caps the devices one identity may have enrolled.
	MaxDevicesPerSubject int
}

// Load reads configuration from the environment and validates required fields.
func Load() (*Config, error) {
	c := &Config{
		ListenAddr:           env("LISTEN_ADDR", ":8443"),
		TLSCert:              os.Getenv("TLS_CERT"),
		TLSKey:               os.Getenv("TLS_KEY"),
		GRPCAddr:             env("GRPC_ADDR", ":8444"),
		MetricsAddr:          env("METRICS_ADDR", "127.0.0.1:9090"),
		GRPCEndpoint:         os.Getenv("GRPC_ENDPOINT"),
		AdminToken:           os.Getenv("ADMIN_TOKEN"),
		AuthProvider:         env("AUTH_PROVIDER", "github"),
		OIDCIssuer:           os.Getenv("OIDC_ISSUER"),
		OIDCClientID:         os.Getenv("OIDC_CLIENT_ID"),
		AllowedDomains:       splitCSV(os.Getenv("OIDC_ALLOWED_DOMAINS")),
		GitHubAPIURL:         os.Getenv("GITHUB_API_URL"),
		GitHubAllowedOrgs:    splitCSV(os.Getenv("GITHUB_ALLOWED_ORGS")),
		WGInterface:          env("WG_INTERFACE", "wg0"),
		WGEndpoint:           os.Getenv("WG_ENDPOINT"),
		WGPrivateKey:         os.Getenv("WG_PRIVATE_KEY"),
		DryRun:               boolEnv("WG_DRYRUN", false),
		VPNCIDR:              env("VPN_CIDR", "10.80.0.0/24"),
		PushRoutes:           splitCSV(os.Getenv("PUSH_ROUTES")),
		TenantsFile:          os.Getenv("TENANTS_FILE"),
		DNS:                  splitCSV(os.Getenv("DNS")),
		Keepalive:            intEnv("KEEPALIVE", 25),
		LeaseTTL:             durEnv("LEASE_TTL", 24*time.Hour),
		MaxDevicesPerSubject: intEnv("MAX_DEVICES_PER_SUBJECT", 5),
		GatewayClientID:      os.Getenv("GOAUTHN_GATEWAY_CLIENT_ID"),
		PeerListInterval:     durEnv("GOAUTHN_PEER_LIST_INTERVAL", 30*time.Second),
		SSF:                  boolEnv("GOAUTHN_SSF", false),
		SSFInterval:          durEnv("GOAUTHN_SSF_INTERVAL", 5*time.Second),
	}

	if file := os.Getenv("WG_PRIVATE_KEY_FILE"); file != "" && c.WGPrivateKey == "" {
		b, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("read WG_PRIVATE_KEY_FILE: %w", err)
		}
		c.WGPrivateKey = strings.TrimSpace(string(b))
	}
	if len(c.PushRoutes) == 0 {
		c.PushRoutes = []string{c.VPNCIDR}
	}

	required := map[string]string{
		"WG_ENDPOINT":    c.WGEndpoint,
		"WG_PRIVATE_KEY": c.WGPrivateKey,
	}
	switch c.AuthProvider {
	case "github":
		// ⛔ Fail closed, with no escape hatch: with neither an org allowlist
		// nor tenants naming members EVERY GitHub account would be let in. The
		// allowlist is optional only when tenants have members, which Load
		// cannot see: the server checks it after seeding the tenants.
	case "oidc":
		required["OIDC_ISSUER"] = c.OIDCIssuer
		required["OIDC_CLIENT_ID"] = c.OIDCClientID
	case "go-authn":
		required["OIDC_ISSUER"] = c.OIDCIssuer
		required["OIDC_CLIENT_ID"] = c.OIDCClientID
		required["GOAUTHN_GATEWAY_CLIENT_ID"] = c.GatewayClientID
		file := os.Getenv("GOAUTHN_GATEWAY_SECRET_FILE")
		required["GOAUTHN_GATEWAY_SECRET_FILE"] = file
		if file != "" {
			b, err := os.ReadFile(file)
			if err != nil {
				return nil, fmt.Errorf("read GOAUTHN_GATEWAY_SECRET_FILE: %w", err)
			}
			c.GatewaySecret = strings.TrimSpace(string(b))
			if c.GatewaySecret == "" {
				return nil, fmt.Errorf("GOAUTHN_GATEWAY_SECRET_FILE %s is empty", file)
			}
		}
		if c.PeerListInterval <= 0 {
			return nil, fmt.Errorf("GOAUTHN_PEER_LIST_INTERVAL must be positive")
		}
	default:
		return nil, fmt.Errorf("invalid AUTH_PROVIDER %q (want \"github\", \"oidc\" or \"go-authn\")", c.AuthProvider)
	}

	if c.MaxDevicesPerSubject <= 0 {
		return nil, fmt.Errorf("MAX_DEVICES_PER_SUBJECT must be positive")
	}

	var missing []string
	for k, v := range required {
		if v == "" {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("missing required config: %s", strings.Join(missing, ", "))
	}
	return c, nil
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func boolEnv(key string, def bool) bool {
	if v := os.Getenv(key); v != "" {
		b, err := strconv.ParseBool(v)
		if err == nil {
			return b
		}
	}
	return def
}

func intEnv(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func durEnv(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}
