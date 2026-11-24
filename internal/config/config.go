// Package config loads claimward-vpn-server configuration from the environment
// and, for secrets, from the credentials directory ($CREDENTIALS_DIRECTORY).
package config

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/claimward/claimward-vpn-server/internal/creds"
)

// Config is the fully-resolved server configuration.
type Config struct {
	ListenAddr string // e.g. ":8443"
	TLSCert    string // optional; if set with TLSKey, server serves HTTPS
	TLSKey     string

	// MetricsAddr is where /metrics is served, on its own listener: it names
	// every tenant. Empty (the default) means no metrics at all: there is no
	// default port to clash with another service.
	MetricsAddr string

	GRPCAddr     string // RouteService gRPC listen address, e.g. ":8444"
	GRPCEndpoint string // host:port advertised to clients for route streaming

	// AdminToken is the bearer for the admin WebUI/API, from the credential
	// file admin-token; with no such file the admin API is disabled.
	AdminToken string
	// GitHubToken is the credential file github-token: the bearer for
	// GET /users/{login}, which pins a tenant member's login to an ID. Optional
	// here; the server refuses to start without it when a tenant has members.
	GitHubToken string

	AuthProvider string // "github" (default), "oidc" or "go-authn"

	OIDCIssuer     string   // required when AuthProvider is "oidc" or "go-authn"
	OIDCClientID   string   // required when AuthProvider is "oidc" or "go-authn" (token audience)
	AllowedDomains []string // optional email-domain allowlist for authz (oidc)

	// go-authn: the gateway's own client at the provider, which reads the
	// list of registered WireGuard keys. The secret is read from a file
	// only: an environment is copied into every child and every crash dump.
	GatewayClientID  string
	GatewaySecret    string        // credential file goauthn-gateway-secret
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
	WGPrivateKey      string   // base64 server private key, credential file wg-private-key
	DryRun            bool     // if true, don't touch a real device — log peer ops

	VPNCIDR    string   // pool, e.g. "10.80.0.0/24"; server takes the first host
	PushRoutes []string // AllowedIPs pushed to clients; defaults to [VPNCIDR]
	// TenantsFile is a JSON file of tenants with their access policies
	// (see internal/tenant ParseFile). Tenant "default" overrides PUSH_ROUTES.
	TenantsFile string
	DNS         []string // optional DNS servers pushed to clients
	Keepalive   int      // persistent keepalive seconds advertised to clients
	// TunnelMTU is the MTU of the gateway's WireGuard interface, advertised
	// to clients as `mtu`. TUNNEL_MTU, 0 = derive it from the uplink's MTU
	// (see AutoTunnelMTU); main fills in the derived value.
	TunnelMTU int
	LeaseTTL  time.Duration // how long an enrollment lasts without a heartbeat

	// MaxDevicesPerSubject caps the devices one identity may have enrolled.
	MaxDevicesPerSubject int
}

// Load reads configuration from the environment and validates required fields.
func Load() (*Config, error) {
	if err := refuseRemovedEnv(); err != nil {
		return nil, err
	}
	c := &Config{
		ListenAddr:           env("LISTEN_ADDR", ":8443"),
		TLSCert:              os.Getenv("TLS_CERT"),
		TLSKey:               os.Getenv("TLS_KEY"),
		GRPCAddr:             env("GRPC_ADDR", ":8444"),
		MetricsAddr:          os.Getenv("METRICS_ADDR"),
		GRPCEndpoint:         os.Getenv("GRPC_ENDPOINT"),
		AuthProvider:         env("AUTH_PROVIDER", "github"),
		OIDCIssuer:           os.Getenv("OIDC_ISSUER"),
		OIDCClientID:         os.Getenv("OIDC_CLIENT_ID"),
		AllowedDomains:       splitCSV(os.Getenv("OIDC_ALLOWED_DOMAINS")),
		GitHubAPIURL:         os.Getenv("GITHUB_API_URL"),
		GitHubAllowedOrgs:    splitCSV(os.Getenv("GITHUB_ALLOWED_ORGS")),
		WGInterface:          env("WG_INTERFACE", "wg0"),
		WGEndpoint:           os.Getenv("WG_ENDPOINT"),
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

	// Secrets come from the credentials directory and nowhere else.
	dir := os.Getenv(creds.EnvDir)
	var err error
	if c.WGPrivateKey, err = creds.Read(dir, creds.WGPrivateKey); err != nil {
		return nil, fmt.Errorf("required credential: %w", err)
	}
	// admin-token: the admin API is enabled by the file; no file, no admin.
	if c.AdminToken, err = optional(dir, creds.AdminToken); err != nil {
		return nil, err
	}
	// github-token: optional here; main refuses to start without it when a
	// tenant names members (the resolver needs it), which Load cannot see.
	if c.GitHubToken, err = optional(dir, creds.GitHubToken); err != nil {
		return nil, err
	}
	if len(c.PushRoutes) == 0 {
		c.PushRoutes = []string{c.VPNCIDR}
	}

	required := map[string]string{
		"WG_ENDPOINT": c.WGEndpoint,
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
		if c.GatewaySecret, err = creds.Read(dir, creds.GoAuthnGatewaySecret); err != nil {
			return nil, fmt.Errorf("required credential (AUTH_PROVIDER=go-authn): %w", err)
		}
		if c.PeerListInterval <= 0 {
			return nil, fmt.Errorf("GOAUTHN_PEER_LIST_INTERVAL must be positive")
		}
	default:
		return nil, fmt.Errorf("invalid AUTH_PROVIDER %q (want \"github\", \"oidc\" or \"go-authn\")", c.AuthProvider)
	}

	mtu, err := ParseTunnelMTU(os.Getenv("TUNNEL_MTU"))
	if err != nil {
		return nil, err
	}
	c.TunnelMTU = mtu

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

// Gateway is the part of the configuration that the privileged parent of a
// privilege-separated server needs: where the tunnel is and which addresses
// its peers may have. It is read from the same variables, with the same
// defaults, as Load; and it reads no credential: the parent holds no secret.
type Gateway struct {
	Interface string
	Pool      netip.Prefix
	DryRun    bool
}

// LoadGateway reads WG_INTERFACE, VPN_CIDR and WG_DRYRUN.
func LoadGateway() (Gateway, error) {
	g := Gateway{Interface: env("WG_INTERFACE", "wg0"), DryRun: boolEnv("WG_DRYRUN", false)}
	cidr := env("VPN_CIDR", "10.80.0.0/24")
	p, err := netip.ParsePrefix(cidr)
	if err != nil || !p.Addr().Is4() {
		return Gateway{}, fmt.Errorf("invalid VPN_CIDR %q: want an IPv4 prefix such as 10.80.0.0/24", cidr)
	}
	g.Pool = p.Masked()
	return g, nil
}

// optional reads a credential that may be absent; one that is present but
// unsafe is still an error.
func optional(dir, name string) (string, error) {
	v, err := creds.Read(dir, name)
	if errors.Is(err, creds.ErrNotFound) {
		return "", nil
	}
	return v, err
}

// removedEnv maps each variable that used to carry a secret, or name its file,
// to the credential file that replaces it.
var removedEnv = []struct{ env, file string }{
	{"ADMIN_TOKEN", creds.AdminToken},
	{"WG_PRIVATE_KEY", creds.WGPrivateKey},
	{"WG_PRIVATE_KEY_FILE", creds.WGPrivateKey},
	{"GOAUTHN_GATEWAY_SECRET_FILE", creds.GoAuthnGatewaySecret},
}

// refuseRemovedEnv stops the start when a removed variable is set (non-empty):
// no fallback, so a secret cannot go on travelling in the environment unseen.
func refuseRemovedEnv() error {
	var msgs []string
	for _, r := range removedEnv {
		if os.Getenv(r.env) != "" {
			msgs = append(msgs, fmt.Sprintf("%s is no longer read: unset it and create the credential file %s/%s instead (the file's content is the secret)",
				r.env, creds.EnvDir, r.file))
		}
	}
	if len(msgs) == 0 {
		return nil
	}
	return fmt.Errorf("claimward-server v0.6.0 takes every secret from the credentials directory $%s, never from the environment (see deploy/README.md): %s",
		creds.EnvDir, strings.Join(msgs, "; "))
}

// Tunnel MTU bounds. 1280 is IPv6's minimum link MTU; 1420 is WireGuard's
// default, the most a 1500-byte IPv4 path carries; 9000 is a jumbo frame.
const (
	MinTunnelMTU     = 1280
	DefaultTunnelMTU = 1420
	MaxTunnelMTU     = 9000
)

// ParseTunnelMTU reads TUNNEL_MTU: empty is 0 (derive it), anything else must
// be a whole number within [MinTunnelMTU, MaxTunnelMTU]. A value that does
// not parse or is out of range is refused at start, never replaced by a
// default: an MTU that does not fit the path stalls TCP silently.
func ParseTunnelMTU(s string) (int, error) {
	if s == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("invalid TUNNEL_MTU %q: want a whole number of bytes", s)
	}
	if n < MinTunnelMTU || n > MaxTunnelMTU {
		return 0, fmt.Errorf("invalid TUNNEL_MTU %d: want %d to %d", n, MinTunnelMTU, MaxTunnelMTU)
	}
	return n, nil
}

// AutoTunnelMTU is the tunnel MTU to use when TUNNEL_MTU is unset: the
// uplink's MTU minus 80 (WireGuard over an IPv6 underlay, which also covers
// IPv4's 60), capped at DefaultTunnelMTU and floored at MinTunnelMTU. An
// unknown uplink (0) gives DefaultTunnelMTU.
func AutoTunnelMTU(uplinkMTU int) int {
	if uplinkMTU <= 0 {
		return DefaultTunnelMTU
	}
	return min(DefaultTunnelMTU, max(uplinkMTU-80, MinTunnelMTU))
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
