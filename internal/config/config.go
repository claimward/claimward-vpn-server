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

	OIDCIssuer     string   // required
	OIDCClientID   string   // required (token audience)
	AllowedDomains []string // optional email-domain allowlist for authz

	WGInterface     string // kernel interface managed via wgctrl, e.g. "wg0"
	WGEndpoint      string // public host:port advertised to clients (required)
	WGPrivateKey    string // base64 server private key (or use WGPrivateKeyFile)
	WGServerPrivKey string // resolved private key (internal, filled by Load)
	DryRun          bool   // if true, don't touch a real device — log peer ops

	VPNCIDR    string        // pool, e.g. "10.80.0.0/24"; server takes the first host
	PushRoutes []string      // AllowedIPs pushed to clients; defaults to [VPNCIDR]
	DNS        []string      // optional DNS servers pushed to clients
	Keepalive  int           // persistent keepalive seconds advertised to clients
	LeaseTTL   time.Duration // how long an enrollment lasts without a heartbeat
}

// Load reads configuration from the environment and validates required fields.
func Load() (*Config, error) {
	c := &Config{
		ListenAddr:     env("LISTEN_ADDR", ":8443"),
		TLSCert:        os.Getenv("TLS_CERT"),
		TLSKey:         os.Getenv("TLS_KEY"),
		OIDCIssuer:     os.Getenv("OIDC_ISSUER"),
		OIDCClientID:   os.Getenv("OIDC_CLIENT_ID"),
		AllowedDomains: splitCSV(os.Getenv("OIDC_ALLOWED_DOMAINS")),
		WGInterface:    env("WG_INTERFACE", "wg0"),
		WGEndpoint:     os.Getenv("WG_ENDPOINT"),
		WGPrivateKey:   os.Getenv("WG_PRIVATE_KEY"),
		DryRun:         boolEnv("WG_DRYRUN", false),
		VPNCIDR:        env("VPN_CIDR", "10.80.0.0/24"),
		PushRoutes:     splitCSV(os.Getenv("PUSH_ROUTES")),
		DNS:            splitCSV(os.Getenv("DNS")),
		Keepalive:      intEnv("KEEPALIVE", 25),
		LeaseTTL:       durEnv("LEASE_TTL", 24*time.Hour),
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

	var missing []string
	for k, v := range map[string]string{
		"OIDC_ISSUER":    c.OIDCIssuer,
		"OIDC_CLIENT_ID": c.OIDCClientID,
		"WG_ENDPOINT":    c.WGEndpoint,
		"WG_PRIVATE_KEY": c.WGPrivateKey,
	} {
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
