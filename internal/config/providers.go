package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/claimward/claimward-vpn-client/pkg/protocol"
	"github.com/claimward/claimward-vpn-server/internal/creds"
)

// Provider is one identity provider the server accepts, from PROVIDERS_FILE.
//
// The file holds public parameters and admission rules only; each secret is a
// credential file named after the provider's id (creds.ProviderSecret,
// creds.ProviderGatewaySecret), read into the fields tagged `json:"-"`.
type Provider struct {
	// ID is stable and url-safe: clients send it in the Claimward-Provider
	// header, and tenants name groups with it. Renaming it changes tenant
	// group rules, never an identity (see internal/auth).
	ID string `json:"id"`
	// Kind is "github", "oidc" or "go-authn".
	Kind string `json:"kind"`
	// Name is what a client shows on its sign-in choice.
	Name string `json:"name"`

	// github: Claimward's OAuth app (public client ID; the secret is the
	// credential file provider-<id>-secret), the API base URL (empty =
	// https://api.github.com, set for GitHub Enterprise) and the organisations
	// whose members are admitted.
	GitHubClientID string   `json:"github_client_id,omitempty"`
	APIURL         string   `json:"api_url,omitempty"`
	AllowedOrgs    []string `json:"allowed_orgs,omitempty"`

	// oidc and go-authn: the issuer and the token audience; oidc also takes an
	// email-domain allowlist.
	OIDCIssuer     string   `json:"oidc_issuer,omitempty"`
	OIDCClientID   string   `json:"oidc_client_id,omitempty"`
	AllowedDomains []string `json:"allowed_domains,omitempty"`

	// go-authn: the gateway's own client at the provider, which reads the list
	// of registered WireGuard keys (secret: provider-<id>-gateway-secret).
	GatewayClientID string `json:"gateway_client_id,omitempty"`

	ClientSecret  string `json:"-"` // github: the OAuth app's client secret
	GatewaySecret string `json:"-"` // go-authn: the gateway client's secret
}

// Public is what the unauthenticated discovery document says of the provider,
// built field by field: never the whole struct, which holds secrets.
func (p Provider) Public() protocol.Provider {
	out := protocol.Provider{ID: p.ID, Kind: p.Kind, Name: p.Name}
	if p.Kind == protocol.KindGitHub {
		out.GitHubClientID = p.GitHubClientID
	} else {
		out.OIDCIssuer, out.OIDCClientID = p.OIDCIssuer, p.OIDCClientID
	}
	return out
}

// maxProvidersFile bounds PROVIDERS_FILE.
const maxProvidersFile = 1 << 20

// providerID is an id a header, a file name and a tenant rule can all carry.
var providerID = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$`)

// removedProviderEnv are the variables that configured the single provider
// before v0.14.0.
var removedProviderEnv = []string{
	"AUTH_PROVIDER", "OIDC_ISSUER", "OIDC_CLIENT_ID", "OIDC_ALLOWED_DOMAINS",
	"GITHUB_CLIENT_ID", "GITHUB_ALLOWED_ORGS", "GOAUTHN_GATEWAY_CLIENT_ID",
}

// refuseRemovedProviderEnv stops the start when a single-provider variable is
// set: a server accepts a list of providers now, from PROVIDERS_FILE, and no
// mapping is silently guessed.
func refuseRemovedProviderEnv() error {
	var set []string
	for _, k := range removedProviderEnv {
		if os.Getenv(k) != "" {
			set = append(set, k)
		}
	}
	if len(set) == 0 {
		return nil
	}
	return fmt.Errorf("claimward-server v0.14.0 accepts several identity providers, listed in the JSON file PROVIDERS_FILE; %s no longer read: unset %s and describe the provider(s) there, with each secret in the credential file provider-<id>-secret (github) or provider-<id>-gateway-secret (go-authn) (see deploy/README.md)",
		plural(set), strings.Join(set, ", "))
}

func plural(set []string) string {
	if len(set) == 1 {
		return set[0] + " is"
	}
	return "these are"
}

// loadProviders reads and validates PROVIDERS_FILE, then each provider's
// secrets from the credentials directory dir.
func loadProviders(path, dir string) ([]Provider, error) {
	if path == "" {
		return nil, errors.New("missing required config: PROVIDERS_FILE (a JSON file listing the identity providers this server accepts; see deploy/README.md)")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("PROVIDERS_FILE: %w", err)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxProvidersFile+1))
	if err != nil {
		return nil, fmt.Errorf("PROVIDERS_FILE %s: %w", path, err)
	}
	if len(b) > maxProvidersFile {
		return nil, fmt.Errorf("PROVIDERS_FILE %s is larger than %d bytes", path, maxProvidersFile)
	}
	return parseProviders(b, dir)
}

func parseProviders(b []byte, dir string) ([]Provider, error) {
	var doc struct {
		Providers []Provider `json:"providers"`
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields() // a misspelt rule must not read as "no rule"
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("PROVIDERS_FILE: %w", err)
	}
	if dec.More() {
		return nil, errors.New("PROVIDERS_FILE: trailing data after the JSON document")
	}
	if len(doc.Providers) == 0 {
		return nil, errors.New("PROVIDERS_FILE lists no provider: with none nobody could sign in")
	}
	ids := map[string]bool{}
	issuers := map[string]string{}
	goauthn := ""
	for i := range doc.Providers {
		p := &doc.Providers[i]
		if !providerID.MatchString(p.ID) {
			return nil, fmt.Errorf("PROVIDERS_FILE: provider %d: id %q must be 1 to 32 characters of a-z, 0-9 and '-', not starting or ending with '-'", i+1, p.ID)
		}
		if ids[p.ID] {
			return nil, fmt.Errorf("PROVIDERS_FILE: provider id %q is listed twice", p.ID)
		}
		ids[p.ID] = true
		if err := checkDisplayName("name of provider "+p.ID, p.Name); err != nil {
			return nil, err
		}
		if p.Name == "" {
			return nil, fmt.Errorf("PROVIDERS_FILE: provider %q has no name (what a client shows on its sign-in choice)", p.ID)
		}
		switch p.Kind {
		case protocol.KindGitHub:
			if err := p.forbid("oidc_issuer", p.OIDCIssuer, "oidc_client_id", p.OIDCClientID, "gateway_client_id", p.GatewayClientID); err != nil {
				return nil, err
			}
			if len(p.AllowedDomains) > 0 {
				return nil, fmt.Errorf("PROVIDERS_FILE: provider %q (github) cannot have allowed_domains: use allowed_orgs", p.ID)
			}
			if p.GitHubClientID == "" {
				return nil, fmt.Errorf("PROVIDERS_FILE: provider %q (github) needs github_client_id", p.ID)
			}
			p.AllowedOrgs = cleanList(p.AllowedOrgs)
			// ⛔ Our own OAuth app only: a token minted by any other app a member
			// authorised would enrol a peer. No secret file, no start.
			s, err := creds.Read(dir, creds.ProviderSecret(p.ID))
			if err != nil {
				return nil, fmt.Errorf("required credential (provider %q, the OAuth app's client secret): %w", p.ID, err)
			}
			p.ClientSecret = s
		case protocol.KindOIDC, protocol.KindGoAuthn:
			if err := p.forbid("github_client_id", p.GitHubClientID, "api_url", p.APIURL); err != nil {
				return nil, err
			}
			if len(p.AllowedOrgs) > 0 {
				return nil, fmt.Errorf("PROVIDERS_FILE: provider %q (%s) cannot have allowed_orgs: that is a github rule", p.ID, p.Kind)
			}
			if p.OIDCIssuer == "" || p.OIDCClientID == "" {
				return nil, fmt.Errorf("PROVIDERS_FILE: provider %q (%s) needs oidc_issuer and oidc_client_id", p.ID, p.Kind)
			}
			p.AllowedDomains = cleanList(p.AllowedDomains)
			// One issuer, one provider: two entries for it would be two ids for
			// one set of people, with two sets of admission rules.
			if other, dup := issuers[p.OIDCIssuer]; dup {
				return nil, fmt.Errorf("PROVIDERS_FILE: providers %q and %q have the same oidc_issuer %q", other, p.ID, p.OIDCIssuer)
			}
			issuers[p.OIDCIssuer] = p.ID
			if p.Kind == protocol.KindGoAuthn {
				if len(p.AllowedDomains) > 0 {
					return nil, fmt.Errorf("PROVIDERS_FILE: provider %q (go-authn) cannot have allowed_domains", p.ID)
				}
				// The registry of WireGuard keys is the gateway's alone.
				if goauthn != "" {
					return nil, fmt.Errorf("PROVIDERS_FILE: providers %q and %q are both go-authn: a server reads ONE list of registered keys", goauthn, p.ID)
				}
				goauthn = p.ID
				if p.GatewayClientID == "" {
					return nil, fmt.Errorf("PROVIDERS_FILE: provider %q (go-authn) needs gateway_client_id", p.ID)
				}
				s, err := creds.Read(dir, creds.ProviderGatewaySecret(p.ID))
				if err != nil {
					return nil, fmt.Errorf("required credential (provider %q, go-authn): %w", p.ID, err)
				}
				p.GatewaySecret = s
			} else if p.GatewayClientID != "" {
				return nil, fmt.Errorf("PROVIDERS_FILE: provider %q (oidc) cannot have gateway_client_id: that is go-authn's", p.ID)
			}
		default:
			return nil, fmt.Errorf("PROVIDERS_FILE: provider %q: kind %q must be \"github\", \"oidc\" or \"go-authn\"", p.ID, p.Kind)
		}
	}
	return doc.Providers, nil
}

// forbid refuses a field that does not belong to the provider's kind.
func (p Provider) forbid(kv ...string) error {
	for i := 0; i < len(kv); i += 2 {
		if kv[i+1] != "" {
			return fmt.Errorf("PROVIDERS_FILE: provider %q (%s) cannot have %s", p.ID, p.Kind, kv[i])
		}
	}
	return nil
}

func cleanList(l []string) []string {
	var out []string
	for _, s := range l {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// checkDisplayName refuses what a client could not show: control characters, or
// more than maxServerName characters.
func checkDisplayName(what, v string) error {
	if utf8.RuneCountInString(v) > maxServerName {
		return fmt.Errorf("PROVIDERS_FILE: the %s is longer than %d characters", what, maxServerName)
	}
	for _, r := range v {
		if unicode.IsControl(r) {
			return fmt.Errorf("PROVIDERS_FILE: the %s holds a control character", what)
		}
	}
	return nil
}
