// Package fakeauthn is a go-authn provider as far as this server can see
// one, for tests: discovery, a key set, a token endpoint for the gateway's
// own client, and the signed list of WireGuard peers. It signs what a test
// asks it to, so that the code under test is judged on what it accepts.
package fakeauthn

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/go-authn/wireguard"
)

// The gateway's credentials at the fake provider.
const (
	GatewayID     = "claimward-gw"
	GatewaySecret = "a-gateway-secret"
	Audience      = "claimward"
)

// Provider is a running fake issuer.
type Provider struct {
	t   *testing.T
	srv *httptest.Server
	key *rsa.PrivateKey

	mu   sync.Mutex
	list wireguard.List

	// The SSF transmitter, poll delivery.
	streams  int      // created
	events   []string // jtis waiting
	Acked    []string // jtis the receiver acknowledged
	PollSeen int
}

// New starts one, closed when the test ends.
func New(t *testing.T) *Provider {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &Provider{t: t, key: k}
	mux := http.NewServeMux()
	p.srv = httptest.NewServer(mux)
	t.Cleanup(p.srv.Close)
	iss := p.srv.URL
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"issuer": iss, "jwks_uri": iss + "/jwks", "token_endpoint": iss + "/token"})
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, r *http.Request) {
		b64 := base64.RawURLEncoding.EncodeToString
		json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{
			"kty": "RSA", "kid": "k1", "alg": "RS256", "use": "sig",
			"n": b64(k.N.Bytes()), "e": b64(big.NewInt(int64(k.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		id, secret, _ := r.BasicAuth()
		scope := r.FormValue("scope")
		if id != GatewayID || secret != GatewaySecret || (scope != wireguard.ScopePeers && scope != "ssf") {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]any{"error": "invalid_client"})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"access_token": "gateway-token", "token_type": "Bearer", "expires_in": 300})
	})
	mux.HandleFunc("GET /.well-known/ssf-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"issuer": iss, "configuration_endpoint": iss + "/ssf/streams", "delivery_methods_supported": []string{"urn:ietf:rfc:8936"}})
	})
	stream := func() map[string]any {
		return map[string]any{"stream_id": "s1", "delivery": map[string]any{"method": "urn:ietf:rfc:8936", "endpoint_url": iss + "/ssf/poll"}}
	}
	mux.HandleFunc("/ssf/streams", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer gateway-token" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		p.mu.Lock()
		defer p.mu.Unlock()
		switch r.Method {
		case http.MethodGet:
			out := []any{}
			if p.streams > 0 {
				out = append(out, stream())
			}
			json.NewEncoder(w).Encode(out)
		case http.MethodPost:
			p.streams++
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(stream())
		}
	})
	mux.HandleFunc("POST /ssf/poll", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer gateway-token" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		var req struct {
			Ack []string `json:"ack"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		p.mu.Lock()
		defer p.mu.Unlock()
		p.PollSeen++
		p.Acked = append(p.Acked, req.Ack...)
		sets := map[string]string{}
		for _, j := range p.events {
			sets[j] = "a.set.jwt"
		}
		p.events = nil
		json.NewEncoder(w).Encode(map[string]any{"sets": sets})
	})
	mux.HandleFunc("GET "+wireguard.ListPath, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer gateway-token" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		p.mu.Lock()
		l := p.list
		p.mu.Unlock()
		now := time.Now()
		l.IssuedAt, l.Expires = now, now.Add(5*time.Minute)
		w.Write([]byte(p.Sign(wireguard.ListType, l.Claims(iss, GatewayID))))
	})
	return p
}

// Event queues a Shared Signals event for the receiver's next poll.
func (p *Provider) Event(jti string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.events = append(p.events, jti)
}

// Streams is how many streams the receiver created.
func (p *Provider) Streams() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.streams
}

// Issuer is the provider's issuer URL.
func (p *Provider) Issuer() string { return p.srv.URL }

// SetPeers is what the list says from now on, at a version.
func (p *Provider) SetPeers(version uint64, peers ...wireguard.Peer) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.list = wireguard.List{Version: version, Peers: peers}
}

// Sign makes a JWS of claims with typ.
func (p *Provider) Sign(typ string, claims map[string]any) string {
	p.t.Helper()
	enc := func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			p.t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}
	signed := enc(map[string]any{"alg": "RS256", "kid": "k1", "typ": typ}) + "." + enc(claims)
	sum := sha256.Sum256([]byte(signed))
	sig, err := rsa.SignPKCS1v15(rand.Reader, p.key, crypto.SHA256, sum[:])
	if err != nil {
		p.t.Fatal(err)
	}
	return signed + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// AccessToken is an access token for sub, as go-authn/bridge issues one to
// the claimward client after a refresh for "openid".
func (p *Provider) AccessToken(sub, username string, extra map[string]any) string {
	now := time.Now()
	c := map[string]any{
		"iss": p.srv.URL, "aud": Audience, "sub": sub, "client_id": Audience,
		"preferred_username": username, "scope": "openid",
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "jti": sub + "-jti",
	}
	for k, v := range extra {
		c[k] = v
	}
	return p.Sign("at+jwt", c)
}
