// Package ssfpoll listens to a go-authn provider's Shared Signals (SSF 1.0,
// poll delivery, RFC 8936) for one thing: that somebody was disabled, so the
// list of WireGuard keys should be fetched NOW rather than at the next tick.
//
// ⛔ An event here is a trigger, never a decision. What may connect is
// decided by the signed list alone (internal/peers); an event only makes it
// be read sooner. So the events are not verified: a forged one buys an
// extra fetch of a list that is verified, and nothing else.
package ssfpoll

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	deliveryPoll   = "urn:ietf:rfc:8936"
	sessionRevoked = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
	wellKnown      = "/.well-known/ssf-configuration"
)

// Config is the provider, and the gateway's own client there: a confidential
// client that is an SSF receiver (ssf_receiver = true in go-authn/bridge).
type Config struct {
	Issuer, ClientID, ClientSecret string
	Interval                       time.Duration
	Client                         *http.Client
}

// Poller polls one stream and kicks on every event.
type Poller struct {
	cfg  Config
	kick chan<- struct{}
	log  *slog.Logger

	tokenURL string
	token    string
	tokenEnd time.Time
	pollURL  string
	acks     []string
}

// New is a poller that sends on kick when an event arrives. kick should be
// buffered: a kick already pending is enough.
func New(cfg Config, kick chan<- struct{}, log *slog.Logger) *Poller {
	if cfg.Client == nil {
		cfg.Client = &http.Client{Timeout: 30 * time.Second}
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 5 * time.Second
	}
	cfg.Issuer = strings.TrimRight(cfg.Issuer, "/")
	return &Poller{cfg: cfg, kick: kick, log: log}
}

// Run polls until ctx ends. Errors are logged and retried: the list keeps
// being fetched on its own clock whatever happens here.
func (p *Poller) Run(ctx context.Context) {
	t := time.NewTicker(p.cfg.Interval)
	defer t.Stop()
	for {
		if err := p.Once(ctx); err != nil {
			p.log.Warn("go-authn SSF poll", "err", err)
			p.pollURL = "" // set up again next time: the stream may be gone
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Once sets the stream up if need be, and polls it once.
func (p *Poller) Once(ctx context.Context) error {
	if p.pollURL == "" {
		if err := p.setup(ctx); err != nil {
			return err
		}
	}
	max := 50
	body := map[string]any{"maxEvents": max, "returnImmediately": true}
	if len(p.acks) > 0 {
		body["ack"] = p.acks
	}
	var out struct {
		Sets map[string]string `json:"sets"`
	}
	if err := p.call(ctx, http.MethodPost, p.pollURL, body, &out); err != nil {
		return err
	}
	p.acks = p.acks[:0]
	for jti := range out.Sets {
		p.acks = append(p.acks, jti)
	}
	if len(out.Sets) > 0 {
		p.log.Info("go-authn SSF: an event; fetching the key list now", "events", len(out.Sets))
		select {
		case p.kick <- struct{}{}:
		default: // one already pending
		}
	}
	return nil
}

// setup finds this receiver's poll stream, or creates one. One is reused
// rather than one made per start: a provider bounds the streams a receiver
// may hold.
func (p *Poller) setup(ctx context.Context) error {
	var meta struct {
		ConfigurationEndpoint string `json:"configuration_endpoint"`
	}
	if err := p.get(ctx, p.cfg.Issuer+wellKnown, &meta); err != nil {
		return err
	}
	if meta.ConfigurationEndpoint == "" {
		return errors.New("the provider publishes no SSF configuration endpoint")
	}
	var raw json.RawMessage
	if err := p.call(ctx, http.MethodGet, meta.ConfigurationEndpoint, nil, &raw); err != nil {
		return err
	}
	type stream struct {
		Delivery struct {
			Method      string `json:"method"`
			EndpointURL string `json:"endpoint_url"`
		} `json:"delivery"`
	}
	var streams []stream
	if err := json.Unmarshal(raw, &streams); err != nil {
		var one stream
		if json.Unmarshal(raw, &one) == nil && one.Delivery.Method != "" {
			streams = []stream{one}
		}
	}
	for _, s := range streams {
		if s.Delivery.Method == deliveryPoll && s.Delivery.EndpointURL != "" {
			p.pollURL = s.Delivery.EndpointURL
			return nil
		}
	}
	var created stream
	req := map[string]any{"delivery": map[string]any{"method": deliveryPoll}, "events_requested": []string{sessionRevoked}}
	if err := p.call(ctx, http.MethodPost, meta.ConfigurationEndpoint, req, &created); err != nil {
		return err
	}
	if created.Delivery.EndpointURL == "" {
		return errors.New("the provider created a stream with no poll endpoint")
	}
	p.pollURL = created.Delivery.EndpointURL
	return nil
}

// get is an unauthenticated GET of a JSON document.
func (p *Poller) get(ctx context.Context, u string, out any) error {
	if err := protected(u); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	res, err := p.cfg.Client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", u, res.Status)
	}
	return json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(out)
}

// protected refuses a URL the receiver's secret or token would cross in the
// clear; loopback has no link to listen on.
func protected(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme == "http" {
		if h := u.Hostname(); h == "localhost" || h == "127.0.0.1" || h == "::1" {
			return nil
		}
	}
	return fmt.Errorf("%q is not https", raw)
}

// call sends a request with the receiver's token, and decodes the answer.
func (p *Poller) call(ctx context.Context, method, u string, in, out any) error {
	if err := protected(u); err != nil {
		return err
	}
	tok, err := p.bearer(ctx)
	if err != nil {
		return err
	}
	var body io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := p.cfg.Client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(res.Body, 1<<10))
		if res.StatusCode == http.StatusUnauthorized {
			p.token = "" // a token the provider no longer honours
		}
		return fmt.Errorf("%s %s: %s %s", method, u, res.Status, strings.TrimSpace(string(msg)))
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(io.LimitReader(res.Body, 4<<20)).Decode(out)
}

// bearer is the receiver's own token, client credentials, scope ssf.
func (p *Poller) bearer(ctx context.Context) (string, error) {
	if p.token != "" && time.Until(p.tokenEnd) > 30*time.Second {
		return p.token, nil
	}
	if p.tokenURL == "" {
		var meta struct {
			TokenEndpoint string `json:"token_endpoint"`
		}
		if err := p.get(ctx, p.cfg.Issuer+"/.well-known/openid-configuration", &meta); err != nil {
			return "", err
		}
		if err := protected(meta.TokenEndpoint); err != nil {
			return "", fmt.Errorf("the token endpoint: %w", err)
		}
		p.tokenURL = meta.TokenEndpoint
	}
	form := url.Values{"grant_type": {"client_credentials"}, "scope": {"ssf"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(p.cfg.ClientID), url.QueryEscape(p.cfg.ClientSecret))
	res, err := p.cfg.Client.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		Error       string `json:"error"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&out); err != nil || out.AccessToken == "" {
		return "", fmt.Errorf("no SSF token for the gateway (%s): %q %v", res.Status, out.Error, err)
	}
	p.token = out.AccessToken
	p.tokenEnd = time.Now().Add(time.Duration(out.ExpiresIn) * time.Second)
	return p.token, nil
}
