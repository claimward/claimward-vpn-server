package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// maxResolveBody caps what is read of a /users/{login} answer.
const maxResolveBody = 64 << 10

// NewGitHubResolver returns a tenant.Resolver that pins a login to the
// account's numeric ID with GET {apiURL}/users/{login} (empty apiURL =
// https://api.github.com). Bounded: 10 s per call, 64 KiB of answer. Anything
// but a User account whose login is the one asked for is an error.
//
// token is the github-token credential, sent as a bearer (an anonymous caller
// has 60 requests an hour). It is REQUIRED: with an empty token every call
// fails, naming the credential file, so a tenant with members stops the start
// when the token is missing. It is never sent over plain HTTP except to a
// loopback address.
func NewGitHubResolver(apiURL, token string) func(ctx context.Context, login string) (int64, error) {
	if apiURL == "" {
		apiURL = "https://api.github.com"
	}
	apiURL = strings.TrimRight(apiURL, "/")
	client := &http.Client{Timeout: 10 * time.Second}
	return func(ctx context.Context, login string) (int64, error) {
		if token == "" {
			return 0, fmt.Errorf("tenant member %q needs the github-token credential: create $CREDENTIALS_DIRECTORY/github-token (a GitHub token with no scope, read access to public data suffices)", login)
		}
		if u, err := url.Parse(apiURL); err != nil || (u.Scheme != "https" && !isLoopback(u.Hostname())) {
			return 0, fmt.Errorf("GITHUB_API_URL %q: the github-token is only sent over https (or to loopback)", apiURL)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL+"/users/"+url.PathEscape(login), nil)
		if err != nil {
			return 0, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
		resp, err := client.Do(req)
		if err != nil {
			return 0, err
		}
		defer resp.Body.Close()
		if resp.StatusCode/100 != 2 {
			return 0, fmt.Errorf("GitHub user %q: HTTP %d", login, resp.StatusCode)
		}
		var u struct {
			ID    int64  `json:"id"`
			Login string `json:"login"`
			Type  string `json:"type"`
		}
		// A body that does not decode leaves u zero (json.Decoder fills nothing
		// from an incomplete value), and the checks below refuse a zero u.
		_ = json.NewDecoder(io.LimitReader(resp.Body, maxResolveBody)).Decode(&u)
		if u.Type != "User" {
			return 0, fmt.Errorf("GitHub account %q is not a user (%q)", login, u.Type)
		}
		if u.ID <= 0 || !strings.EqualFold(u.Login, login) {
			return 0, fmt.Errorf("GitHub user %q: unexpected answer", login)
		}
		return u.ID, nil
	}
}
