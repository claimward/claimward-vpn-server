package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// maxResolveBody caps what is read of a /users/{login} answer.
const maxResolveBody = 64 << 10

// NewGitHubResolver returns a tenant.Resolver that pins a login to the
// account's numeric ID with GET {apiURL}/users/{login} (empty apiURL =
// https://api.github.com). Bounded: 10 s per call, 64 KiB of answer. Anything
// but a User account whose login is the one asked for is an error.
func NewGitHubResolver(apiURL string) func(ctx context.Context, login string) (int64, error) {
	if apiURL == "" {
		apiURL = "https://api.github.com"
	}
	apiURL = strings.TrimRight(apiURL, "/")
	client := &http.Client{Timeout: 10 * time.Second}
	return func(ctx context.Context, login string) (int64, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL+"/users/"+url.PathEscape(login), nil)
		if err != nil {
			return 0, err
		}
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
		if err := json.NewDecoder(io.LimitReader(resp.Body, maxResolveBody)).Decode(&u); err != nil {
			return 0, fmt.Errorf("GitHub user %q: %w", login, err)
		}
		if u.Type != "User" {
			return 0, fmt.Errorf("GitHub account %q is not a user (%q)", login, u.Type)
		}
		if u.ID <= 0 || !strings.EqualFold(u.Login, login) {
			return 0, fmt.Errorf("GitHub user %q: unexpected answer", login)
		}
		return u.ID, nil
	}
}
