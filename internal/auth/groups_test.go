package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
)

// GitHub organisations are the person's groups.
func TestGitHubOrganisationsAreGroups(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /user", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"id": 42, "login": "carol", "email": "carol@univ-a.fr"})
	})
	mux.HandleFunc("GET /user/orgs", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]map[string]any{{"login": "univ-a-hpc"}, {"login": "chem-lab"}})
	})
	api := httptest.NewServer(mux)
	defer api.Close()
	c, err := NewGitHubVerifier(api.URL, nil).Verify(context.Background(), "token")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(c.Groups, []string{"univ-a-hpc", "chem-lab"}) || c.Subject != "github:42" {
		t.Errorf("claims: %+v", c)
	}

	// The organisations cannot be listed: refused, not a person with none.
	mux2 := http.NewServeMux()
	mux2.HandleFunc("GET /user", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"id": 42, "login": "carol"})
	})
	mux2.HandleFunc("GET /user/orgs", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusForbidden) })
	api2 := httptest.NewServer(mux2)
	defer api2.Close()
	if _, err := NewGitHubVerifier(api2.URL, nil).Verify(context.Background(), "token"); err == nil {
		t.Error("a person whose organisations could not be read was let in")
	}
}

// A "groups" claim is a list, or -- from some providers -- one string.
func TestAGroupsClaimIsAListOrAString(t *testing.T) {
	for _, tc := range []struct {
		in   any
		want []string
	}{
		{[]any{"a", "b", 3, ""}, []string{"a", "b"}},
		{"solo", []string{"solo"}},
		{"", nil},
		{nil, nil},
		{map[string]any{}, nil},
	} {
		if got := stringList(tc.in); !slices.Equal(got, tc.want) {
			t.Errorf("%v: %v, want %v", tc.in, got, tc.want)
		}
	}
}
