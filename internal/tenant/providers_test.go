package tenant

import (
	"strings"
	"testing"
)

// ⛔ With several providers, a tenant matching on a domain or an institution
// that does not say which providers may vouch for it is refused: a provider
// that lets people type any address must not join them to a tenant a stricter
// provider guards.
func TestSeveralProvidersFailClosed(t *testing.T) {
	for name, tc := range map[string]struct {
		in   Tenant
		want string // "" = accepted
	}{
		"domains, no providers":       {Tenant{ID: "a", Domains: []string{"example.org"}}, "must name its \"providers\""},
		"idps, no providers":          {Tenant{ID: "a", IdPs: []string{"https://idp.example"}}, "must name its \"providers\""},
		"domains, naming providers":   {Tenant{ID: "a", Domains: []string{"example.org"}, Providers: []string{"campus"}}, ""},
		"idps, naming providers":      {Tenant{ID: "a", IdPs: []string{"https://idp.example"}, Providers: []string{"fed"}}, ""},
		"an unknown provider":         {Tenant{ID: "a", Domains: []string{"example.org"}, Providers: []string{"nope"}}, "not a configured provider"},
		"a scoped group":              {Tenant{ID: "a", Groups: []string{"campus:hpc"}}, ""},
		"a group with no provider":    {Tenant{ID: "a", Groups: []string{"hpc"}}, "<provider id>:<group>"},
		"a group of unknown provider": {Tenant{ID: "a", Groups: []string{"nope:hpc"}}, "<provider id>:<group>"},
	} {
		s := New([]string{"10.80.0.0/24"}, nil)
		s.SetProviders([]string{"hub", "campus", "fed"})
		_, err := s.Create(tc.in)
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: refused: %v", name, err)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%s: err = %v, want one containing %q", name, err, tc.want)
		}
	}
}

// With ONE provider the tenant need not say which: there is nobody else.
func TestOneProviderNeedsNoScoping(t *testing.T) {
	s := New([]string{"10.80.0.0/24"}, nil)
	s.SetProviders([]string{"campus"})
	if _, err := s.Create(Tenant{ID: "a", Domains: []string{"example.org"}}); err != nil {
		t.Errorf("one provider: %v", err)
	}
}

// A domain or institution counts only when the member's provider is one of the
// tenant's providers; a group is already scoped by its prefix.
func TestProviderScopesWhoBelongs(t *testing.T) {
	s := New([]string{"10.80.0.0/24"}, nil)
	s.SetProviders([]string{"hub", "campus", "fed"})
	for _, in := range []Tenant{
		{ID: "chem", Domains: []string{"example.org"}, Providers: []string{"campus"}},
		{ID: "univ", IdPs: []string{"https://idp.example"}, Providers: []string{"fed"}},
		{ID: "hpc", Groups: []string{"campus:hpc"}},
	} {
		if _, err := s.Create(in); err != nil {
			t.Fatal(err)
		}
	}
	for name, tc := range map[string]struct {
		m    Member
		want []string
	}{
		"the named provider's domain":         {Member{Provider: "campus", Email: "a@example.org", EmailVerified: true}, []string{"chem"}},
		"the same domain at another provider": {Member{Provider: "hub", Email: "a@example.org", EmailVerified: true}, nil},
		"no provider at all":                  {Member{Email: "a@example.org", EmailVerified: true}, nil},
		"the named provider's idp":            {Member{Provider: "fed", IdP: "https://idp.example"}, []string{"univ"}},
		"the same idp at another provider":    {Member{Provider: "campus", IdP: "https://idp.example"}, nil},
		"a group of the named provider":       {Member{Provider: "campus", Groups: []string{"campus:hpc"}}, []string{"hpc"}},
		"a group of another provider":         {Member{Provider: "hub", Groups: []string{"hub:hpc"}}, nil},
	} {
		if got := ids(s.For(tc.m)); !eq(got, tc.want) {
			t.Errorf("%s: %v, want %v", name, got, tc.want)
		}
	}
}
