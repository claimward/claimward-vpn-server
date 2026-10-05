package tenant

import "testing"

func store(t *testing.T) *Store {
	t.Helper()
	s := New([]string{"10.80.0.0/24"}, nil)
	for _, in := range []Tenant{
		{ID: "chem", Name: "Chemistry", Domains: []string{"chem.univ-a.fr"}, AllowedIPs: []string{"10.1.0.0/16"}},
		{ID: "hpc", Name: "HPC", Groups: []string{"urn:mace:univ-a.fr:hpc"}, AllowedIPs: []string{"10.2.0.0/16"}},
		{ID: "univ-b", Name: "Univ B", IdPs: []string{"https://idp.univ-b.fr/idp/shibboleth"}, AllowedIPs: []string{"10.3.0.0/16"}},
	} {
		if _, err := s.Create(in); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func ids(ts []Tenant) []string {
	var out []string
	for _, t := range ts {
		out = append(out, t.ID)
	}
	return out
}

func eq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// A person may belong to several tenants, by any of the three rules, and to
// the default one only when they match none.
func TestMembership(t *testing.T) {
	s := store(t)
	for name, tc := range map[string]struct {
		m    Member
		want []string
	}{
		"a verified address":             {Member{Email: "a@chem.univ-a.fr", EmailVerified: true}, []string{"chem"}},
		"the same domain, any case":      {Member{Email: "a@CHEM.univ-a.fr", EmailVerified: true}, []string{"chem"}},
		"an address nobody verified":     {Member{Email: "a@chem.univ-a.fr"}, []string{"default"}},
		"a group":                        {Member{Groups: []string{"urn:mace:univ-a.fr:hpc"}}, []string{"hpc"}},
		"an institution":                 {Member{IdP: "https://idp.univ-b.fr/idp/shibboleth"}, []string{"univ-b"}},
		"all three at once":              {Member{Email: "a@chem.univ-a.fr", EmailVerified: true, Groups: []string{"x", "urn:mace:univ-a.fr:hpc"}, IdP: "https://idp.univ-b.fr/idp/shibboleth"}, []string{"chem", "hpc", "univ-b"}},
		"nothing that matches":           {Member{Email: "a@elsewhere.org", EmailVerified: true, Groups: []string{"other"}}, []string{"default"}},
		"a group that only resembles":    {Member{Groups: []string{"urn:mace:univ-a.fr:hpc-staff"}}, []string{"default"}},
		"an institution that resembles":  {Member{IdP: "https://idp.univ-b.fr/idp/shibboleth/"}, []string{"default"}},
		"a domain that merely ends alike": {Member{Email: "a@xchem.univ-a.fr", EmailVerified: true}, []string{"default"}},
	} {
		if got := ids(s.For(tc.m)); !eq(got, tc.want) {
			t.Errorf("%s: %v, want %v", name, got, tc.want)
		}
	}
	m := Member{Groups: []string{"urn:mace:univ-a.fr:hpc"}}
	if !s.IsMember("hpc", m) || s.IsMember("chem", m) || s.IsMember("default", m) {
		t.Error("IsMember disagrees with For")
	}
}

// Updating a tenant's rules changes who belongs, at once.
func TestUpdateChangesMembership(t *testing.T) {
	s := store(t)
	m := Member{Groups: []string{"urn:mace:univ-a.fr:hpc"}}
	if _, err := s.Update("hpc", Tenant{Name: "HPC", Groups: []string{"urn:mace:univ-a.fr:hpc-new"}, AllowedIPs: []string{"10.2.0.0/16"}}); err != nil {
		t.Fatal(err)
	}
	if s.IsMember("hpc", m) {
		t.Error("a group taken off the tenant still belongs")
	}
	if _, err := s.Update("nope", Tenant{}); err == nil {
		t.Error("an unknown tenant was updated")
	}
	got, _ := s.Get("hpc")
	if got.Serial != 2 || !eq(got.Groups, []string{"urn:mace:univ-a.fr:hpc-new"}) {
		t.Errorf("after update: %+v", got)
	}
}
