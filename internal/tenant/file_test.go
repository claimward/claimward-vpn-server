package tenant

import (
	"reflect"
	"strings"
	"testing"

	"github.com/claimward/claimward-vpn-server/internal/policy"
)

const file = `[
 {"id":"default","policy":[{"cidr":"10.20.0.5/32","proto":"tcp","ports":[445,88]},{"cidr":"10.20.0.5/32","proto":"udp","ports":[88]}]},
 {"id":"chem","groups":["chem"],"allowed_ips":["10.1.0.0/16"]}
]`

func TestParseFileDerivesRoutesFromPolicy(t *testing.T) {
	ts, err := ParseFile([]byte(file))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := ts[0].AllowedIPs, []string{"10.20.0.5/32"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("routes = %v, want %v", got, want)
	}
	// Legacy: routes only, every protocol.
	if r := ts[1].Rules(); len(r) != 1 || r[0].Proto != "any" {
		t.Fatalf("legacy rules = %+v", r)
	}
}

func TestPolicyOverridesAllowedIPs(t *testing.T) {
	s := New([]string{"10.0.0.0/8"}, nil)
	ts, _ := ParseFile([]byte(file))
	if err := s.Seed(ts[0]); err != nil {
		t.Fatal(err)
	}
	if got := s.Routes(DefaultID).AllowedIPs; !reflect.DeepEqual(got, []string{"10.20.0.5/32"}) {
		t.Fatalf("pushed routes = %v", got)
	}
}

func TestOnChange(t *testing.T) {
	s := New(nil, nil)
	n := 0
	s.SetOnChange(func() { n++ })
	s.Create(Tenant{ID: "x"})
	s.Update("x", Tenant{})
	s.Delete("x")
	if n != 3 {
		t.Fatalf("callback ran %d times, want 3", n)
	}
	if _, err := s.Update("nope", Tenant{}); err == nil || n != 3 {
		t.Fatal("a failed update must not fire the callback")
	}
}

func TestParseFileRefuses(t *testing.T) {
	for name, in := range map[string]string{
		"bad policy": `[{"id":"a","policy":[{"cidr":"10.0.0.1/32","proto":"tcp"}]}]`,
		"unknown":    `[{"id":"a","polcy":[]}]`,
		"trailing":   `[] x`,
	} {
		if _, err := ParseFile([]byte(in)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestParseFileBounds(t *testing.T) {
	if _, err := ParseFile([]byte("[" + strings.Repeat(" ", maxFileBytes) + "]")); err == nil {
		t.Error("a file over the size limit was parsed")
	}
	many := "[" + strings.Repeat(`{"id":"a"},`, maxFileTenants) + `{"id":"a"}]`
	if _, err := ParseFile([]byte(many)); err == nil {
		t.Error("a file over the tenant limit was parsed")
	}
	if ts, err := ParseFile([]byte(`[{"id":"a"}]`)); err != nil || len(ts) != 1 {
		t.Errorf("%v %v", ts, err)
	}
}

func TestRulesAreThePolicyWhenThereIsOne(t *testing.T) {
	ts, _ := ParseFile([]byte(file))
	if got := ts[0].Rules(); !reflect.DeepEqual(got, ts[0].Policy) || got[0].Proto != "tcp" {
		t.Fatalf("rules = %+v", got)
	}
	if got := (Tenant{}).Rules(); len(got) != 0 {
		t.Fatalf("a tenant with neither reaches %+v", got)
	}
}

func TestSeed(t *testing.T) {
	s := New([]string{"10.0.0.0/8"}, []string{"10.0.0.53"})
	ts, _ := ParseFile([]byte(file))
	// Replacing the default tenant keeps its identity and bumps the serial.
	if err := s.Seed(ts[0]); err != nil {
		t.Fatal(err)
	}
	d, _ := s.Get(DefaultID)
	if d.Serial != 2 || len(d.Policy) != 2 || d.DNS != nil {
		t.Fatalf("default = %+v", d)
	}
	// A new tenant starts at serial 1; its ID can come from its name.
	if err := s.Seed(Tenant{Name: "Chimie Fine"}); err != nil {
		t.Fatal(err)
	}
	if c, ok := s.Get("chimie-fine"); !ok || c.Serial != 1 {
		t.Fatalf("seeded = %+v %v", c, ok)
	}
	if err := s.Seed(Tenant{}); err == nil {
		t.Error("a tenant with no id or name was seeded")
	}
	bad := Tenant{ID: "bad", Policy: []policy.Rule{{CIDR: "10.0.0.1/32", Proto: "tcp"}}}
	if err := s.Seed(bad); err == nil {
		t.Error("an invalid policy was seeded")
	}
	if _, ok := s.Get("bad"); ok {
		t.Error("an invalid tenant was stored")
	}
	if _, err := s.Create(bad); err == nil {
		t.Error("an invalid policy was created")
	}
	if _, err := s.Update(DefaultID, bad); err == nil {
		t.Error("an invalid policy was updated")
	}
}

func FuzzParseFile(f *testing.F) {
	f.Add([]byte(file))
	f.Add([]byte(`[]`))
	f.Fuzz(func(t *testing.T, data []byte) {
		ts, err := ParseFile(data)
		if err != nil {
			return
		}
		s := New(nil, nil)
		for _, x := range ts {
			// A parsed file can always be loaded, or is refused cleanly.
			_ = s.Seed(x)
		}
	})
}
