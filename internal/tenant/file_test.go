package tenant

import (
	"reflect"
	"testing"
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
