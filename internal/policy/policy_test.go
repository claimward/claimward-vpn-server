package policy

import (
	"reflect"
	"strings"
	"testing"
)

const mesocentre = `[
 {"cidr":"10.20.0.5/32","proto":"tcp","ports":[445]},
 {"cidr":"10.20.0.5/32","proto":"tcp","ports":[88]},
 {"cidr":"10.20.0.5/32","proto":"udp","ports":["88"]},
 {"cidr":"10.30.0.0/24","proto":"tcp","ports":["8000-8100", 443]}
]`

func TestParseMesocentre(t *testing.T) {
	rules, err := Parse([]byte(mesocentre))
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 4 {
		t.Fatalf("got %d rules", len(rules))
	}
	if got := rules[3].Ports; !reflect.DeepEqual(got, []Port{{8000, 8100}, {443, 443}}) {
		t.Fatalf("ports = %v", got)
	}
	// Routes derive from the policy: each CIDR once, in order.
	if got, want := Routes(rules), []string{"10.20.0.5/32", "10.30.0.0/24"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("routes = %v, want %v", got, want)
	}
}

func TestParseRefuses(t *testing.T) {
	for name, in := range map[string]string{
		"empty proto":      `[{"cidr":"10.0.0.1/32","ports":[1]}]`,
		"any proto":        `[{"cidr":"10.0.0.1/32","proto":"any","ports":[1]}]`,
		"icmp":             `[{"cidr":"10.0.0.1/32","proto":"icmp","ports":[1]}]`,
		"no ports":         `[{"cidr":"10.0.0.1/32","proto":"tcp"}]`,
		"port 0":           `[{"cidr":"10.0.0.1/32","proto":"tcp","ports":[0]}]`,
		"port 65536":       `[{"cidr":"10.0.0.1/32","proto":"tcp","ports":[65536]}]`,
		"backwards range":  `[{"cidr":"10.0.0.1/32","proto":"tcp","ports":["9-1"]}]`,
		"negative":         `[{"cidr":"10.0.0.1/32","proto":"tcp","ports":[-5]}]`,
		"ipv6":             `[{"cidr":"fd00::/8","proto":"tcp","ports":[1]}]`,
		"bad cidr":         `[{"cidr":"10.0.0.1","proto":"tcp","ports":[1]}]`,
		"unknown field":    `[{"cidr":"10.0.0.1/32","proto":"tcp","ports":[1],"allow":true}]`,
		"trailing":         `[] []`,
		"not an array":     `{}`,
		"float port":       `[{"cidr":"10.0.0.1/32","proto":"tcp","ports":[1.5]}]`,
		"too many ports":   `[{"cidr":"10.0.0.1/32","proto":"tcp","ports":[` + strings.Repeat("1,", MaxPortsPerRule) + `1]}]`,
		"too many rules":   `[` + strings.Repeat(`{"cidr":"10.0.0.1/32","proto":"tcp","ports":[1]},`, MaxRules) + `{"cidr":"10.0.0.1/32","proto":"tcp","ports":[1]}]`,
		"huge port string": `[{"cidr":"10.0.0.1/32","proto":"tcp","ports":["` + strings.Repeat("1", 100) + `"]}]`,
	} {
		if _, err := Parse([]byte(in)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestPortRoundTrip(t *testing.T) {
	rules, err := Parse([]byte(mesocentre))
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rules {
		for _, p := range r.Ports {
			var q Port
			b, _ := p.MarshalJSON()
			if err := q.UnmarshalJSON(b); err != nil || q != p {
				t.Errorf("%v -> %s -> %v (%v)", p, b, q, err)
			}
		}
	}
}

func TestLegacyAndRoutes(t *testing.T) {
	l := Legacy([]string{"10.1.0.0/16", "10.1.5.0/16", "bogus"})
	if got, want := Routes(l), []string{"10.1.0.0/16"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("routes = %v, want %v", got, want)
	}
	if l[0].Proto != ProtoAny {
		t.Fatal("legacy rules allow every protocol")
	}
	if err := l[0].Validate(); err == nil {
		t.Fatal("a policy may not say proto any")
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte(mesocentre))
	f.Add([]byte(`[]`))
	f.Add([]byte(`[{"cidr":"0.0.0.0/0","proto":"udp","ports":["1-65535"]}]`))
	f.Fuzz(func(t *testing.T, data []byte) {
		rules, err := Parse(data)
		if err != nil {
			return
		}
		// Whatever Parse accepts is enforceable and routable.
		if err := Validate(rules); err != nil {
			t.Fatalf("Parse accepted what Validate refuses: %v", err)
		}
		for _, r := range rules {
			if !r.Prefix().IsValid() || !r.Prefix().Addr().Is4() {
				t.Fatalf("accepted rule has no IPv4 prefix: %+v", r)
			}
		}
		if len(Routes(rules)) > len(rules) {
			t.Fatal("more routes than rules")
		}
	})
}
