package main

import "testing"

func TestTheChildRefusesAnyRootIdentity(t *testing.T) {
	cases := []struct {
		name                 string
		uid, euid, gid, egid int
		groups               []int
		wantRefused          bool
	}{
		{"unprivileged", 500, 500, 500, 500, []int{500}, false},
		{"root uid", 0, 500, 500, 500, nil, true},
		{"root euid", 500, 0, 500, 500, nil, true},
		{"root gid", 500, 500, 0, 500, nil, true},
		{"root egid", 500, 500, 500, 0, nil, true},
		{"wheel supplementary", 500, 500, 500, 500, []int{500, 0}, true},
	}
	for _, c := range cases {
		err := requireUnprivileged(c.uid, c.euid, c.gid, c.egid, c.groups)
		if (err != nil) != c.wantRefused {
			t.Errorf("%s: err = %v, want refused = %v", c.name, err, c.wantRefused)
		}
	}
}
