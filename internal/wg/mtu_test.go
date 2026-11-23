package wg

import (
	"net/netip"
	"testing"
)

func TestUplinkMTU(t *testing.T) {
	for _, c := range []struct {
		name   string
		v4, v6 int
		want   int
	}{
		{"neither route", 0, 0, 0},
		{"v4 only", 1500, 0, 1500},
		{"v6 only", 0, 1450, 1450},
		{"smallest of both", 1500, 1450, 1450},
		{"smallest of both, other order", 1400, 1500, 1400},
	} {
		got := uplinkMTU(func(p netip.AddrPort) int {
			if p.Addr().Is4() {
				return c.v4
			}
			return c.v6
		})
		if got != c.want {
			t.Errorf("%s: uplinkMTU = %d, want %d", c.name, got, c.want)
		}
	}
}
