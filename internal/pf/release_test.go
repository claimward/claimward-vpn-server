package pf

import "testing"

func TestCheckRelease(t *testing.T) {
	for _, ok := range []string{"7.9", "8.0"} {
		if err := CheckRelease(ok); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "7.8", "7.9.1", "7.10", "8.1", "9.0", " 7.9", "7.9\n", "7", "8.0-current"} {
		if err := CheckRelease(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
