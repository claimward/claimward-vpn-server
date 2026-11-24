package pf

import "fmt"

// SupportedReleases are the OpenBSD releases whose pf ioctl ABI was generated
// and diffed byte for byte by the pfabi CI lane (7.9 and 8.0 share one
// struct pf_rule layout). Any other release is refused: a different layout
// would be encoded silently wrong, and a gateway that mis-encodes its own
// firewall is worse than one that does not start.
var SupportedReleases = []string{"7.9", "8.0"}

// CheckRelease refuses every kern.osrelease that is not in SupportedReleases.
// The value is compared whole: "7.9" is accepted, "7.9.1", "7.10" and "" are
// not.
func CheckRelease(osrelease string) error {
	for _, r := range SupportedReleases {
		if osrelease == r {
			return nil
		}
	}
	return fmt.Errorf("pf: OpenBSD %q is not supported (only %v: the pf ioctl layout is generated and verified per release)", osrelease, SupportedReleases)
}
