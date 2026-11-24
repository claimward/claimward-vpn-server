//go:build !linux && !openbsd

package wg

import "errors"

// SetInterfaceMTU is supported on Linux and OpenBSD only.
func SetInterfaceMTU(string, int) error {
	return errors.New("setting an interface MTU is only supported on Linux and OpenBSD")
}
