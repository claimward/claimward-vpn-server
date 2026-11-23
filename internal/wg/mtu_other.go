//go:build !linux

package wg

import "errors"

// SetInterfaceMTU is Linux only: the gateway runs on Linux.
func SetInterfaceMTU(string, int) error {
	return errors.New("setting an interface MTU is only supported on Linux")
}
