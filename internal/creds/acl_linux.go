//go:build linux

package creds

import (
	"os"

	"golang.org/x/sys/unix"
)

// readACL returns the raw access ACL of the open file, through its descriptor
// (the file cannot change between the check and the read). A file without one
// returns ENODATA; a value over MaxACLSize returns ERANGE, which is refused.
func readACL(f *os.File) ([]byte, error) {
	buf := make([]byte, MaxACLSize)
	n, err := unix.Fgetxattr(int(f.Fd()), XattrACLAccess, buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}
