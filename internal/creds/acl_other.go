//go:build unix && !linux

package creds

import (
	"errors"
	"os"
)

// readACL: POSIX ACL xattrs are read the Linux way only; elsewhere no ACL is
// ever trusted and the file is judged by its mode and owner alone.
func readACL(*os.File) ([]byte, error) {
	return nil, errors.New("ACLs are not read on this platform")
}
