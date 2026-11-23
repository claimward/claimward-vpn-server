//go:build !unix

package creds

import (
	"errors"
	"os"
)

var errUnsupported = errors.New("credentials directories need a Unix system (no O_NOFOLLOW/owner check here)")

func openNoFollow(path string) (*os.File, error) {
	return nil, &os.PathError{Op: "open", Path: path, Err: errUnsupported}
}

func isSymlinkError(error) bool { return false }

func checkFile(*os.File, string, string) error { return errUnsupported }
