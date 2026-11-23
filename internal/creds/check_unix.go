//go:build unix

package creds

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// openNoFollow opens path read-only; a symbolic link as the last element
// fails (ELOOP) rather than being followed. O_NONBLOCK keeps a FIFO from
// blocking the open: it is refused below as not regular.
func openNoFollow(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(fd), path), nil
}

// getuid is the process's uid; a variable so a test can play another owner.
var getuid = os.Getuid

func isSymlinkError(err error) bool {
	return errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.EMLINK)
}

// checkFile judges the open descriptor: regular file, no group or other
// access, owned by this process's uid.
func checkFile(f *os.File, path, name string) error {
	var st syscall.Stat_t
	if err := syscall.Fstat(int(f.Fd()), &st); err != nil {
		return fmt.Errorf("credential %s: %w", path, err)
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFREG {
		return refuse(path, name, "is not a regular file")
	}
	if st.Mode&0o077 != 0 {
		return refuse(path, name, fmt.Sprintf("has mode %04o: readable or writable by group or other", st.Mode&0o777))
	}
	if int(st.Uid) != getuid() {
		return refuse(path, name, fmt.Sprintf("is owned by uid %d, not by this process (uid %d)", st.Uid, getuid()))
	}
	// Size is judged by Read, on what it actually read (empty, over MaxSize).
	return nil
}
