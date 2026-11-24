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

// getegid and getgroups are the process's effective gid and supplementary
// groups; variables so a test can play another group.
var (
	getegid   = os.Getegid
	getgroups = os.Getgroups
)

// inProcessGroup reports whether gid is the effective gid or one of the
// supplementary groups. Kubernetes applies fsGroup as a supplementary group.
func inProcessGroup(gid int) bool {
	if gid == getegid() {
		return true
	}
	// On error getgroups returns no groups, so nothing matches and the file is
	// refused: failing closed needs no branch of its own.
	groups, _ := getgroups()
	for _, g := range groups {
		if g == gid {
			return true
		}
	}
	return false
}

// judge decides on a file's mode, owner and group. Two shapes are accepted:
//   - the process's own file with no group or other access (0400, 0600);
//   - a root-owned file of mode exactly 0440 whose group is the process's
//     effective gid or one of its supplementary groups: what a Kubernetes
//     Secret volume holds with defaultMode 0440 and fsGroup, where the files
//     can only belong to root and the pod need not run as root.
//
// It returns the reason for a refusal, "" for an acceptance.
func judge(mode, uid, gid uint32) string {
	perm := mode & 0o777
	if perm&0o077 == 0 && int(uid) == getuid() {
		return ""
	}
	if uid == 0 && perm == 0o440 {
		if inProcessGroup(int(gid)) {
			return ""
		}
		return fmt.Sprintf("is owned by root with mode 0440 but its group %d is neither this process's gid (%d) nor one of its supplementary groups", gid, getegid())
	}
	if perm&0o077 != 0 {
		return fmt.Sprintf("has mode %04o: readable or writable by group or other", perm)
	}
	return fmt.Sprintf("is owned by uid %d, not by this process (uid %d)", uid, getuid())
}

// checkFile judges the open descriptor: a regular file, accepted by judge.
func checkFile(f *os.File, path, name string) error {
	var st syscall.Stat_t
	if err := syscall.Fstat(int(f.Fd()), &st); err != nil {
		return fmt.Errorf("credential %s: %w", path, err)
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFREG {
		return refuse(path, name, "is not a regular file")
	}
	if why := judge(uint32(st.Mode), st.Uid, st.Gid); why != "" {
		// systemd gives another user's service a root-owned file whose
		// stat mode is 0440 (the ACL mask) and whose ACL names the service
		// uid: accepted only if the ACL is exactly that (see acl.go).
		return aclRescue(path, name, why, &st, func() ([]byte, error) { return readACL(f) })
	}
	// Size is judged by Read, on what it actually read (empty, over MaxSize).
	return nil
}

// aclRescue accepts a root-owned file whose stat mode is 0440 when its ACL is
// exactly systemd's shape for this uid; otherwise it returns the refusal reason,
// extended with why the ACL was no better.
func aclRescue(path, name, why string, st *syscall.Stat_t, read func() ([]byte, error)) error {
	if st.Uid != 0 || st.Mode&0o777 != 0o440 {
		return refuse(path, name, why)
	}
	acl, err := read()
	if err != nil {
		return refuse(path, name, why)
	}
	aclWhy := judgeACL(acl, uint32(getuid()))
	if aclWhy == "" {
		return nil
	}
	return refuse(path, name, why+"; and it "+aclWhy)
}
