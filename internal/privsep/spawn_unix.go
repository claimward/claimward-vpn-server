//go:build unix

package privsep

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"syscall"
)

// ChildFD is the descriptor the child finds its end of the socketpair on: the
// first ExtraFiles entry. It is the only descriptor the child inherits besides
// stdio.
const ChildFD = 3

// Child is the started unprivileged process.
type Child struct {
	Cmd *exec.Cmd
	// Conn is the parent's end of the socketpair.
	Conn *net.UnixConn
}

// StartChild runs exe with args as a fresh process (fork and exec: its address
// space holds nothing of the parent's), as the credential cred when it is not
// nil, with env as its whole environment, and the child's end of a new
// socketpair as descriptor ChildFD. Standard input is /dev/null; standard
// output and error are the parent's.
//
// ⛔ If the credential cannot be applied the child does not run: the fork's
// setuid failing makes Start return the error, and nothing is executed as root.
func StartChild(exe string, args, env []string, cred *syscall.Credential) (*Child, error) {
	fds, err := socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, fmt.Errorf("privsep: socketpair: %w", err)
	}
	syscall.CloseOnExec(fds[0])
	syscall.CloseOnExec(fds[1])
	parentFile := os.NewFile(uintptr(fds[0]), "privsep-parent")
	childFile := os.NewFile(uintptr(fds[1]), "privsep-child")
	defer childFile.Close() // the child has its own copy once it runs

	cmd := exec.Command(exe, args...)
	cmd.Env = env
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	cmd.ExtraFiles = []*os.File{childFile}
	if cred != nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: cred}
	}
	if err := cmd.Start(); err != nil {
		parentFile.Close()
		return nil, fmt.Errorf("privsep: start the unprivileged child: %w", err)
	}
	uc, err := unixConn(parentFile)
	parentFile.Close()
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, fmt.Errorf("privsep: parent end of the socketpair: %w", err)
	}
	return &Child{Cmd: cmd, Conn: uc}, nil
}

// The two system calls whose failure a test cannot cause by itself.
var (
	socketpair = syscall.Socketpair
	fileConn   = net.FileConn
)

// unixConn is the connection on f, which must be a unix socket. It duplicates
// the descriptor: the caller still owns f.
func unixConn(f *os.File) (*net.UnixConn, error) {
	c, err := fileConn(f)
	if err != nil {
		return nil, err
	}
	uc, ok := c.(*net.UnixConn)
	if !ok {
		c.Close()
		return nil, errors.New("not a unix socket")
	}
	return uc, nil
}

// ParentConn is the child's end of the socketpair, inherited on ChildFD. It
// fails when the descriptor is not a unix stream socket, which is what a
// child started by hand, not by the parent, finds.
func ParentConn() (*net.UnixConn, error) { return connOnFD(ChildFD) }

// connOnFD takes ownership of descriptor fd (it is closed once duplicated).
func connOnFD(fd int) (*net.UnixConn, error) {
	// Look before taking ownership: closing a descriptor that is not ours (the
	// runtime's own poller can be number 3 in a process nobody gave a socket)
	// would be a crash, not a refusal.
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil || st.Mode&syscall.S_IFMT != syscall.S_IFSOCK {
		return nil, fmt.Errorf("privsep: descriptor %d is not a socket to the privileged parent: this role is started by the parent only", fd)
	}
	f := os.NewFile(uintptr(fd), "privsep-parent")
	defer f.Close() // the connection holds a duplicate
	uc, err := unixConn(f)
	if err != nil {
		return nil, fmt.Errorf("privsep: descriptor %d: %w", fd, err)
	}
	return uc, nil
}
