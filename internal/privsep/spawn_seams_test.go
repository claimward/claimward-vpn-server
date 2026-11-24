//go:build unix

package privsep

import (
	"errors"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
)

func TestAStartThatCannotMakeASocketpairFailsBeforeRunningAnything(t *testing.T) {
	old := socketpair
	t.Cleanup(func() { socketpair = old })
	socketpair = func(int, int, int) ([2]int, error) { return [2]int{}, errors.New("EMFILE") }
	if _, err := StartChild("/bin/true", nil, nil, nil); err == nil || !strings.Contains(err.Error(), "socketpair") {
		t.Fatalf("err = %v", err)
	}
}

func TestAStartOfAMissingProgramFails(t *testing.T) {
	if _, err := StartChild("/nonexistent/claimward", nil, nil, nil); err == nil || !strings.Contains(err.Error(), "start the unprivileged child") {
		t.Fatalf("err = %v", err)
	}
}

func TestAStartWhoseSocketCannotBeWrappedEndsTheChild(t *testing.T) {
	old := fileConn
	t.Cleanup(func() { fileConn = old })
	fileConn = func(*os.File) (net.Conn, error) { return nil, errors.New("EBADF") }
	if _, err := StartChild("/bin/sleep", []string{"30"}, nil, nil); err == nil || !strings.Contains(err.Error(), "parent end of the socketpair") {
		t.Fatalf("err = %v", err)
	}
}

func TestADescriptorIsTakenOnlyWhenItIsAUnixSocket(t *testing.T) {
	dup := func(t *testing.T, fd int) int {
		t.Helper()
		n, err := syscall.Dup(fd)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	t.Run("a unix socket", func(t *testing.T) {
		fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer syscall.Close(fds[1])
		c, err := connOnFD(fds[0])
		if err != nil {
			t.Fatal(err)
		}
		c.Close()
	})
	t.Run("a regular file", func(t *testing.T) {
		f, err := os.CreateTemp(t.TempDir(), "x")
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		fd := dup(t, int(f.Fd()))
		if _, err := connOnFD(fd); err == nil || !strings.Contains(err.Error(), "started by the parent only") {
			t.Fatalf("err = %v", err)
		}
		syscall.Close(fd)
	})
	t.Run("a closed descriptor", func(t *testing.T) {
		if _, err := connOnFD(1 << 20); err == nil || !strings.Contains(err.Error(), "started by the parent only") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("a socket of another family", func(t *testing.T) {
		fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
		if err != nil {
			t.Skip("no inet socket here:", err)
		}
		if _, err := connOnFD(fd); err == nil || !strings.Contains(err.Error(), "not a unix socket") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("a socket that cannot be wrapped", func(t *testing.T) {
		old := fileConn
		t.Cleanup(func() { fileConn = old })
		fileConn = func(*os.File) (net.Conn, error) { return nil, errors.New("EBADF") }
		fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer syscall.Close(fds[1])
		if _, err := connOnFD(fds[0]); err == nil || !strings.Contains(err.Error(), "EBADF") {
			t.Fatalf("err = %v", err)
		}
	})
}
