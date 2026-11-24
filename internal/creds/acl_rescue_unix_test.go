//go:build unix

package creds

import (
	"errors"
	"os"
	"strings"
	"syscall"
	"testing"
)

func TestACLRescue(t *testing.T) {
	uid := uint32(os.Getuid())
	good := func() ([]byte, error) { return aclBytes(2, systemdACL(uid)...), nil }
	other := func() ([]byte, error) { return aclBytes(2, systemdACL(uid+1)...), nil }
	fail := func() ([]byte, error) { return nil, errors.New("no xattr") }

	// Untyped constants: Stat_t.Mode is uint16 on darwin and uint32 on linux.
	cases := []struct {
		name   string
		st     *syscall.Stat_t
		read   func() ([]byte, error)
		ok     bool
		suffix string
	}{
		{"systemd's shape", &syscall.Stat_t{Uid: 0, Mode: 0o100440}, good, true, ""},
		{"another uid in the ACL", &syscall.Stat_t{Uid: 0, Mode: 0o100440}, other, false, "; and it "},
		{"unreadable ACL", &syscall.Stat_t{Uid: 0, Mode: 0o100440}, fail, false, ""},
		{"not owned by root", &syscall.Stat_t{Uid: 1000, Mode: 0o100440}, good, false, ""},
		{"mode 0640", &syscall.Stat_t{Uid: 0, Mode: 0o100640}, good, false, ""},
		{"mode 0444", &syscall.Stat_t{Uid: 0, Mode: 0o100444}, good, false, ""},
	}
	for _, c := range cases {
		err := aclRescue("/p", "n", "base", c.st, c.read)
		if (err == nil) != c.ok {
			t.Errorf("%s: accepted = %v (%v), want %v", c.name, err == nil, err, c.ok)
			continue
		}
		if err == nil {
			continue
		}
		if !strings.Contains(err.Error(), "base") {
			t.Errorf("%s: reason lost: %v", c.name, err)
		}
		if has := strings.Contains(err.Error(), "; and it "); has != (c.suffix != "") {
			t.Errorf("%s: ACL reason present = %v: %v", c.name, has, err)
		}
	}
}
