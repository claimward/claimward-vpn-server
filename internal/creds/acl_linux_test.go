//go:build linux

package creds

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// setfacl runs setfacl on path; it skips (fails under CW_REQUIRE_ROOT) when the
// tool or the filesystem has no ACLs.
func setfacl(t *testing.T, path string, spec string) {
	t.Helper()
	out, err := exec.Command("setfacl", "-m", spec, path).CombinedOutput()
	if err != nil {
		if os.Getenv("CW_REQUIRE_ROOT") != "" {
			t.Fatalf("setfacl -m %s: %v: %s", spec, err, out)
		}
		t.Skipf("setfacl unavailable here: %v: %s", err, out)
	}
}

// The shape systemd makes, built the way systemd builds it (a root:root 0400
// file, one read-only user entry added), then read through Read: the loader
// accepts it for that user and refuses every wider ACL.
func TestSystemdACLCredentialThroughRead(t *testing.T) {
	requireRoot(t)
	const uid = 61234
	playProcess(t, uid, uid) // DynamicUser: an uid and a gid nobody else has
	dir := t.TempDir()
	mk := func(spec ...string) string {
		t.Helper()
		p := filepath.Join(dir, GitHubToken)
		_ = os.Remove(p)
		if err := os.WriteFile(p, []byte("tok\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(p, 0, 0); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, 0o400); err != nil {
			t.Fatal(err)
		}
		for _, s := range spec {
			setfacl(t, p, s)
		}
		return p
	}

	p := mk("u:61234:r")
	if st, err := os.Stat(p); err != nil || st.Mode().Perm() != 0o440 {
		t.Fatalf("the mask must show as mode 0440, got %v, %v", st, err)
	}
	if got, err := Read(dir, GitHubToken); err != nil || got != "tok" {
		t.Fatalf("systemd's ACL shape: %q, %v", got, err)
	}

	// Each of these must be refused, and the message must say why.
	for _, c := range []struct {
		name string
		spec []string
		want string
	}{
		{"another user only", []string{"u:61235:r"}, "not this process"},
		{"also another user", []string{"u:61234:r", "u:61235:r"}, "not this process"},
		{"a named group", []string{"u:61234:r", "g:61234:r"}, "entry for group"},
		// The mask then shows as mode 0460 / 0450: refused before the ACL.
		{"write for the service", []string{"u:61234:rw"}, "mode 0460"},
		{"execute for the service", []string{"u:61234:rx"}, "mode 0450"},
		{"a group entry alone", []string{"g:61234:r"}, "entry for group"},
	} {
		mk(c.spec...)
		refused(t, dir, GitHubToken, c.want)
	}
	// No ACL at all: root:root 0400 is not this process's.
	mk()
	refused(t, dir, GitHubToken, "owned by uid 0")
	// The ACL is right but the file is wider than the ACL says.
	p = mk("u:61234:r")
	if err := os.Chmod(p, 0o444); err != nil {
		t.Fatal(err)
	}
	refused(t, dir, GitHubToken, "readable or writable by group or other")
}
