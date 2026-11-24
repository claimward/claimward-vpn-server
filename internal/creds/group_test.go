//go:build unix

package creds

import (
	"os"
	"strings"
	"testing"
)

// playProcess makes the process look like uid/gid/groups for the rule under test.
func playProcess(t *testing.T, uid, egid int, groups ...int) {
	t.Helper()
	ou, oe, og := getuid, getegid, getgroups
	t.Cleanup(func() { getuid, getegid, getgroups = ou, oe, og })
	getuid = func() int { return uid }
	getegid = func() int { return egid }
	getgroups = func() ([]int, error) { return groups, nil }
}

// TestJudge covers every accepted and refused shape on bare numbers, so it
// runs anywhere (no chown needed).
func TestJudge(t *testing.T) {
	playProcess(t, 65532, 65532, 65532, 7)
	for _, c := range []struct {
		name        string
		mode        uint32
		uid, gid    uint32
		wantRefusal string // "" = accepted
	}{
		{"own 0400", 0o400, 65532, 1, ""},
		{"own 0600", 0o600, 65532, 1, ""},
		{"root 0440 egid", 0o440, 0, 65532, ""},
		{"root 0440 supplementary group", 0o440, 0, 7, ""},
		{"root 0440 foreign group", 0o440, 0, 99, "neither this process's gid (65532) nor one of its supplementary"},
		{"root 0444", 0o444, 0, 65532, "mode 0444"},
		{"root 0644", 0o644, 0, 65532, "mode 0644"},
		{"root 0640", 0o640, 0, 65532, "mode 0640"},
		{"root 0400 foreign owner rule", 0o400, 0, 65532, "owned by uid 0"},
		{"root 0660", 0o660, 0, 65532, "mode 0660"},
		{"other owner 0440 own group", 0o440, 1000, 65532, "mode 0440"},
		{"other owner 0400", 0o400, 1000, 65532, "owned by uid 1000"},
		{"own 0444", 0o444, 65532, 65532, "mode 0444"},
	} {
		got := judge(c.mode, c.uid, c.gid)
		if c.wantRefusal == "" {
			if got != "" {
				t.Errorf("%s: refused: %s", c.name, got)
			}
			continue
		}
		if !strings.Contains(got, c.wantRefusal) {
			t.Errorf("%s: got %q, want it to contain %q", c.name, got, c.wantRefusal)
		}
	}
}

// A getgroups failure must not accept a root file by luck.
func TestJudgeGetgroupsError(t *testing.T) {
	playProcess(t, 65532, 65532)
	og := getgroups
	t.Cleanup(func() { getgroups = og })
	getgroups = func() ([]int, error) { return nil, os.ErrPermission }
	if got := judge(0o440, 0, 7); got == "" {
		t.Fatal("accepted a root 0440 file of group 7 although the groups could not be read")
	}
	if got := judge(0o440, 0, 65532); got != "" {
		t.Fatalf("the effective gid alone must suffice: %s", got)
	}
}

func TestRefusalNamesTheKubernetesSettings(t *testing.T) {
	err := refuse("/c/x", "admin-token", "has mode 0644: x")
	for _, want := range []string{"defaultMode: 0440", "fsGroup", "runAsUser", "runAsGroup"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal lacks %q: %v", want, err)
		}
	}
}

// requireRoot skips off root, with the reason; the CI lane `creds as root`
// sets CW_REQUIRE_ROOT=1 so that there a skip is a failure.
func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		return
	}
	if os.Getenv("CW_REQUIRE_ROOT") != "" {
		t.Fatal("CW_REQUIRE_ROOT is set but the test does not run as root")
	}
	t.Skip("needs root to chown a file to root:<gid> (CI runs it in the `creds as root` lane)")
}

// rootFile writes a real file owned root:gid with the given mode.
func rootFile(t *testing.T, dir, name string, gid int, mode os.FileMode) {
	t.Helper()
	p := put(t, dir, name, "tok\n", mode)
	if err := os.Chown(p, 0, gid); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil { // chown may clear nothing, but be explicit
		t.Fatal(err)
	}
}

// The real thing, through Read: O_NOFOLLOW, Fstat, then the rule.
func TestRootOwnedFilesThroughRead(t *testing.T) {
	requireRoot(t)
	playProcess(t, 65532, 65532, 4242) // a non-root pod: egid 65532, fsGroup 4242
	dir := t.TempDir()

	rootFile(t, dir, GitHubToken, 65532, 0o440) // egid
	if got, err := Read(dir, GitHubToken); err != nil || got != "tok" {
		t.Fatalf("egid group: %q, %v", got, err)
	}
	rootFile(t, dir, GitHubToken, 4242, 0o440) // supplementary group (fsGroup)
	if got, err := Read(dir, GitHubToken); err != nil || got != "tok" {
		t.Fatalf("supplementary group: %q, %v", got, err)
	}
	rootFile(t, dir, GitHubToken, 99, 0o440) // foreign group
	refused(t, dir, GitHubToken, "neither this process's gid")
	for _, m := range []os.FileMode{0o444, 0o644, 0o640, 0o660} {
		rootFile(t, dir, GitHubToken, 65532, m)
		refused(t, dir, GitHubToken, "readable or writable by group or other")
	}
	// Another non-root owner with a matching group is refused as well.
	p := put(t, dir, AdminToken, "t", 0o440)
	if err := os.Chown(p, 1000, 65532); err != nil {
		t.Fatal(err)
	}
	refused(t, dir, AdminToken, "mode 0440")
}
