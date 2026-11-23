//go:build unix

package creds

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func put(t *testing.T, dir, name, content string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, name)
	_ = os.Remove(p) // a 0400 file cannot be rewritten in place
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil { // umask must not weaken the test
		t.Fatal(err)
	}
	return p
}

func refused(t *testing.T, dir, name, want string) {
	t.Helper()
	got, err := Read(dir, name)
	if err == nil {
		t.Fatalf("Read accepted the file, returned %q", got)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("error %q does not contain %q", err, want)
	}
	if errors.Is(err, ErrNotFound) {
		t.Fatalf("a refused file must not read as an absent one: %v", err)
	}
}

func TestHappyPathTrimsOneNewline(t *testing.T) {
	dir := t.TempDir()
	for content, want := range map[string]string{
		"s3cret":     "s3cret",
		"s3cret\n":   "s3cret",
		"s3cret\r\n": "s3cret",
		"s3cret\n\n": "s3cret\n",
		"s3cret ":    "s3cret ",
		"a\nb\n":     "a\nb",
	} {
		put(t, dir, AdminToken, content, 0o400)
		got, err := Read(dir, AdminToken)
		if err != nil || got != want {
			t.Errorf("%q: got %q, %v; want %q", content, got, err, want)
		}
	}
	// 0600 (owner only) is as good as 0400.
	put(t, dir, WGPrivateKey, "k", 0o600)
	if got, err := Read(dir, WGPrivateKey); err != nil || got != "k" {
		t.Errorf("0600: %q, %v", got, err)
	}
}

func TestRefusesASymlink(t *testing.T) {
	dir := t.TempDir()
	target := put(t, dir, "real", "x", 0o400)
	if err := os.Symlink(target, filepath.Join(dir, GitHubToken)); err != nil {
		t.Fatal(err)
	}
	refused(t, dir, GitHubToken, "symbolic link")
}

func TestRefusesADanglingSymlink(t *testing.T) {
	dir := t.TempDir()
	if err := os.Symlink(filepath.Join(dir, "nowhere"), filepath.Join(dir, GitHubToken)); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(dir, GitHubToken); err == nil {
		t.Fatal("accepted a dangling link")
	}
}

func TestRefusesNotRegular(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, AdminToken), 0o700); err != nil {
		t.Fatal(err)
	}
	refused(t, dir, AdminToken, "not a regular file")
	if err := syscall.Mkfifo(filepath.Join(dir, GitHubToken), 0o600); err != nil {
		t.Fatal(err)
	}
	refused(t, dir, GitHubToken, "not a regular file") // must not block either
}

func TestRefusesGroupOrOtherAccess(t *testing.T) {
	for _, mode := range []os.FileMode{0o644, 0o640, 0o604, 0o440, 0o420, 0o700 | 0o001} {
		dir := t.TempDir()
		put(t, dir, WGPrivateKey, "k", mode)
		refused(t, dir, WGPrivateKey, "readable or writable by group or other")
	}
	// the refusal carries the fix for every platform
	dir := t.TempDir()
	put(t, dir, WGPrivateKey, "k", 0o644)
	_, err := Read(dir, WGPrivateKey)
	for _, want := range []string{"mode: 0400", "defaultMode: 0400", "--secret wg-private-key,mode=0400", "chmod 0400"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("fix lacks %q: %v", want, err)
		}
	}
}

func TestRefusesWrongOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("changing the owner needs root")
	}
	dir := t.TempDir()
	p := put(t, dir, AdminToken, "t", 0o400)
	if err := os.Chown(p, 65534, -1); err != nil {
		t.Skip(err)
	}
	refused(t, dir, AdminToken, "owned by uid 65534")
}

func TestRefusesEmpty(t *testing.T) {
	dir := t.TempDir()
	put(t, dir, AdminToken, "", 0o400)
	refused(t, dir, AdminToken, "empty")
	put(t, dir, AdminToken, "\n", 0o400) // only a newline: empty once trimmed
	refused(t, dir, AdminToken, "empty")
}

func TestRefusesOversize(t *testing.T) {
	dir := t.TempDir()
	put(t, dir, AdminToken, strings.Repeat("x", MaxSize+1), 0o400)
	refused(t, dir, AdminToken, "larger than")
	put(t, dir, AdminToken, strings.Repeat("x", MaxSize), 0o400)
	if _, err := Read(dir, AdminToken); err != nil {
		t.Fatalf("exactly the bound must pass: %v", err)
	}
}

func TestMissingIsNotFound(t *testing.T) {
	_, err := Read(t.TempDir(), GoAuthnGatewaySecret)
	if !errors.Is(err, ErrNotFound) || !strings.Contains(err.Error(), "goauthn-gateway-secret") {
		t.Fatalf("got %v", err)
	}
	_, err = Read("", GoAuthnGatewaySecret)
	if !errors.Is(err, ErrNotFound) || !strings.Contains(err.Error(), EnvDir) {
		t.Fatalf("unset dir: %v", err)
	}
}

func TestOnlyFixedNames(t *testing.T) {
	dir := t.TempDir()
	put(t, dir, "other", "x", 0o400)
	for _, n := range []string{"other", "../x", "", "/etc/passwd", "admin-token/", "admin-token\x00"} {
		if _, err := Read(dir, n); err == nil {
			t.Errorf("name %q accepted", n)
		}
	}
}

func FuzzNameAndContent(f *testing.F) {
	f.Add("admin-token", "abc\n")
	f.Add("../../etc/passwd", "")
	f.Add("wg-private-key", "\r\n\r\n")
	f.Fuzz(func(t *testing.T, name, content string) {
		// A name outside the fixed set is always refused, whatever it holds.
		if !ValidName(name) {
			if _, err := Read(t.TempDir(), name); err == nil {
				t.Fatalf("name %q accepted", name)
			}
			return
		}
		// Trimming removes at most one newline (two bytes with a CR) and
		// never adds or alters anything.
		got := TrimNewline(content)
		if !strings.HasPrefix(content, got) || len(content)-len(got) > 2 {
			t.Fatalf("TrimNewline(%q) = %q", content, got)
		}
		if strings.HasSuffix(content, "\n") == (got == content) {
			t.Fatalf("TrimNewline(%q) = %q: newline not removed exactly when present", content, got)
		}
	})
}
