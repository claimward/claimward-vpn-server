// Package creds reads the server's secrets from a credentials directory.
//
// The directory is $CREDENTIALS_DIRECTORY, the systemd contract: one plain
// file per secret, named for it. Docker and Podman (/run/secrets) and
// Kubernetes (the Secret volume's mount path) set the same variable by hand.
// Nothing else carries a secret: an environment is copied into every child
// process and every crash dump.
//
// Every file is checked through the descriptor it was opened with (O_NOFOLLOW,
// then Fstat), never by a Lstat followed by an open: the file cannot change
// between the check and the read.
package creds

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
)

// EnvDir is the variable that names the credentials directory.
const EnvDir = "CREDENTIALS_DIRECTORY"

// The fixed credential names, and the only ones Read accepts.
const (
	GitHubToken          = "github-token"
	WGPrivateKey         = "wg-private-key"
	AdminToken           = "admin-token"
	GoAuthnGatewaySecret = "goauthn-gateway-secret"
	GitHubClientSecret   = "github-client-secret"
)

// MaxSize bounds a credential file.
const MaxSize = 64 << 10

// ErrNotFound is wrapped by the error Read returns when there is no such
// credential: the directory is not set, or the file is not in it.
var ErrNotFound = errors.New("credential not found")

// readAll is io.ReadAll; a variable so a test can make the read fail.
var readAll = io.ReadAll

// Names lists the credential names Read accepts.
func Names() []string {
	return []string{GitHubToken, WGPrivateKey, AdminToken, GoAuthnGatewaySecret, GitHubClientSecret}
}

// ValidName reports whether name is one of the fixed credential names. A name
// is never a path: no separator, no dot segment can reach Read.
func ValidName(name string) bool {
	for _, n := range Names() {
		if name == n {
			return true
		}
	}
	return false
}

// Read returns the credential name from dir, with one trailing newline
// removed. dir is $CREDENTIALS_DIRECTORY, passed by the caller. A missing
// credential is an error wrapping ErrNotFound; a file that is not safe to read
// is refused with the fix for each platform.
func Read(dir, name string) (string, error) {
	if !ValidName(name) {
		return "", fmt.Errorf("creds: %q is not a credential name", name)
	}
	if dir == "" {
		return "", fmt.Errorf("%w: %s is not set, so %s has nowhere to be read from; %s", ErrNotFound, EnvDir, name, where(name))
	}
	path := filepath.Join(dir, name)
	f, err := openNoFollow(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", fmt.Errorf("%w: %s does not exist; %s", ErrNotFound, path, where(name))
		}
		if isSymlinkError(err) {
			return "", fmt.Errorf("credential %s is a symbolic link, refused: use a regular file (%s)", path, fix(name))
		}
		return "", fmt.Errorf("credential %s: %w", path, err)
	}
	defer f.Close()
	if err := checkFile(f, path, name); err != nil {
		return "", err
	}
	b, err := readAll(io.LimitReader(f, MaxSize+1))
	if err != nil {
		return "", fmt.Errorf("credential %s: %w", path, err)
	}
	if len(b) > MaxSize {
		return "", fmt.Errorf("credential %s is larger than %d bytes, refused", path, MaxSize)
	}
	s := TrimNewline(string(b))
	if s == "" {
		return "", fmt.Errorf("credential %s is empty, refused", path)
	}
	return s, nil
}

// TrimNewline removes ONE trailing newline ("\n", or "\r\n"), nothing else:
// a secret may legitimately end in a space or hold several lines.
func TrimNewline(s string) string {
	if n := len(s); n > 0 && s[n-1] == '\n' {
		s = s[:n-1]
		if n := len(s); n > 0 && s[n-1] == '\r' {
			s = s[:n-1]
		}
	}
	return s
}

func where(name string) string {
	return "create the file " + EnvDir + "/" + name + " (see deploy/README.md)"
}

// fix is the exact remedy for a file that is too open or not the process's.
func fix(name string) string {
	return "Swarm: `mode: 0400` on the secret; Kubernetes: `defaultMode: 0440` on the Secret volume " +
		"and `fsGroup: <gid>` with `runAsUser: <uid>` / `runAsGroup: <gid>` in the pod securityContext " +
		"(the files are root:<fsGroup>, mode 0440, which the server accepts; 0444 or 0644 it refuses); " +
		"Podman: `--secret " + name + ",mode=0400`; " +
		"systemd: `LoadCredential=` / `LoadCredentialEncrypted=` as shipped (root-owned file with a read-only ACL for the service's user is accepted); " +
		"otherwise: `chown <service user> " + EnvDir + "/" + name + " && chmod 0400 " + EnvDir + "/" + name + "`"
}

func refuse(path, name, why string) error {
	return fmt.Errorf("credential %s %s, refused. Fix: %s", path, why, fix(name))
}
