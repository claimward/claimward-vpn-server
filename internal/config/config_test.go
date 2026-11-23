package config

import (
	"os"
	"path/filepath"
	"testing"
)

// credsDir writes each name: content as a 0400 file in a fresh directory and
// points CREDENTIALS_DIRECTORY at it. It returns the directory.
func credsDir(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o400); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("CREDENTIALS_DIRECTORY", dir)
	return dir
}

// baseEnv is the least environment Load accepts with the OIDC provider, so
// the tests below vary one setting at a time.
func baseEnv(t *testing.T) {
	t.Helper()
	credsDir(t, map[string]string{"wg-private-key": "c2VydmVy\n"})
	t.Setenv("WG_ENDPOINT", "vpn.example.org:51820")
	t.Setenv("AUTH_PROVIDER", "oidc")
	t.Setenv("OIDC_ISSUER", "https://idp.example.org")
	t.Setenv("OIDC_CLIENT_ID", "claimward")
}

func TestMaxDevicesPerSubject(t *testing.T) {
	for _, tc := range []struct {
		env     string
		want    int
		wantErr bool
	}{
		{"", 5, false},
		{"2", 2, false},
		{"0", 0, true},
		{"-1", 0, true},
	} {
		baseEnv(t)
		t.Setenv("MAX_DEVICES_PER_SUBJECT", tc.env)
		c, err := Load()
		if (err != nil) != tc.wantErr {
			t.Errorf("MAX_DEVICES_PER_SUBJECT=%q: err = %v, want error %v", tc.env, err, tc.wantErr)
			continue
		}
		if err == nil && c.MaxDevicesPerSubject != tc.want {
			t.Errorf("MAX_DEVICES_PER_SUBJECT=%q: %d, want %d", tc.env, c.MaxDevicesPerSubject, tc.want)
		}
	}
}
