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

func TestTunnelMTU(t *testing.T) {
	for _, tc := range []struct {
		env     string
		want    int
		wantErr bool
	}{
		{"", 0, false},
		{"1390", 1390, false},
		{"1280", 1280, false},
		{"1279", 0, true},
		{"9000", 9000, false},
		{"9001", 0, true},
		{"0", 0, true},
		{"-1", 0, true},
		{"1420x", 0, true},
		{" 1420", 0, true},
		{"1.5e3", 0, true},
	} {
		baseEnv(t)
		t.Setenv("TUNNEL_MTU", tc.env)
		c, err := Load()
		if (err != nil) != tc.wantErr {
			t.Errorf("TUNNEL_MTU=%q: err = %v, want error %v", tc.env, err, tc.wantErr)
			continue
		}
		if err == nil && c.TunnelMTU != tc.want {
			t.Errorf("TUNNEL_MTU=%q: %d, want %d", tc.env, c.TunnelMTU, tc.want)
		}
	}
}

func TestAutoTunnelMTU(t *testing.T) {
	for _, tc := range []struct{ uplink, want int }{
		{0, 1420},    // unknown uplink: WireGuard's default
		{-5, 1420},   // nonsense reads as unknown
		{1500, 1420}, // capped at the default
		{9000, 1420}, // jumbo uplink: still capped
		{1450, 1370}, // 1450 - 80
		{1360, 1280}, // exactly the floor
		{1300, 1280}, // floored
		{576, 1280},  // floored
		{1499, 1419}, // minus 80, below the cap
	} {
		if got := AutoTunnelMTU(tc.uplink); got != tc.want {
			t.Errorf("AutoTunnelMTU(%d) = %d, want %d", tc.uplink, got, tc.want)
		}
	}
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
