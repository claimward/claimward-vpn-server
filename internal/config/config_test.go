package config

import "testing"

// baseEnv is the least environment Load accepts with the OIDC provider, so
// the tests below vary one setting at a time.
func baseEnv(t *testing.T) {
	t.Helper()
	t.Setenv("WG_ENDPOINT", "vpn.example.org:51820")
	t.Setenv("WG_PRIVATE_KEY", "c2VydmVy")
	t.Setenv("WG_PRIVATE_KEY_FILE", "")
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
