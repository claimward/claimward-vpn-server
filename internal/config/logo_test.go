package config

import (
	"errors"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// A directory opens but cannot be read: the start stops, it does not drop the
// logo.
func TestADirectoryAsLogoStopsTheStart(t *testing.T) {
	baseEnv(t)
	t.Setenv("SERVER_LOGO_FILE", t.TempDir())
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "SERVER_LOGO_FILE") || strings.Contains(err.Error(), "refused") {
		t.Errorf("a directory as logo must fail at the read, not at the validation: %v", err)
	}
}

func TestAMissingLogoSaysSoAtTheOpen(t *testing.T) {
	baseEnv(t)
	t.Setenv("SERVER_LOGO_FILE", filepath.Join(t.TempDir(), "absent.svg"))
	if _, err := Load(); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a missing logo: %v", err)
	}
}

func TestThePeerListIntervalMustBePositive(t *testing.T) {
	for _, v := range []string{"0s", "-5s"} {
		baseEnv(t)
		t.Setenv("GOAUTHN_PEER_LIST_INTERVAL", v)
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "GOAUTHN_PEER_LIST_INTERVAL") {
			t.Errorf("%q: %v", v, err)
		}
	}
	baseEnv(t)
	t.Setenv("GOAUTHN_PEER_LIST_INTERVAL", "5s")
	if _, err := Load(); err != nil {
		t.Errorf("5s: %v", err)
	}
}
