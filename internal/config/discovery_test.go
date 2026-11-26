package config

import (
	"strings"
	"testing"
)

// SERVER_NAME is optional, with no invented default; SERVER_EXCLUSIVE defaults
// to false.
func TestDiscoveryDefaults(t *testing.T) {
	githubEnv(t, "acme")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.ServerName != "" || c.Exclusive {
		t.Errorf("name = %q, exclusive = %v; want none, false", c.ServerName, c.Exclusive)
	}
}

func TestDiscoveryValues(t *testing.T) {
	githubEnv(t, "acme")
	t.Setenv("SERVER_NAME", "  Lab network ")
	t.Setenv("SERVER_EXCLUSIVE", "true")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.ServerName != "Lab network" || !c.Exclusive {
		t.Errorf("name = %q, exclusive = %v", c.ServerName, c.Exclusive)
	}
}

// ⛔ A typo in a safety flag must not silently read as "not exclusive".
func TestExclusiveRefusesWhatItCannotRead(t *testing.T) {
	githubEnv(t, "acme")
	t.Setenv("SERVER_EXCLUSIVE", "ture")
	refuses(t, "SERVER_EXCLUSIVE")
}

// The name is shown to people by clients: no control characters, bounded.
func TestServerNameRefusesWhatCannotBeShown(t *testing.T) {
	for name, v := range map[string]string{
		"newline": "a\nb",
		"escape":  "a\x1b[31mb",
		"long":    strings.Repeat("x", 101),
	} {
		githubEnv(t, "acme")
		t.Setenv("SERVER_NAME", v)
		t.Run(name, func(t *testing.T) { refuses(t, "SERVER_NAME") })
	}
	githubEnv(t, "acme")
	t.Setenv("SERVER_NAME", strings.Repeat("é", 100))
	if _, err := Load(); err != nil {
		t.Errorf("100 characters refused: %v", err)
	}
}
