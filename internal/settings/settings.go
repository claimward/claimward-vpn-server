// Package settings holds runtime-editable server settings (the invitation-email
// relay, sender, and subject/body templates), persisted to a JSON file so they
// survive restarts and can be changed from the admin WebUI without redeploying.
package settings

import (
	"encoding/json"
	"fmt"
	"net"
	"net/mail"
	"os"
	"strings"
	"sync"
	"text/template"
)

// Settings is the persisted, admin-editable configuration.
type Settings struct {
	// MailFrom is the From header / envelope sender for invite emails, e.g.
	// "Claimward VPN <vpn@example.org>" or a bare address. Empty disables
	// invite emails.
	MailFrom string `json:"mail_from"`
	// SMTPAddr is the relay host:port the server posts invites to (e.g. a local
	// Postfix smarthost at 127.0.0.1:25). Empty disables invite emails.
	SMTPAddr string `json:"smtp_addr"`
	// InviteSubject and InviteBody are text/template sources for the invitation
	// email. Empty falls back to the built-in defaults. Available placeholders:
	// {{.Email}}, {{.TenantName}}, {{.TenantID}}, {{.PortalURL}}.
	InviteSubject string `json:"invite_subject"`
	InviteBody    string `json:"invite_body"`
}

// Store guards the current settings and mirrors changes to a JSON file.
type Store struct {
	mu   sync.RWMutex
	path string
	s    Settings
}

// New creates a Store. When path is non-empty and the file exists, settings are
// loaded from it; otherwise the store is seeded with def (typically derived from
// env config + the built-in templates) and, if path is set, written out.
func New(path string, def Settings) *Store {
	def.MailFrom = strings.TrimSpace(def.MailFrom)
	def.SMTPAddr = strings.TrimSpace(def.SMTPAddr)
	st := &Store{path: path, s: def}
	if path != "" {
		if data, err := os.ReadFile(path); err == nil {
			var loaded Settings
			if json.Unmarshal(data, &loaded) == nil {
				st.s = loaded
				return st
			}
		}
		_ = st.saveLocked() // seed the file from the defaults on first run
	}
	return st
}

// Get returns a copy of the current settings.
func (s *Store) Get() Settings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.s
}

// Update validates and applies new settings, persisting them when a path is set.
func (s *Store) Update(in Settings) (Settings, error) {
	in.MailFrom = strings.TrimSpace(in.MailFrom)
	in.SMTPAddr = strings.TrimSpace(in.SMTPAddr)
	if in.MailFrom != "" {
		if _, err := mail.ParseAddress(in.MailFrom); err != nil {
			return Settings{}, fmt.Errorf("invalid sender address: %w", err)
		}
	}
	if in.SMTPAddr != "" {
		if _, _, err := net.SplitHostPort(in.SMTPAddr); err != nil {
			return Settings{}, fmt.Errorf("invalid SMTP address (want host:port): %w", err)
		}
	}
	if _, err := template.New("subject").Parse(in.InviteSubject); err != nil {
		return Settings{}, fmt.Errorf("invalid subject template: %w", err)
	}
	if _, err := template.New("body").Parse(in.InviteBody); err != nil {
		return Settings{}, fmt.Errorf("invalid body template: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	prev := s.s
	s.s = in
	if err := s.saveLocked(); err != nil {
		s.s = prev // roll back in-memory state if persistence fails
		return Settings{}, err
	}
	return s.s, nil
}

// saveLocked writes settings to the configured file. The caller must hold the
// write lock. No-op when persistence is disabled.
func (s *Store) saveLocked() error {
	if s.path == "" {
		return nil
	}
	data, err := json.MarshalIndent(s.s, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
