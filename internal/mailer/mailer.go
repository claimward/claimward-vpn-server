// Package mailer sends tenant-invitation emails through a plain SMTP relay,
// typically a local Postfix smarthost listening on 127.0.0.1:25. It speaks
// plaintext SMTP and deliberately does not attempt STARTTLS or auth: the target
// is a trusted loopback MTA that relays onward (and negotiates TLS) upstream.
// This avoids net/smtp.SendMail's automatic STARTTLS, which fails against a
// loopback MTA presenting a self-signed certificate.
//
// The relay address, sender, and the subject/body templates are all resolved at
// send time from a provider, so they can be edited from the admin UI without a
// restart.
package mailer

import (
	"log/slog"
	"net/smtp"
	"strings"
	"text/template"
	"time"
)

// DefaultSubject and DefaultBody are the built-in invitation templates, used
// when the corresponding setting is left blank. Both are text/template sources
// rendered against Data.
const (
	DefaultSubject = `You've been invited to the {{.TenantName}} VPN`
	DefaultBody    = `Hello,

You have been granted access to the Claimward VPN tenant "{{.TenantName}}".
Sign in with this email address ({{.Email}}) in the Claimward app to connect.
{{if .PortalURL}}
Get started: {{.PortalURL}}
{{end}}
— Claimward VPN
`
)

// Settings is the send-time configuration the mailer resolves from its provider.
type Settings struct {
	SMTPAddr string // relay host:port
	From     string // From header / envelope sender; "" disables sending
	Subject  string // subject template; "" uses DefaultSubject
	Body     string // body template; "" uses DefaultBody
}

// Data is the template context passed to the subject/body templates.
type Data struct {
	Email      string
	TenantName string
	TenantID   string
	PortalURL  string
}

// Mailer sends invitation emails. A nil *Mailer is disabled.
type Mailer struct {
	get       func() Settings
	portalURL string
	log       *slog.Logger
	now       func() time.Time // injectable clock for tests
}

// New builds a Mailer. get resolves the current settings at send time; portalURL
// (optional) is exposed to templates as {{.PortalURL}}.
func New(get func() Settings, portalURL string, log *slog.Logger) *Mailer {
	return &Mailer{get: get, portalURL: portalURL, log: log, now: time.Now}
}

// Addr returns the currently-configured relay address (for the admin UI).
func (m *Mailer) Addr() string {
	if m == nil || m.get == nil {
		return ""
	}
	return m.get().SMTPAddr
}

// Enabled reports whether invite emails can be sent (relay addr and sender both
// set).
func (m *Mailer) Enabled() bool {
	if m == nil || m.get == nil {
		return false
	}
	s := m.get()
	return strings.TrimSpace(s.SMTPAddr) != "" && strings.TrimSpace(s.From) != ""
}

// ValidateTemplates reports whether the given subject/body parse as templates.
// Empty strings are valid (they fall back to the defaults).
func ValidateTemplates(subject, body string) error {
	if _, err := template.New("subject").Parse(subject); err != nil {
		return err
	}
	_, err := template.New("body").Parse(body)
	return err
}

// SendInvite emails one newly-invited member. It is safe to call in a goroutine:
// it logs its own outcome and never panics. No-op when the mailer is disabled.
func (m *Mailer) SendInvite(to, tenantName, tenantID string) {
	if !m.Enabled() {
		return
	}
	s := m.get()
	from := strings.TrimSpace(s.From)
	display := tenantName
	if strings.TrimSpace(display) == "" {
		display = tenantID
	}
	data := Data{Email: to, TenantName: display, TenantID: tenantID, PortalURL: m.portalURL}

	subjTmpl := firstNonEmpty(s.Subject, DefaultSubject)
	bodyTmpl := firstNonEmpty(s.Body, DefaultBody)
	subject, err := render("subject", subjTmpl, data)
	if err != nil {
		m.log.Error("invite subject render failed", "to", to, "tenant", tenantID, "err", err)
		return
	}
	body, err := render("body", bodyTmpl, data)
	if err != nil {
		m.log.Error("invite body render failed", "to", to, "tenant", tenantID, "err", err)
		return
	}

	msg := m.message(from, to, strings.TrimSpace(subject), body)
	if err := m.send(s.SMTPAddr, from, to, msg); err != nil {
		m.log.Error("invite email failed", "to", to, "tenant", tenantID, "err", err)
		return
	}
	m.log.Info("invite email sent", "to", to, "tenant", tenantID)
}

func render(name, tmpl string, data Data) (string, error) {
	t, err := template.New(name).Parse(tmpl)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	if err := t.Execute(&b, data); err != nil {
		return "", err
	}
	return b.String(), nil
}

// message builds the RFC 5322 message bytes with CRLF line endings.
func (m *Mailer) message(from, to, subject, body string) []byte {
	var b strings.Builder
	b.WriteString("From: " + from + "\n")
	b.WriteString("To: " + to + "\n")
	b.WriteString("Subject: " + subject + "\n")
	b.WriteString("Date: " + m.now().Format(time.RFC1123Z) + "\n")
	b.WriteString("MIME-Version: 1.0\n")
	b.WriteString("Content-Type: text/plain; charset=UTF-8\n")
	b.WriteString("\n")
	b.WriteString(body)
	return []byte(normalizeCRLF(b.String()))
}

// normalizeCRLF converts any \r\n or lone \n to canonical CRLF, so admin-edited
// templates (which use \n) produce SMTP-correct line endings.
func normalizeCRLF(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	return strings.ReplaceAll(s, "\n", "\r\n")
}

// send drives a plaintext SMTP transaction against the loopback MTA, skipping
// STARTTLS on purpose (see the package comment).
func (m *Mailer) send(addr, from, to string, msg []byte) error {
	c, err := smtp.Dial(addr)
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.Hello("localhost"); err != nil {
		return err
	}
	if err := c.Mail(envelopeAddr(from)); err != nil {
		return err
	}
	if err := c.Rcpt(to); err != nil {
		return err
	}
	wc, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := wc.Write(msg); err != nil {
		_ = wc.Close()
		return err
	}
	if err := wc.Close(); err != nil {
		return err
	}
	return c.Quit()
}

// envelopeAddr extracts the bare address from a "Display Name <addr@host>" From,
// or returns the input unchanged if it is already bare.
func envelopeAddr(from string) string {
	if i := strings.LastIndex(from, "<"); i >= 0 {
		if j := strings.Index(from[i:], ">"); j > 0 {
			return strings.TrimSpace(from[i+1 : i+j])
		}
	}
	return strings.TrimSpace(from)
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}
