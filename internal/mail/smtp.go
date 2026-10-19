package mail

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/smtp"
	"strings"
	"time"
)

const (
	maxAttempts  = 3
	addrFmt      = "%s:%d"
	submissionPt = 587
)

// conn abstracts an SMTP client session for test injection.
type conn interface {
	Mail(from string) error
	Rcpt(to string) error
	Data(r io.Reader) error
	Quit() error
	Close() error
}

// SMTPConfig carries the SMTP server settings; the password never comes from
// the config file (viper binds it to PANEL_SMTP_PASSWORD only).
type SMTPConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
}

// SMTP delivers mail over SMTP with STARTTLS (implicit TLS on port 465) and
// up to three attempts with exponential backoff on transient failures.
type SMTP struct {
	cfg       SMTPConfig
	dial      func(addr string) (conn, error)
	retryBase time.Duration
}

// NewSMTP builds the SMTP Mailer with the real dialer.
func NewSMTP(cfg SMTPConfig) *SMTP {
	s := &SMTP{cfg: cfg, retryBase: 500 * time.Millisecond}
	s.dial = func(addr string) (conn, error) {
		return dialSMTP(addr, cfg)
	}
	return s
}

// dialSMTP connects, upgrades to TLS and authenticates as needed.
func dialSMTP(addr string, cfg SMTPConfig) (conn, error) {
	if cfg.Port == 465 {
		d := &net.Dialer{Timeout: 10 * time.Second}
		c, err := tls.DialWithDialer(d, "tcp", addr, &tls.Config{ServerName: cfg.Host})
		if err != nil {
			return nil, err
		}
		cl, err := smtp.NewClient(c, cfg.Host)
		if err != nil {
			_ = c.Close()
			return nil, err
		}
		return clientConn{cl: cl}, nil
	}

	c, err := smtp.Dial(addr)
	if err != nil {
		return nil, err
	}
	wrapped, err := clientConn{cl: c}.startTLSIfPossible(cfg.Host)
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	if cfg.Username != "" {
		auth := smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)
		if err := wrapped.Auth(auth); err != nil {
			_ = wrapped.Quit()
			return nil, fmt.Errorf("smtp auth: %w", err)
		}
	}
	return wrapped, nil
}

// Send delivers the message with up to maxAttempts tries separated by
// exponential backoff; every attempt dials a fresh connection and closes it.
func (s *SMTP) Send(_ context.Context, msg Message) error {
	addr := fmt.Sprintf(addrFmt, s.cfg.Host, s.cfg.Port)
	raw, err := buildMessage(s.cfg.From, msg)
	if err != nil {
		return err
	}

	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			time.Sleep(s.retryBase << (attempt - 1))
		}
		c, derr := s.dial(addr)
		if derr != nil {
			lastErr = derr
			continue
		}
		serr := deliver(c, s.cfg.From, msg.To, raw)
		_ = c.Quit()
		_ = c.Close()
		if serr == nil {
			return nil
		}
		lastErr = serr
	}
	return fmt.Errorf("smtp send after %d attempts: %w", maxAttempts, lastErr)
}

// deliver performs the MAIL FROM / RCPT TO / DATA sequence.
func deliver(c conn, from string, to []string, raw []byte) error {
	if err := c.Mail(from); err != nil {
		return fmt.Errorf("mail from: %w", err)
	}
	for _, rcpt := range to {
		if err := c.Rcpt(rcpt); err != nil {
			return fmt.Errorf("rcpt to %s: %w", rcpt, err)
		}
	}
	if err := c.Data(bytes.NewReader(raw)); err != nil {
		return fmt.Errorf("data: %w", err)
	}
	return nil
}

// joinAddresses renders the To header value.
func joinAddresses(to []string) string {
	return strings.Join(to, ", ")
}
