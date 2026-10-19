package mail

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/smtp"
	"strings"
	"time"
)

const (
	maxAttempts       = 3
	addrFmt           = "%s:%d"
	defaultSessionTTL = 30 * time.Second
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
// the config file (viper binds it to PANEL_SMTP_PASSWORD only). Timeout
// bounds a whole delivery attempt (dial through QUIT); zero means 30s.
type SMTPConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	Timeout  time.Duration

	// tlsRoots lets tests pin a private CA; production uses the system pool.
	tlsRoots *x509.CertPool
}

// sessionTimeout returns the per-attempt bound.
func (c SMTPConfig) sessionTimeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return defaultSessionTTL
}

// SMTP delivers mail over SMTP with mandatory TLS (STARTTLS upgraded, or
// implicit TLS on port 465) and up to three attempts with exponential
// backoff on transient failures. Each attempt is bounded by the configured
// timeout and honours the caller's context: a cancellation or deadline
// closes the connection mid-session.
type SMTP struct {
	cfg       SMTPConfig
	dial      func(ctx context.Context, addr string) (conn, error)
	retryBase time.Duration
}

// NewSMTP builds the SMTP Mailer with the real dialer.
func NewSMTP(cfg SMTPConfig) *SMTP {
	s := &SMTP{cfg: cfg, retryBase: 500 * time.Millisecond}
	s.dial = func(ctx context.Context, addr string) (conn, error) {
		return dialSMTP(ctx, addr, cfg)
	}
	return s
}

// dialSMTP connects with the context deadline, forces TLS (implicit on 465,
// STARTTLS upgrade otherwise — plaintext is never accepted), and
// authenticates when credentials are configured. A context cancellation
// closes the underlying connection to unblock any in-flight I/O.
func dialSMTP(ctx context.Context, addr string, cfg SMTPConfig) (conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	deadline := ctxDeadline(ctx, cfg.sessionTimeout())
	d := &net.Dialer{Deadline: deadline}

	nc, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	// Bound every subsequent read/write (greeting, TLS, AUTH, DATA).
	_ = nc.SetDeadline(deadline)
	go func() {
		<-ctx.Done()
		_ = nc.Close()
	}()

	if cfg.Port == 465 {
		tc := tls.Client(nc, &tls.Config{ServerName: cfg.Host, MinVersion: tls.VersionTLS12, RootCAs: cfg.tlsRoots})
		cl, err := smtp.NewClient(tc, cfg.Host)
		if err != nil {
			_ = nc.Close()
			return nil, err
		}
		c := clientConn{cl: cl}
		return authenticate(c, cfg)
	}

	cl, err := smtp.NewClient(nc, cfg.Host)
	if err != nil {
		_ = nc.Close()
		return nil, err
	}
	c := clientConn{cl: cl}
	if ok, _ := cl.Extension("STARTTLS"); !ok {
		_ = c.Quit()
		_ = c.Close()
		return nil, errors.New("smtp: server does not offer STARTTLS; refusing to send over plaintext")
	}
	if err := cl.StartTLS(&tls.Config{ServerName: cfg.Host, MinVersion: tls.VersionTLS12, RootCAs: cfg.tlsRoots}); err != nil {
		_ = c.Quit()
		_ = c.Close()
		return nil, fmt.Errorf("starttls: %w", err)
	}
	return authenticate(c, cfg)
}

// authenticate performs PlainAuth when credentials are configured.
func authenticate(c clientConn, cfg SMTPConfig) (clientConn, error) {
	if cfg.Username == "" {
		return c, nil
	}
	auth := smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)
	if err := c.Auth(auth); err != nil {
		_ = c.Quit()
		_ = c.Close()
		return clientConn{}, fmt.Errorf("smtp auth: %w", err)
	}
	return c, nil
}

// ctxDeadline returns the earlier of the context deadline and now+timeout.
func ctxDeadline(ctx context.Context, timeout time.Duration) time.Time {
	dl := time.Now().Add(timeout)
	if cd, ok := ctx.Deadline(); ok && cd.Before(dl) {
		return cd
	}
	return dl
}

// Send delivers the message with up to maxAttempts tries separated by
// exponential backoff; every attempt dials a fresh connection and closes it.
func (s *SMTP) Send(ctx context.Context, msg Message) error {
	addr := fmt.Sprintf(addrFmt, s.cfg.Host, s.cfg.Port)
	raw, err := buildMessage(s.cfg.From, msg)
	if err != nil {
		return err
	}

	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			// Back off, but bail out immediately when the caller is done.
			timer := time.NewTimer(s.retryBase << (attempt - 1))
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
		attemptCtx, cancel := context.WithTimeout(ctx, s.cfg.sessionTimeout())
		c, derr := s.dial(attemptCtx, addr)
		if derr != nil {
			cancel()
			lastErr = derr
			continue
		}
		serr := deliver(c, s.cfg.From, msg.To, raw)
		_ = c.Quit()
		_ = c.Close()
		cancel() // releases the connection watcher goroutine
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
