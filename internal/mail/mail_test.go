package mail

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/textproto"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestDev_Send_WritesToWriter(t *testing.T) {
	var buf bytes.Buffer
	dev := NewDev(&buf)

	err := dev.Send(context.Background(), Message{
		To:       []string{"a@example.com", "b@example.com"},
		Subject:  "verify your email",
		TextBody: "hello",
		HTMLBody: "<b>hello</b>",
	})
	require.NoError(t, err)

	out := buf.String()
	require.Contains(t, out, "a@example.com")
	require.Contains(t, out, "b@example.com")
	require.Contains(t, out, "verify your email")
	require.Contains(t, out, "hello")
}

func TestDev_Send_NilWriterIsSafe(t *testing.T) {
	dev := NewDev(nil)
	err := dev.Send(context.Background(), Message{To: []string{"x@example.com"}, Subject: "s"})
	require.NoError(t, err)
}

// buildMessage must produce RFC 5322 headers and a MIME body without any
// network activity.
func TestSMTP_BuildMessage_Headers(t *testing.T) {
	msg := Message{
		To:       []string{"to1@example.com", "to2@example.com"},
		Subject:  "invite & verify",
		TextBody: "plain text",
		HTMLBody: "<p>rich</p>",
	}
	raw, err := buildMessage("panel@example.com", msg)
	require.NoError(t, err)

	s := string(raw)
	require.Contains(t, s, "From: panel@example.com\r\n")
	require.Contains(t, s, "To: to1@example.com, to2@example.com\r\n")
	require.Contains(t, s, "Subject: invite & verify\r\n")
	require.Contains(t, s, "MIME-Version: 1.0\r\n")
	require.Contains(t, s, "multipart/alternative")
	// Bodies are base64-encoded (RFC 2045); decode them to assert content.
	bodies := decodedBodies(t, s)
	require.Contains(t, bodies, "plain text")
	require.Contains(t, bodies, "<p>rich</p>")
}

// A text-only message must not carry an HTML part.
// decodedBodies concatenates every base64-encoded body line in the message.
func decodedBodies(t *testing.T, raw string) string {
	t.Helper()
	var out bytes.Buffer
	for _, line := range strings.Split(raw, "\r\n") {
		if line == "" || strings.Contains(line, ":") || strings.HasPrefix(line, "--") {
			continue
		}
		dec, err := base64.StdEncoding.DecodeString(line)
		require.NoError(t, err, "line %q must be valid base64", line)
		out.Write(dec)
	}
	return out.String()
}

func TestSMTP_BuildMessage_TextOnly(t *testing.T) {
	raw, err := buildMessage("panel@example.com", Message{
		To: []string{"x@example.com"}, Subject: "s", TextBody: "body",
	})
	require.NoError(t, err)
	require.NotContains(t, string(raw), "multipart/alternative")
	require.Contains(t, string(raw), "text/plain")
}

// fakeConn records Send attempts; the first n attempts fail with the
// configured error (a generic transient error by default).
type fakeConn struct {
	failures int
	smtpErr  error
	sent     [][]string
	closed   bool
}

func (f *fakeConn) Mail(from string) error { return nil }
func (f *fakeConn) Rcpt(to string) error   { return nil }
func (f *fakeConn) Quit() error            { return nil }
func (f *fakeConn) Close() error           { f.closed = true; return nil }

func (f *fakeConn) Data(r io.Reader) error {
	b, _ := io.ReadAll(r)
	f.sent = append(f.sent, []string{string(b)})
	if len(f.sent) <= f.failures {
		if f.smtpErr != nil {
			return f.smtpErr
		}
		return errors.New("transient smtp error")
	}
	return nil
}

func TestSMTP_Retry_OnTransientError(t *testing.T) {
	fc := &fakeConn{failures: 2}
	dials := 0
	s := NewSMTP(SMTPConfig{
		Host: "smtp.example.com", Port: 587,
		Username: "u", Password: "p", From: "panel@example.com",
	})
	s.dial = func(_ context.Context, addr string) (conn, error) {
		dials++
		return fc, nil
	}
	s.retryBase = time.Millisecond

	err := s.Send(context.Background(), Message{
		To: []string{"to@example.com"}, Subject: "s", TextBody: "b",
	})
	require.NoError(t, err)
	require.Equal(t, 3, dials, "two transient failures then one success")
	require.Len(t, fc.sent, 3)
	require.True(t, fc.closed, "connection must be closed on every attempt")
}

func TestSMTP_Retry_Exhausted(t *testing.T) {
	fc := &fakeConn{failures: 100}
	dials := 0
	s := NewSMTP(SMTPConfig{Host: "h", Port: 1, From: "f@example.com"})
	s.dial = func(_ context.Context, addr string) (conn, error) {
		dials++
		return fc, nil
	}
	s.retryBase = time.Millisecond

	err := s.Send(context.Background(), Message{
		To: []string{"to@example.com"}, Subject: "s", TextBody: "b",
	})
	require.Error(t, err)
	require.Equal(t, 3, dials, "exactly three attempts")
	require.True(t, strings.Contains(err.Error(), "transient"))
}

func TestSMTP_DialError_Propagates(t *testing.T) {
	s := NewSMTP(SMTPConfig{Host: "h", Port: 1, From: "f@example.com"})
	s.dial = func(_ context.Context, addr string) (conn, error) {
		return nil, errors.New("connection refused")
	}
	s.retryBase = time.Millisecond

	err := s.Send(context.Background(), Message{
		To: []string{"to@example.com"}, Subject: "s", TextBody: "b",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "connection refused")
}

// Review round 2: the Dev writer must be safe for concurrent Send calls.
func TestDev_ConcurrentWritesAreSerialized(t *testing.T) {
	var buf bytes.Buffer
	dev := NewDev(&buf)

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			require.NoError(t, dev.Send(context.Background(), Message{
				To:       []string{"u@example.com"},
				Subject:  "s",
				TextBody: fmt.Sprintf("line-%d", n),
			}))
		}(i)
	}
	wg.Wait()

	out := buf.String()
	for i := 0; i < 32; i++ {
		require.Contains(t, out, fmt.Sprintf("line-%d\n", i), "line %d must be intact", i)
	}
	require.Equal(t, 32, strings.Count(out, "[mail "), "each message must be one block")
}

// fakeSMTP is a minimal SMTP server over plain TCP for dialSMTP integration
// tests. It speaks EHLO/STARTTLS/AUTH/MAIL/RCPT/DATA/QUIT.
type fakeSMTP struct {
	t        *testing.T
	listener net.Listener
	offerTLS bool
	// dropFinalReply simulates a connection loss right after the body was
	// handed over: the client can never confirm the final DATA reply.
	dropFinalReply bool
	certs          []tls.Certificate
	roots          *x509.CertPool
	mu             sync.Mutex
	gotAuth        bool
	gotMail        string
	gotBody        string
}

func newFakeSMTP(t *testing.T, offerTLS bool) (*fakeSMTP, *x509.CertPool) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	f := &fakeSMTP{t: t, listener: l, offerTLS: offerTLS}
	f.certs, f.roots = f.buildCerts()
	go f.serve()
	t.Cleanup(func() { _ = l.Close() })
	return f, f.roots
}

func (f *fakeSMTP) addr() string { return f.listener.Addr().String() }

// The server goroutine must never call require.*: a failed assert there
// would deadlock the test instead of failing it. I/O errors simply end the
// connection (the client may abort mid-session during negative tests).
func (f *fakeSMTP) w(c net.Conn, s string) {
	_, _ = c.Write([]byte(s + "\r\n"))
}

func (f *fakeSMTP) r(c net.Conn) (string, bool) {
	buf := make([]byte, 4096)
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := c.Read(buf)
	if err != nil {
		return "", false
	}
	return string(buf[:n]), true
}

func (f *fakeSMTP) serve() {
	for {
		c, err := f.listener.Accept()
		if err != nil {
			return
		}
		go f.handle(c)
	}
}

func (f *fakeSMTP) handle(c net.Conn) {
	defer func() { _ = c.Close() }()
	f.w(c, "220 fake ready")
	for {
		line, ok := f.r(c)
		if !ok {
			return
		}
		switch {
		case strings.HasPrefix(line, "EHLO"):
			if f.offerTLS {
				f.w(c, "250-fake\r\n250-STARTTLS\r\n250-AUTH PLAIN\r\n250 OK")
			} else {
				f.w(c, "250-fake\r\n250 OK")
			}
		case strings.HasPrefix(line, "STARTTLS"):
			f.w(c, "220 ready for TLS")
			tlsConn := tls.Server(c, &tls.Config{Certificates: f.certs})
			if err := tlsConn.Handshake(); err != nil {
				return
			}
			c = tlsConn
		case strings.HasPrefix(line, "AUTH"):
			f.mu.Lock()
			f.gotAuth = true
			f.mu.Unlock()
			f.w(c, "235 ok")
		case strings.HasPrefix(line, "MAIL FROM"):
			f.mu.Lock()
			f.gotMail = line
			f.mu.Unlock()
			f.w(c, "250 ok")
		case strings.HasPrefix(line, "RCPT TO"):
			f.w(c, "250 ok")
		case strings.HasPrefix(line, "DATA"):
			f.w(c, "354 go")
			body := f.readBody(c)
			f.mu.Lock()
			f.gotBody = body
			f.mu.Unlock()
			if f.dropFinalReply {
				// The body arrived, but the final reply is never sent: from
				// the client's perspective the delivery outcome is unknown.
				return
			}
			f.w(c, "250 queued")
		case strings.HasPrefix(line, "QUIT"):
			f.w(c, "221 bye")
			return
		default:
			f.w(c, "500 nope")
		}
	}
}

// certs builds a throwaway self-signed certificate; the matching DER is
// kept so the test can pin it as the client's root.
func (f *fakeSMTP) buildCerts() ([]tls.Certificate, *x509.CertPool) {
	f.t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(f.t, err)
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"127.0.0.1"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	require.NoError(f.t, err)
	roots := x509.NewCertPool()
	roots.AddCert(mustCert(f.t, der))
	return []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, roots
}

func mustCert(t *testing.T, der []byte) *x509.Certificate {
	t.Helper()
	c, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return c
}

func (f *fakeSMTP) readBody(c net.Conn) string {
	var b strings.Builder
	buf := make([]byte, 2048)
	for {
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := c.Read(buf)
		b.Write(buf[:n])
		if err != nil || strings.HasSuffix(b.String(), "\r\n.\r\n") {
			return b.String()
		}
	}
}

// Without STARTTLS the dialer must refuse to send over plaintext.
func TestSMTP_Dial_RefusesPlaintext(t *testing.T) {
	f, _ := newFakeSMTP(t, false)
	s := NewSMTP(SMTPConfig{Host: "127.0.0.1", Port: portOf(f.addr()), From: "f@example.com"})

	err := s.Send(context.Background(), Message{
		To: []string{"to@example.com"}, Subject: "s", TextBody: "b",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "STARTTLS")
	f.mu.Lock()
	defer f.mu.Unlock()
	require.Empty(t, f.gotBody, "no mail body may cross a plaintext connection")
}

// With STARTTLS the full flow — including auth when configured — succeeds.
func TestSMTP_Dial_StartTLSAndAuth(t *testing.T) {
	f, roots := newFakeSMTP(t, true)
	s := NewSMTP(SMTPConfig{
		Host: "127.0.0.1", Port: portOf(f.addr()),
		Username: "user", Password: "pass", From: "f@example.com",
		tlsRoots: roots,
	})
	s.retryBase = time.Millisecond

	err := s.Send(context.Background(), Message{
		To: []string{"to@example.com"}, Subject: "s", TextBody: "b",
	})
	require.NoError(t, err)
	f.mu.Lock()
	defer f.mu.Unlock()
	require.True(t, f.gotAuth, "configured credentials must authenticate")
	require.Contains(t, f.gotMail, "f@example.com")
	// Bodies travel base64-encoded: assert the encoded form, a bare "b"
	// would spuriously match the "base64" header text.
	require.Contains(t, f.gotBody, base64.StdEncoding.EncodeToString([]byte("b")))
}

func portOf(addr string) int {
	_, p, _ := net.SplitHostPort(addr)
	n, _ := strconv.Atoi(p)
	return n
}

// A cancelled context must fail fast instead of dialing.
func TestSMTP_Send_RespectsContext(t *testing.T) {
	s := NewSMTP(SMTPConfig{Host: "h", Port: 1, From: "f@example.com"})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := s.Send(ctx, Message{
		To: []string{"to@example.com"}, Subject: "s", TextBody: "b",
	})
	require.ErrorIs(t, err, context.Canceled)
}

// Review round 3: 5xx SMTP replies are permanent — retrying them only
// delays the failure and can trip provider rate limits. A 535 on AUTH must
// surface immediately instead of being retried.
func TestSMTP_NoRetry_OnPermanentError(t *testing.T) {
	fc := &fakeConn{failures: 100, smtpErr: &textproto.Error{Code: 535, Msg: "authentication failed"}}
	dials := 0
	s := NewSMTP(SMTPConfig{Host: "h", Port: 1, From: "f@example.com"})
	s.dial = func(_ context.Context, addr string) (conn, error) {
		dials++
		return fc, nil
	}
	s.retryBase = time.Millisecond

	err := s.Send(context.Background(), Message{
		To: []string{"to@example.com"}, Subject: "s", TextBody: "b",
	})
	require.Error(t, err)
	require.Equal(t, 1, dials, "a 5xx reply must not be retried")
	var tpErr *textproto.Error
	require.ErrorAs(t, err, &tpErr)
	require.Equal(t, 535, tpErr.Code)
}

// 4xx replies stay transient and keep the retry behaviour.
func TestSMTP_Retry_OnTemporaryError(t *testing.T) {
	fc := &fakeConn{failures: 1, smtpErr: &textproto.Error{Code: 451, Msg: "try again later"}}
	s := NewSMTP(SMTPConfig{Host: "h", Port: 1, From: "f@example.com"})
	s.dial = func(_ context.Context, addr string) (conn, error) {
		return fc, nil
	}
	s.retryBase = time.Millisecond

	err := s.Send(context.Background(), Message{
		To: []string{"to@example.com"}, Subject: "s", TextBody: "b",
	})
	require.NoError(t, err, "a 4xx reply is transient and must be retried")
	require.Len(t, fc.sent, 2)
}

// When the body was handed over but the final DATA reply is lost, the
// delivery outcome is unknown: the error must wrap ErrDeliveryAccepted so
// callers do not treat the message as definitely lost (e.g. by deleting
// one-time tokens the mail may still deliver).
func TestSMTP_Send_UnconfirmedDelivery_WrapsSentinel(t *testing.T) {
	f, roots := newFakeSMTP(t, true)
	f.dropFinalReply = true
	s := NewSMTP(SMTPConfig{
		Host: "127.0.0.1", Port: portOf(f.addr()),
		Username: "user", Password: "pass", From: "f@example.com",
		tlsRoots: roots,
	})
	s.retryBase = time.Millisecond

	err := s.Send(context.Background(), Message{
		To: []string{"to@example.com"}, Subject: "s", TextBody: "b",
	})
	require.Error(t, err)
	require.ErrorIs(t, err, ErrDeliveryAccepted, "an unconfirmed final reply must be recognisable")
	f.mu.Lock()
	defer f.mu.Unlock()
	require.NotEmpty(t, f.gotBody, "the body did reach the server")
}
