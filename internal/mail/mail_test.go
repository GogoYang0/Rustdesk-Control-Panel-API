package mail

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"strings"
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

// fakeConn records Send attempts; the first n fail with a transient error.
type fakeConn struct {
	failures int
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
	s.dial = func(addr string) (conn, error) {
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
	s.dial = func(addr string) (conn, error) {
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
	s.dial = func(addr string) (conn, error) {
		return nil, errors.New("connection refused")
	}
	s.retryBase = time.Millisecond

	err := s.Send(context.Background(), Message{
		To: []string{"to@example.com"}, Subject: "s", TextBody: "b",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "connection refused")
}
