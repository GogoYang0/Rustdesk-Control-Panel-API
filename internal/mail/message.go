package mail

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"mime"
	"strings"
	"time"
)

// buildMessage renders an RFC 5322 message. Bodies are base64-encoded so
// non-ASCII content (e.g. Chinese invitation text) survives any hop; the
// Subject uses the Q-encoding for the same reason.
func buildMessage(from string, msg Message) ([]byte, error) {
	if from == "" {
		return nil, errors.New("mail: empty From address")
	}
	if len(msg.To) == 0 {
		return nil, errors.New("mail: no recipients")
	}
	if strings.TrimSpace(msg.Subject) == "" {
		return nil, errors.New("mail: empty subject")
	}

	var b bytes.Buffer
	writeHeader := func(k, v string) {
		fmt.Fprintf(&b, "%s: %s\r\n", k, v)
	}
	writeHeader("From", from)
	writeHeader("To", joinAddresses(msg.To))
	writeHeader("Subject", mime.QEncoding.Encode("utf-8", msg.Subject))
	writeHeader("Date", time.Now().Format(time.RFC1123Z))
	writeHeader("Message-ID", fmt.Sprintf("<%d@mail.rustdesk-panel>", time.Now().UnixNano()))
	writeHeader("MIME-Version", "1.0")

	if msg.HTMLBody == "" {
		writeHeader("Content-Type", `text/plain; charset="utf-8"`)
		writeHeader("Content-Transfer-Encoding", "base64")
		b.WriteString("\r\n")
		writeBase64Body(&b, msg.TextBody)
		return b.Bytes(), nil
	}

	boundary := fmt.Sprintf("=_panel_%d", time.Now().UnixNano())
	writeHeader("Content-Type", fmt.Sprintf(`multipart/alternative; boundary="%s"`, boundary))
	b.WriteString("\r\n")

	writePart := func(contentType string, body string) {
		fmt.Fprintf(&b, "--%s\r\n", boundary)
		fmt.Fprintf(&b, "Content-Type: %s; charset=\"utf-8\"\r\n", contentType)
		b.WriteString("Content-Transfer-Encoding: base64\r\n\r\n")
		writeBase64Body(&b, body)
		b.WriteString("\r\n")
	}
	writePart("text/plain", msg.TextBody)
	writePart("text/html", msg.HTMLBody)
	fmt.Fprintf(&b, "--%s--\r\n", boundary)
	return b.Bytes(), nil
}

// writeBase64Body emits body wrapped at 76 characters per RFC 2045.
func writeBase64Body(b *bytes.Buffer, body string) {
	enc := base64.StdEncoding.EncodeToString([]byte(body))
	for len(enc) > 76 {
		b.WriteString(enc[:76])
		b.WriteString("\r\n")
		enc = enc[76:]
	}
	b.WriteString(enc)
	b.WriteString("\r\n")
}
