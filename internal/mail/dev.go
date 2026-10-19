package mail

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"
)

// Dev is the development Mailer: instead of a real delivery it renders each
// message to the given writer (stdout in devMode, a buffer in tests). A nil
// writer discards messages.
type Dev struct {
	mu sync.Mutex
	w  io.Writer
}

// NewDev builds the development Mailer.
func NewDev(w io.Writer) *Dev { return &Dev{w: w} }

// Send renders the message; it never fails.
func (d *Dev) Send(_ context.Context, msg Message) error {
	if d.w == nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	recipients := "none"
	if len(msg.To) > 0 {
		recipients = joinAddresses(msg.To)
	}
	_, err := fmt.Fprintf(d.w, "[mail %s] to=%s subject=%q\n%s\n",
		time.Now().Format(time.RFC3339), recipients, msg.Subject, msg.TextBody)
	return err
}
