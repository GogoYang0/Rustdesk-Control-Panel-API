// Package mail delivers transactional email. Production deployments use the
// SMTP implementation; development and tests use the Dev writer or a fake.
package mail

import "context"

// Message is one outgoing email. TextBody is always required; HTMLBody is
// optional and, when present, is attached as a multipart/alternative part.
type Message struct {
	To       []string
	Subject  string
	TextBody string
	HTMLBody string
}

// Mailer sends one message at a time; implementations must be safe for
// concurrent use and must not panic on empty recipients (callers validate).
type Mailer interface {
	Send(ctx context.Context, msg Message) error
}
