// Package audit records security-relevant actions.
package audit

import "context"

// Entry describes one auditable action.
type Entry struct {
	OrganizationID uint
	ActorUserID    uint
	Action         string
	TargetType     string
	TargetID       string
	Detail         map[string]any
}

// Auditor records audit entries. The GORM implementation arrives with the
// audit log task; until then a no-op implementation is wired in.
type Auditor interface {
	Record(ctx context.Context, entry Entry) error
}

// Nop discards every entry. It keeps the middleware chain in place before the
// persistent auditor is installed.
type Nop struct{}

// Record implements Auditor.
func (Nop) Record(context.Context, Entry) error { return nil }
