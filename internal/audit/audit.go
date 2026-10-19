// Package audit records security-relevant actions.
package audit

import (
	"context"

	"gorm.io/gorm"
)

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

// TxRecorder records an audit entry on the caller's transaction, so the
// entity change and its audit trail commit or roll back together (#19).
// Implementations must run the sequence allocation on the given tx; a
// duplicate-key collision aborts that transaction, and the outer entity
// retry strategy decides whether to re-run it.
type TxRecorder interface {
	RecordTx(tx *gorm.DB, entry Entry) error
}

// Nop discards every entry. It keeps the middleware chain in place before the
// persistent auditor is installed.
type Nop struct{}

// Record implements Auditor.
func (Nop) Record(context.Context, Entry) error { return nil }
