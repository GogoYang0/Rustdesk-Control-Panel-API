package audit

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// SystemActionPrefix marks entries written by background workers. RecordSystem
// accepts only actions with this prefix, so request-scoped code cannot use it
// to bypass the org-0 fail-closed behaviour of Record.
const SystemActionPrefix = "worker."

// RecordSystem persists a system-scoped audit entry for a background worker.
//
// Background work has no tenant (no request context), so these entries live in
// the organization 0 partition with their own continuous sequence, separate
// from the per-organization sequences used by request-scoped entries. The
// organization row cannot be locked to serialise allocation (it does not
// exist), so concurrent writers rely on the unique (organization_id, seq)
// index and the retry loop below — the same collision contract Record uses.
func (a *GormAuditor) RecordSystem(ctx context.Context, entry Entry) error {
	if entry.OrganizationID != 0 {
		return errors.New("audit: system entries must not carry an organization")
	}
	if !strings.HasPrefix(entry.Action, SystemActionPrefix) {
		return fmt.Errorf("audit: system entries must use the %q action prefix", SystemActionPrefix)
	}

	detail, err := detailJSON(entry)
	if err != nil {
		return err
	}

	var lastErr error
	for attempt := 0; attempt < maxSeqAttempts; attempt++ {
		err := a.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			return insertSystemAuditRow(tx, entry, detail)
		})
		if err == nil {
			return nil
		}
		lastErr = err
		if !errors.Is(err, gorm.ErrDuplicatedKey) {
			return fmt.Errorf("record system audit entry: %w", err)
		}
	}
	return fmt.Errorf("record system audit entry after %d attempts: %w", maxSeqAttempts, lastErr)
}

// insertSystemAuditRow allocates the next global sequence and inserts the
// entry. The explicit organization_id filter is deliberate: tenant scoping is
// fail-closed for org 0, so the system partition is addressed directly.
func insertSystemAuditRow(tx *gorm.DB, entry Entry, detail string) error {
	var maxSeq uint64
	if err := store.WithoutTenantScope(tx).
		Model(&model.AuditLog{}).
		Where("organization_id = ?", 0).
		Select("COALESCE(MAX(seq), 0)").
		Scan(&maxSeq).Error; err != nil {
		return err
	}

	row := model.AuditLog{
		OrganizationID: 0,
		Seq:            maxSeq + 1,
		ActorUserID:    0,
		Action:         entry.Action,
		TargetType:     entry.TargetType,
		TargetID:       entry.TargetID,
		Detail:         detail,
	}
	// No ON CONFLICT clause: a duplicate-key collision must surface as an error
	// so the caller's retry loop re-reads MAX(seq). Silently dropping the row
	// would lose an audit entry.
	res := tx.Create(&row)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected != 1 {
		return fmt.Errorf("audit: system entry insert affected %d rows", res.RowsAffected)
	}
	return nil
}
