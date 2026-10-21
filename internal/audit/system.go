package audit

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// systemSeqMu serialises system-sequence allocation inside this process. The
// only current writer is a low-frequency sweep, but the scheduler is generic:
// a second task in the same process must not turn every insert into a
// duplicate-key retry. Multiple replicas still rely on the unique index.
var systemSeqMu sync.Mutex

// SystemActionPrefix marks entries written by background workers. RecordSystem
// accepts only actions with this prefix, so request-scoped code cannot use it
// to bypass the org-0 fail-closed behaviour of Record.
const SystemActionPrefix = "worker."

// RecordSystem persists a system-scoped audit entry for a background worker.
//
// Background work has no tenant (no request context), so these entries live in
// the organization 0 partition with their own continuous sequence, separate
// from the per-organization sequences used by request-scoped entries.
//
// Unlike Record, there is no organization row to lock (org 0 has none), so
// allocation is "read MAX(seq), insert, retry on a unique-index collision".
// That is acceptable for the low-frequency worker traffic this is built for
// (a retention sweep every few hours), not for high-throughput writes: a
// burst of N concurrent writers degrades to O(N^2) transaction attempts.
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

	systemSeqMu.Lock()
	defer systemSeqMu.Unlock()

	var lastErr error
	for attempt := 0; attempt < maxSeqAttempts; attempt++ {
		if attempt > 0 {
			// Small linear backoff: the collision window is one transaction.
			time.Sleep(time.Duration(attempt) * time.Millisecond)
		}
		err := a.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			return a.insertSystemAuditRow(tx, entry, detail)
		})
		if err == nil {
			return nil
		}
		lastErr = err
		if !isRetryableSeqErr(err) {
			return fmt.Errorf("record system audit entry: %w", err)
		}
	}
	return fmt.Errorf("record system audit entry after %d attempts: %w", maxSeqAttempts, lastErr)
}

// isRetryableSeqErr reports whether the insert failed for a reason a fresh
// MAX(seq) read can fix: a duplicate sequence, or a transient lock conflict
// from a concurrent writer (SQLite SQLITE_BUSY, MySQL deadlock/lock-wait).
// Anything else (bad schema, closed database) surfaces immediately.
func isRetryableSeqErr(err error) bool {
	if errors.Is(err, gorm.ErrDuplicatedKey) {
		return true
	}
	msg := strings.ToLower(err.Error())
	for _, needle := range []string{
		"unique constraint", // sqlite / postgres text form
		"duplicate entry",   // mysql
		"database is locked",
		"database table is locked",
		"deadlock",
		"lock wait timeout",
	} {
		if strings.Contains(msg, needle) {
			return true
		}
	}
	return false
}

// insertSystemAuditRow allocates the next global sequence and inserts the
// entry. The explicit organization_id filter is deliberate: tenant scoping is
// fail-closed for org 0, so the system partition is addressed directly.
func (a *GormAuditor) insertSystemAuditRow(tx *gorm.DB, entry Entry, detail string) error {
	// WithoutTenantScope derives from tx's statement context, so it must be
	// applied to the handle the read actually uses. The subsequent Create is
	// not instrumented by the tenant plugin (create has no callback), which is
	// what lets org 0 rows exist at all; reads keep going through the explicit
	// organization_id = 0 filter below.
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
		CreatedAt:      time.Now(),
	}
	// No ON CONFLICT clause: a duplicate-key collision must surface as an
	// error so the caller's retry loop re-reads MAX(seq). Silently dropping
	// the row would lose an audit entry.
	if a.insertSystemHook != nil {
		return a.insertSystemHook(tx, &row, maxSeq)
	}
	res := tx.Create(&row)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected != 1 {
		return fmt.Errorf("audit: system entry insert affected %d rows", res.RowsAffected)
	}
	return nil
}
