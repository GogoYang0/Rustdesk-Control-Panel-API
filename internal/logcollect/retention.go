package logcollect

import (
	"time"

	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// PruneExpired deletes log events older than the retention window and returns
// the number of deleted rows. It is a package-level function so the periodic
// scheduler can sweep even when log collection itself is disabled (#41).
//
// The sweep is ALWAYS cross-tenant: it wraps the caller's handle in
// WithoutTenantScope, so passing a tenant-scoped handle deletes every
// organization's overdue rows by design.
//
// occurred_at is stored as UTC text and compared lexicographically, so the
// cutoff must share that timeline: a local-zone value shifts the window by the
// host's offset.
func PruneExpired(db *gorm.DB, now time.Time) (int64, error) {
	cutoff := now.UTC().Add(-time.Duration(model.DefaultLogEventRetentionDays) * 24 * time.Hour)

	// Batched deletion keeps lock hold times bounded on large tables. The ids
	// are read first and deleted in a second statement: MySQL rejects a
	// DELETE whose subquery selects from the target table (error 1093), so a
	// single `DELETE ... WHERE id IN (SELECT ... FROM log_events)` is not
	// portable.
	var total int64
	for {
		var ids []uint
		if err := store.WithoutTenantScope(db).
			Model(&model.LogEvent{}).
			Where("occurred_at < ?", cutoff).
			Order("id").
			Limit(pruneBatchSize).
			Pluck("id", &ids).Error; err != nil {
			return total, err
		}
		if len(ids) == 0 {
			return total, nil
		}
		res := store.WithoutTenantScope(db).
			Where("id IN ?", ids).
			Delete(&model.LogEvent{})
		if res.Error != nil {
			return total, res.Error
		}
		total += res.RowsAffected
		if len(ids) < pruneBatchSize {
			return total, nil
		}
	}
}

// pruneBatchSize bounds how many rows one delete statement removes, so a large
// backlog does not hold a long write transaction.
const pruneBatchSize = 1000
