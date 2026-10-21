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
// occurred_at is stored as UTC text and compared lexicographically, so the
// cutoff must share that timeline: a local-zone value shifts the window by the
// host's offset.
func PruneExpired(db *gorm.DB, now time.Time) (int64, error) {
	cutoff := now.UTC().Add(-time.Duration(model.DefaultLogEventRetentionDays) * 24 * time.Hour)
	res := store.WithoutTenantScope(db).
		Where("occurred_at < ?", cutoff).
		Delete(&model.LogEvent{})
	if res.Error != nil {
		return 0, res.Error
	}
	return res.RowsAffected, nil
}
