package audit

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/config"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// Internal tests: they need the insertSystemHook seam, which is deliberately
// unexported. The retry path cannot be produced on demand against SQLite —
// writers are serialised and a pre-inserted row is consumed by the MAX(seq)
// read — so the seam is the only deterministic way to cover it.

func newInternalAuditor(t *testing.T) (*GormAuditor, store.Store) {
	t.Helper()
	dsn := "file:audit_internal_" + fmt.Sprint(time.Now().UnixNano()) + "?mode=memory&cache=shared"
	st, err := store.Open(config.DatabaseConfig{Driver: "sqlite", DSN: dsn})
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	require.NoError(t, st.DB.AutoMigrate(&model.Organization{}, &model.AuditLog{}))
	return NewGormAuditor(st.DB), *st
}

func TestRecordSystem_RetriesAfterSequenceCollision(t *testing.T) {
	a, st := newInternalAuditor(t)

	calls := 0
	a.insertSystemHook = func(tx *gorm.DB, row *model.AuditLog) error {
		calls++
		if calls == 1 {
			// Exactly what the unique (organization_id, seq) index produces.
			return gorm.ErrDuplicatedKey
		}
		return tx.Create(row).Error
	}

	require.NoError(t, a.RecordSystem(context.Background(), Entry{Action: SystemActionPrefix + "sweep"}))
	require.Equal(t, 2, calls, "a collision must be retried exactly once here")

	var rows []model.AuditLog
	require.NoError(t, store.WithoutTenantScope(st.DB).Order("seq").Find(&rows).Error)
	require.Len(t, rows, 1, "the retry must persist the entry, not lose it")
	require.Equal(t, uint64(1), rows[0].Seq)
}

func TestRecordSystem_NonRetryableErrorSurfaces(t *testing.T) {
	a, _ := newInternalAuditor(t)

	a.insertSystemHook = func(*gorm.DB, *model.AuditLog) error {
		return fmt.Errorf("schema is broken")
	}
	err := a.RecordSystem(context.Background(), Entry{Action: SystemActionPrefix + "sweep"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "schema is broken")
}

func TestRecordSystem_RetryExhaustion(t *testing.T) {
	a, _ := newInternalAuditor(t)

	calls := 0
	a.insertSystemHook = func(*gorm.DB, *model.AuditLog) error {
		calls++
		return gorm.ErrDuplicatedKey
	}
	err := a.RecordSystem(context.Background(), Entry{Action: SystemActionPrefix + "sweep"})
	require.Error(t, err)
	require.Equal(t, maxSeqAttempts, calls, "bounded attempts, then a hard failure")
}
