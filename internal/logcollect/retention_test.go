package logcollect

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/config"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

func newRetentionStore(t *testing.T) store.Store {
	t.Helper()
	dsn := "file:retention_" + fmt.Sprint(time.Now().UnixNano()) + "?mode=memory&cache=shared"
	st, err := store.Open(config.DatabaseConfig{Driver: "sqlite", DSN: dsn})
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	require.NoError(t, st.DB.AutoMigrate(&model.LogEvent{}))
	return *st
}

func seedEvent(t *testing.T, st store.Store, orgID uint, at time.Time) {
	t.Helper()
	require.NoError(t, st.DB.Create(&model.LogEvent{
		OrganizationID: orgID,
		Source:         model.LogSourceHbbs,
		Level:          "info",
		Kind:           "other",
		DetailJSON:     "{}",
		OccurredAt:     at.UTC(),
	}).Error)
}

func TestPruneExpired_RemovesOnlyOverdueRows(t *testing.T) {
	st := newRetentionStore(t)
	now := time.Now().UTC()

	seedEvent(t, st, 1, now.Add(-31*24*time.Hour)) // overdue
	seedEvent(t, st, 1, now.Add(-29*24*time.Hour)) // inside window
	seedEvent(t, st, 2, now.Add(-31*24*time.Hour)) // another tenant, overdue

	rows, err := PruneExpired(st.DB, now)
	require.NoError(t, err)
	require.Equal(t, int64(2), rows, "the sweep spans tenants")

	var left []model.LogEvent
	require.NoError(t, store.WithoutTenantScope(st.DB).Find(&left).Error)
	require.Len(t, left, 1)
	require.Equal(t, uint(1), left[0].OrganizationID)
}

// TestPruneExpired_Batches proves the batched loop drains a backlog larger
// than pruneBatchSize in one call.
func TestPruneExpired_Batches(t *testing.T) {
	st := newRetentionStore(t)
	now := time.Now().UTC()

	const total = pruneBatchSize*2 + 7
	overdue := now.Add(-31 * 24 * time.Hour)
	for i := 0; i < total; i++ {
		seedEvent(t, st, uint(i%3)+1, overdue)
	}
	seedEvent(t, st, 1, now)

	rows, err := PruneExpired(st.DB, now)
	require.NoError(t, err)
	require.Equal(t, int64(total), rows, "all batches are drained")

	var left []model.LogEvent
	require.NoError(t, store.WithoutTenantScope(st.DB).Find(&left).Error)
	require.Len(t, left, 1)
}

func TestPruneExpired_EmptyTableIsNoop(t *testing.T) {
	st := newRetentionStore(t)
	rows, err := PruneExpired(st.DB, time.Now().UTC())
	require.NoError(t, err)
	require.Zero(t, rows)
}
