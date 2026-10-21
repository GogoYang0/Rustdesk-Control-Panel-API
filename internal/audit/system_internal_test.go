package audit

import (
	"context"
	"errors"
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

// TestRecordSystem_RetriesAfterSequenceCollision proves the retry re-reads
// MAX(seq) instead of reusing the cached value: the first entry is committed
// (seq 1), then the next insert collides once. Only a fresh read can place the
// retried row at seq 2 — a cached seq would collide forever and exhaust the
// attempts.
func TestRecordSystem_RetriesAfterSequenceCollision(t *testing.T) {
	a, st := newInternalAuditor(t)
	ctx := context.Background()

	require.NoError(t, a.RecordSystem(ctx, Entry{Action: SystemActionPrefix + "first"}))

	var calls int
	var seenMax []uint64
	a.insertSystemHook = func(tx *gorm.DB, row *model.AuditLog, maxSeq uint64) error {
		calls++
		seenMax = append(seenMax, maxSeq)
		if calls == 1 {
			// Exactly what the unique (organization_id, seq) index produces.
			return gorm.ErrDuplicatedKey
		}
		return tx.Create(row).Error
	}

	require.NoError(t, a.RecordSystem(ctx, Entry{Action: SystemActionPrefix + "second"}))
	require.Equal(t, 2, calls, "a collision must be retried exactly once here")
	require.Equal(t, []uint64{1, 1}, seenMax,
		"both attempts read the live MAX(seq); a cached sequence would not re-read it")

	var rows []model.AuditLog
	require.NoError(t, store.WithoutTenantScope(st.DB).Order("seq").Find(&rows).Error)
	require.Len(t, rows, 2, "the retry must persist the entry, not lose it")
	require.Equal(t, uint64(1), rows[0].Seq)
	require.Equal(t, uint64(2), rows[1].Seq)
	require.Equal(t, SystemActionPrefix+"second", rows[1].Action)
}

func TestRecordSystem_NonRetryableErrorSurfaces(t *testing.T) {
	a, _ := newInternalAuditor(t)

	a.insertSystemHook = func(*gorm.DB, *model.AuditLog, uint64) error {
		return fmt.Errorf("schema is broken")
	}
	err := a.RecordSystem(context.Background(), Entry{Action: SystemActionPrefix + "sweep"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "schema is broken")
}

func TestRecordSystem_RetryExhaustion(t *testing.T) {
	a, _ := newInternalAuditor(t)

	calls := 0
	a.insertSystemHook = func(*gorm.DB, *model.AuditLog, uint64) error {
		calls++
		return gorm.ErrDuplicatedKey
	}
	err := a.RecordSystem(context.Background(), Entry{Action: SystemActionPrefix + "sweep"})
	require.Error(t, err)
	require.Equal(t, maxSeqAttempts, calls, "bounded attempts, then a hard failure")
}

func TestIsRetryableSeqErr(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"gorm sentinel", gorm.ErrDuplicatedKey, true},
		{"sqlite unique", errors.New("UNIQUE constraint failed: audit_logs.organization_id, audit_logs.seq"), true},
		{"postgres unique", errors.New("duplicate key value violates unique constraint \"idx_audit_org_seq\""), true},
		{"mysql duplicate", errors.New("Error 1062: Duplicate entry '0-1' for key 'idx_audit_org_seq'"), true},
		{"sqlite busy", errors.New("database is locked (5) (SQLITE_BUSY)"), true},
		{"mysql deadlock", errors.New("Error 1213: Deadlock found when trying to get lock"), true},
		{"mysql lock wait", errors.New("Error 1205: Lock wait timeout exceeded"), true},
		{"schema error", errors.New("no such table: audit_logs"), false},
		{"closed database", errors.New("sql: database is closed"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, isRetryableSeqErr(tc.err))
		})
	}
}
