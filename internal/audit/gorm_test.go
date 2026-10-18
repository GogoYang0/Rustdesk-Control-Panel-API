package audit_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/audit"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/config"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

func newAuditor(t *testing.T) (*audit.GormAuditor, store.Store, func()) {
	t.Helper()
	dsn := "file:audit_" + fmt.Sprint(time.Now().UnixNano()) + "?mode=memory&cache=shared"
	st, err := store.Open(config.DatabaseConfig{Driver: "sqlite", DSN: dsn})
	require.NoError(t, err)
	require.NoError(t, st.DB.AutoMigrate(&model.Organization{}, &model.AuditLog{}))
	return audit.NewGormAuditor(st.DB), *st, func() { _ = st.Close() }
}

func TestSeq_Continuous_Concurrent(t *testing.T) {
	a, st, cleanup := newAuditor(t)
	defer cleanup()

	org := model.Organization{Name: "audit-org"}
	require.NoError(t, st.DB.Create(&org).Error)

	const writers = 50
	var wg sync.WaitGroup
	errs := make(chan error, writers)
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs <- a.Record(context.Background(), audit.Entry{
				OrganizationID: org.ID,
				ActorUserID:    uint(i + 1),
				Action:         "test.action",
			})
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}

	var seqs []uint64
	require.NoError(t, store.ScopedByOrg(st.DB, org.ID).
		Model(&model.AuditLog{}).Order("seq").Pluck("seq", &seqs).Error)
	require.Len(t, seqs, writers, "every entry must be persisted")
	for i, seq := range seqs {
		require.EqualValues(t, i+1, seq, "sequence must be continuous without gaps")
	}
}

func TestSeq_Isolated_PerOrg(t *testing.T) {
	a, st, cleanup := newAuditor(t)
	defer cleanup()

	orgA := model.Organization{Name: "org-a"}
	orgB := model.Organization{Name: "org-b"}
	require.NoError(t, st.DB.Create(&orgA).Error)
	require.NoError(t, st.DB.Create(&orgB).Error)

	for i := 0; i < 3; i++ {
		require.NoError(t, a.Record(context.Background(), audit.Entry{OrganizationID: orgA.ID, Action: "a"}))
	}
	require.NoError(t, a.Record(context.Background(), audit.Entry{OrganizationID: orgB.ID, Action: "b"}))

	var seqA, seqB []uint64
	require.NoError(t, store.ScopedByOrg(st.DB, orgA.ID).Model(&model.AuditLog{}).Order("seq").Pluck("seq", &seqA).Error)
	require.NoError(t, store.ScopedByOrg(st.DB, orgB.ID).Model(&model.AuditLog{}).Order("seq").Pluck("seq", &seqB).Error)
	require.Equal(t, []uint64{1, 2, 3}, seqA)
	require.Equal(t, []uint64{1}, seqB, "each organization starts its own sequence")
}

func TestRecord_NoOrg_IsSkipped(t *testing.T) {
	a, st, cleanup := newAuditor(t)
	defer cleanup()

	require.NoError(t, a.Record(context.Background(), audit.Entry{Action: "login"}))
	var count int64
	require.NoError(t, st.DB.Model(&model.AuditLog{}).Count(&count).Error)
	require.Zero(t, count)
}
