package audit_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

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
	// Count through raw SQL: a model-based query would be tenant scoped and
	// fail closed, hiding a regression where Record wrongly persists a row.
	var count int64
	require.NoError(t, st.DB.Raw("SELECT COUNT(*) FROM audit_logs").Scan(&count).Error)
	require.Zero(t, count)
}

// RecordTx must persist the entry on the caller's transaction, continuing
// the per-organization sequence without gaps (#19).
func TestRecordTx_Success(t *testing.T) {
	a, st, cleanup := newAuditor(t)
	defer cleanup()

	org := model.Organization{Name: "tx-org"}
	require.NoError(t, st.DB.Create(&org).Error)

	require.NoError(t, st.DB.Transaction(func(tx *gorm.DB) error {
		return a.RecordTx(tx, audit.Entry{
			OrganizationID: org.ID,
			ActorUserID:    7,
			Action:         "organization.create",
			TargetType:     "organization",
			TargetID:       fmt.Sprint(org.ID),
		})
	}))

	var first model.AuditLog
	require.NoError(t, store.ScopedByOrg(st.DB, org.ID).First(&first).Error)
	require.EqualValues(t, 1, first.Seq)
	require.Equal(t, "organization.create", first.Action)
	require.Equal(t, uint(7), first.ActorUserID)

	// The next transaction continues the sequence.
	require.NoError(t, st.DB.Transaction(func(tx *gorm.DB) error {
		return a.RecordTx(tx, audit.Entry{OrganizationID: org.ID, Action: "test.second"})
	}))
	var seqs []uint64
	require.NoError(t, store.ScopedByOrg(st.DB, org.ID).
		Model(&model.AuditLog{}).Order("seq").Pluck("seq", &seqs).Error)
	require.Equal(t, []uint64{1, 2}, seqs)
}

// When the audit record fails inside the entity transaction, the entity
// change must roll back with it: neither table keeps a row (#19).
func TestRecordTx_RollbackTogether(t *testing.T) {
	a, st, cleanup := newAuditor(t)
	defer cleanup()

	err := st.DB.Transaction(func(tx *gorm.DB) error {
		org := model.Organization{Name: "doomed-org"}
		if err := tx.Create(&org).Error; err != nil {
			return err
		}
		// An unmarshalable detail value makes the audit record fail.
		return a.RecordTx(tx, audit.Entry{
			OrganizationID: org.ID,
			Action:         "organization.create",
			Detail:         map[string]any{"bad": make(chan int)},
		})
	})
	require.Error(t, err, "the audit failure must abort the transaction")

	var orgs, logs int64
	require.NoError(t, st.DB.Model(&model.Organization{}).Count(&orgs).Error)
	// Raw SQL on purpose: the tenant plugin fail-closes model-based
	// audit_logs queries without an org context, which would mask leftovers.
	require.NoError(t, st.DB.Raw("SELECT COUNT(*) FROM audit_logs").Scan(&logs).Error)
	require.Zero(t, orgs, "the entity change must roll back with the audit failure")
	require.Zero(t, logs, "no audit row may survive a failed transaction")
}
