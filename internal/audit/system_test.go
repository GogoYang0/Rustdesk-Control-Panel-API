package audit_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/audit"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// AuditLog is a tenant-scoped table, so reads must declare intent: an
// unscoped handle fails closed (WHERE 1 = 0). The system partition is read
// through WithoutTenantScope, which is also what keeps it out of every
// tenant-scoped view.

func TestRecordSystem_RequiresSystemPrefix(t *testing.T) {
	a, _, cleanup := newAuditor(t)
	defer cleanup()

	err := a.RecordSystem(context.Background(), audit.Entry{Action: "organization.create"})
	require.Error(t, err, "business actions must not use the system partition")

	err = a.RecordSystem(context.Background(), audit.Entry{OrganizationID: 1, Action: audit.SystemActionPrefix + "x"})
	require.Error(t, err, "system entries must not carry an organization")
}

func TestRecordSystem_SequenceInOwnPartition(t *testing.T) {
	a, st, cleanup := newAuditor(t)
	defer cleanup()

	ctx := context.Background()
	for i := 0; i < 3; i++ {
		require.NoError(t, a.RecordSystem(ctx, audit.Entry{
			Action:     audit.SystemActionPrefix + "retention",
			TargetType: "worker",
			TargetID:   "retention",
			Detail:     map[string]any{"changed": i},
		}))
	}

	var rows []model.AuditLog
	require.NoError(t, store.WithoutTenantScope(st.DB).Order("seq").Find(&rows).Error)
	require.Len(t, rows, 3)
	for i, r := range rows {
		require.Equal(t, uint(0), r.OrganizationID)
		require.Equal(t, uint64(i+1), r.Seq, "global sequence is continuous from 1")
		require.Equal(t, "worker.retention", r.Action)
		require.Equal(t, uint(0), r.ActorUserID)
	}
}

func TestRecordSystem_ConcurrentGapFree(t *testing.T) {
	a, st, cleanup := newAuditor(t)
	defer cleanup()

	ctx := context.Background()
	const n = 20
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		go func() {
			errs <- a.RecordSystem(ctx, audit.Entry{Action: audit.SystemActionPrefix + "sweep"})
		}()
	}
	for i := 0; i < n; i++ {
		require.NoError(t, <-errs)
	}

	var seqs []uint64
	require.NoError(t, store.WithoutTenantScope(st.DB).
		Model(&model.AuditLog{}).Where("organization_id = ?", 0).
		Order("seq").Pluck("seq", &seqs).Error)
	require.Len(t, seqs, n)
	for i, seq := range seqs {
		require.Equal(t, uint64(i+1), seq, "concurrent writers keep the sequence gap-free")
	}
}

// The system partition must stay invisible to tenant-scoped reads: that is
// what keeps request-scoped code from ever seeing infrastructure audit
// entries through a normal org-scoped query.
func TestRecordSystem_InvisibleToTenantScope(t *testing.T) {
	a, st, cleanup := newAuditor(t)
	defer cleanup()

	require.NoError(t, a.RecordSystem(context.Background(), audit.Entry{Action: audit.SystemActionPrefix + "x"}))

	var scoped []model.AuditLog
	require.NoError(t, store.ScopedByOrg(st.DB, 1).Find(&scoped).Error)
	require.Empty(t, scoped, "tenant scope never sees the system partition")

	var all []model.AuditLog
	require.NoError(t, store.WithoutTenantScope(st.DB).Find(&all).Error)
	require.Len(t, all, 1)
	require.Equal(t, uint(0), all[0].OrganizationID)
}
