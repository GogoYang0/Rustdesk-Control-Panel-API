package audit_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/audit"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/config"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

func newQueryFixture(t *testing.T) (*store.Store, model.Organization, model.Organization) {
	t.Helper()
	dsn := "file:auditq_" + fmt.Sprint(time.Now().UnixNano()) + "?mode=memory&cache=shared"
	st, err := store.Open(config.DatabaseConfig{Driver: "sqlite", DSN: dsn})
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	require.NoError(t, st.DB.AutoMigrate(&model.Organization{}, &model.AuditLog{}))

	a := model.Organization{Name: "audit-a"}
	b := model.Organization{Name: "audit-b"}
	require.NoError(t, st.DB.Create(&a).Error)
	require.NoError(t, st.DB.Create(&b).Error)
	return st, a, b
}

func TestVisible_IndividualRules(t *testing.T) {
	byActor := model.AuditLog{ActorUserID: 7}
	targeted := model.AuditLog{TargetType: "user", TargetID: "8"}
	deviceTarget := model.AuditLog{TargetType: "device", TargetID: "8"}

	require.True(t, audit.Visible(model.AuditScopeIndividual, 7, byActor))
	require.False(t, audit.Visible(model.AuditScopeIndividual, 8, byActor))
	require.True(t, audit.Visible(model.AuditScopeIndividual, 8, targeted))
	require.False(t, audit.Visible(model.AuditScopeIndividual, 9, targeted))
	require.False(t, audit.Visible(model.AuditScopeIndividual, 8, deviceTarget),
		"only user-type targets match the viewer's id")
	require.True(t, audit.Visible("", 7, byActor), "an unknown scope falls back to the individual predicate")
	require.False(t, audit.Visible("", 8, byActor))
	require.True(t, audit.Visible(model.AuditScopeGlobal, 99, byActor))
}

func TestQuery_FiltersOrderAndPagination(t *testing.T) {
	st, orgA, orgB := newQueryFixture(t)
	ctx := context.Background()
	base := time.Date(2026, 10, 24, 10, 0, 0, 0, time.UTC)

	rows := []model.AuditLog{
		{OrganizationID: orgA.ID, Seq: 1, ActorUserID: 7, Action: "member.role", TargetType: "user", TargetID: "8", CreatedAt: base},
		{OrganizationID: orgA.ID, Seq: 2, ActorUserID: 9, Action: "device.disable", TargetType: "device", TargetID: "1", CreatedAt: base.Add(time.Minute)},
		{OrganizationID: orgA.ID, Seq: 3, ActorUserID: 7, Action: "role.create", TargetType: "role", TargetID: "5", CreatedAt: base.Add(2 * time.Minute)},
		// Another tenant: must never leak into org A queries.
		{OrganizationID: orgB.ID, Seq: 1, ActorUserID: 7, Action: "member.role", TargetType: "user", TargetID: "8", CreatedAt: base},
	}
	require.NoError(t, st.DB.Create(&rows).Error)

	all, total, err := audit.Query(ctx, st.DB, orgA.ID, audit.Filter{}, audit.Viewer{Scope: model.AuditScopeGlobal}, 1, 2)
	require.NoError(t, err)
	require.EqualValues(t, 3, total)
	require.Len(t, all, 2)
	require.Equal(t, "role.create", all[0].Action, "newest first")
	require.Equal(t, "device.disable", all[1].Action)

	secondPage, total, err := audit.Query(ctx, st.DB, orgA.ID, audit.Filter{}, audit.Viewer{Scope: model.AuditScopeGlobal}, 2, 2)
	require.NoError(t, err)
	require.EqualValues(t, 3, total)
	require.Len(t, secondPage, 1)
	require.Equal(t, "member.role", secondPage[0].Action)

	byMine := uint(7)
	mine, total, err := audit.Query(ctx, st.DB, orgA.ID, audit.Filter{ActorUserID: &byMine}, audit.Viewer{Scope: model.AuditScopeGlobal}, 1, 50)
	require.NoError(t, err)
	require.EqualValues(t, 2, total)
	require.Len(t, mine, 2)

	byAction, _, err := audit.Query(ctx, st.DB, orgA.ID, audit.Filter{Action: "member.role"}, audit.Viewer{Scope: model.AuditScopeGlobal}, 1, 50)
	require.NoError(t, err)
	require.Len(t, byAction, 1, "the other tenant's identical action must not appear")

	byTarget, _, err := audit.Query(ctx, st.DB, orgA.ID, audit.Filter{TargetType: "user", TargetID: "8"}, audit.Viewer{Scope: model.AuditScopeGlobal}, 1, 50)
	require.NoError(t, err)
	require.Len(t, byTarget, 1)

	// from inclusive, to exclusive.
	from, to := base.Add(time.Minute), base.Add(2*time.Minute)
	windowed, _, err := audit.Query(ctx, st.DB, orgA.ID, audit.Filter{From: &from, To: &to}, audit.Viewer{Scope: model.AuditScopeGlobal}, 1, 50)
	require.NoError(t, err)
	require.Len(t, windowed, 1)
	require.Equal(t, "device.disable", windowed[0].Action)
}

func TestQuery_IndividualScopeAppliedInSQL(t *testing.T) {
	st, orgA, _ := newQueryFixture(t)
	ctx := context.Background()
	base := time.Date(2026, 10, 24, 10, 0, 0, 0, time.UTC)
	rows := []model.AuditLog{
		{OrganizationID: orgA.ID, Seq: 1, ActorUserID: 7, Action: "a", CreatedAt: base},
		{OrganizationID: orgA.ID, Seq: 2, ActorUserID: 9, Action: "b", CreatedAt: base.Add(time.Minute)},
		{OrganizationID: orgA.ID, Seq: 3, ActorUserID: 9, Action: "c", TargetType: "user", TargetID: "7", CreatedAt: base.Add(2 * time.Minute)},
		{OrganizationID: orgA.ID, Seq: 4, ActorUserID: 9, Action: "d", TargetType: "device", TargetID: "7", CreatedAt: base.Add(3 * time.Minute)},
	}
	require.NoError(t, st.DB.Create(&rows).Error)

	viewer := audit.Viewer{Scope: model.AuditScopeIndividual, UserID: 7}
	items, total, err := audit.Query(ctx, st.DB, orgA.ID, audit.Filter{}, viewer, 1, 50)
	require.NoError(t, err)
	require.EqualValues(t, 2, total, "own action plus user-targeted row")
	require.Len(t, items, 2)
	for _, row := range items {
		require.True(t, audit.Visible(viewer.Scope, viewer.UserID, row))
	}
	require.Equal(t, "c", items[0].Action)
	require.Equal(t, "a", items[1].Action)

	// An unknown scope must fail closed to the individual predicate.
	unknown, total, err := audit.Query(ctx, st.DB, orgA.ID, audit.Filter{}, audit.Viewer{Scope: "", UserID: 7}, 1, 50)
	require.NoError(t, err)
	require.EqualValues(t, 2, total)
	require.Len(t, unknown, 2)
}

func TestNormalizePagination_Clamps(t *testing.T) {
	page, size := audit.NormalizePagination(0, 0)
	require.Equal(t, 1, page)
	require.Equal(t, audit.DefaultPageSize, size)
	page, size = audit.NormalizePagination(3, 10000)
	require.Equal(t, 3, page)
	require.Equal(t, audit.MaxPageSize, size)
}
