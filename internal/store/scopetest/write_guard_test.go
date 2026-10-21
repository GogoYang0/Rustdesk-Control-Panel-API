package scopetest

import (
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// Issue #42: a tenant-scoped update must never move a row into another
// organization. Scoping the WHERE clause stops reading and writing other
// tenants' rows, but nothing stops a caller from *setting* organization_id —
// which silently hands the row to a different tenant.
func TestScopedUpdate_RejectsTenantColumnChange(t *testing.T) {
	db, cleanup := newDB(t)
	defer cleanup()

	orgA := model.Organization{Name: "write-guard-a"}
	orgB := model.Organization{Name: "write-guard-b"}
	require.NoError(t, db.Create(&orgA).Error)
	require.NoError(t, db.Create(&orgB).Error)

	m := model.Membership{OrganizationID: orgA.ID, UserID: 1, Role: model.RoleMember}
	require.NoError(t, db.Create(&m).Error)

	err := store.ScopedByOrg(db, orgA.ID).
		Model(&model.Membership{}).
		Where("id = ?", m.ID).
		Update("organization_id", orgB.ID).Error
	require.Error(t, err, "moving a row to another tenant must be rejected")
	require.ErrorIs(t, err, store.ErrTenantColumnWrite)

	var reloaded model.Membership
	require.NoError(t, store.WithoutTenantScope(db).Where("id = ?", m.ID).First(&reloaded).Error)
	require.Equal(t, orgA.ID, reloaded.OrganizationID, "the row must stay in its original organization")
}

// The same guard must catch a map update, which carries the column name inside
// the payload rather than in the first argument.
func TestScopedUpdate_RejectsTenantColumnInMap(t *testing.T) {
	db, cleanup := newDB(t)
	defer cleanup()

	orgA := model.Organization{Name: "write-guard-map-a"}
	orgB := model.Organization{Name: "write-guard-map-b"}
	require.NoError(t, db.Create(&orgA).Error)
	require.NoError(t, db.Create(&orgB).Error)

	m := model.Membership{OrganizationID: orgA.ID, UserID: 2, Role: model.RoleMember}
	require.NoError(t, db.Create(&m).Error)

	err := store.ScopedByOrg(db, orgA.ID).
		Model(&model.Membership{}).
		Where("id = ?", m.ID).
		Updates(map[string]any{"organization_id": orgB.ID, "role": model.RoleAdmin}).Error
	require.Error(t, err, "a map update carrying organization_id must be rejected")
	require.ErrorIs(t, err, store.ErrTenantColumnWrite)

	var reloaded model.Membership
	require.NoError(t, store.WithoutTenantScope(db).Where("id = ?", m.ID).First(&reloaded).Error)
	require.Equal(t, orgA.ID, reloaded.OrganizationID)
	require.Equal(t, model.RoleMember, reloaded.Role, "the whole statement must be rejected, not partially applied")
}

// Ordinary updates inside the tenant keep working — the guard must not turn
// into a blanket ban on Update.
func TestScopedUpdate_AllowsNonTenantColumns(t *testing.T) {
	db, cleanup := newDB(t)
	defer cleanup()

	org := model.Organization{Name: "write-guard-ok"}
	require.NoError(t, db.Create(&org).Error)

	m := model.Membership{OrganizationID: org.ID, UserID: 3, Role: model.RoleMember}
	require.NoError(t, db.Create(&m).Error)

	require.NoError(t, store.ScopedByOrg(db, org.ID).
		Model(&model.Membership{}).
		Where("id = ?", m.ID).
		Update("role", model.RoleAdmin).Error)

	var reloaded model.Membership
	require.NoError(t, store.WithoutTenantScope(db).Where("id = ?", m.ID).First(&reloaded).Error)
	require.Equal(t, model.RoleAdmin, reloaded.Role)
}

// The explicit transfer channel is the only way through. It exists so that a
// deliberate, reviewable move (and nothing else) can set the tenant column.
func TestAllowTenantTransfer_PermitsTenantColumn(t *testing.T) {
	db, cleanup := newDB(t)
	defer cleanup()

	orgA := model.Organization{Name: "transfer-a"}
	orgB := model.Organization{Name: "transfer-b"}
	require.NoError(t, db.Create(&orgA).Error)
	require.NoError(t, db.Create(&orgB).Error)

	m := model.Membership{OrganizationID: orgA.ID, UserID: 4, Role: model.RoleMember}
	require.NoError(t, db.Create(&m).Error)

	store.RegisterTransferRecorder(func(*gorm.DB, store.TransferAudit) error { return nil })
	t.Cleanup(func() { store.RegisterTransferRecorder(nil) })

	require.NoError(t, store.AllowTenantTransfer(db,
		store.TransferAudit{OrganizationID: orgA.ID, Reason: "test repair"},
		func(tx *gorm.DB) error {
			return store.ScopedByOrg(tx, orgA.ID).
				Model(&model.Membership{}).
				Where("id = ?", m.ID).
				Update("organization_id", orgB.ID).Error
		}))

	var reloaded model.Membership
	require.NoError(t, store.WithoutTenantScope(db).Where("id = ?", m.ID).First(&reloaded).Error)
	require.Equal(t, orgB.ID, reloaded.OrganizationID, "the explicit transfer channel must move the row")
}

// Cross-tenant maintenance handles still go through the guard: opting out of
// the WHERE filter is not the same as opting out of the tenant-column rule.
func TestScopedUpdate_CrossTenantHandleStillGuarded(t *testing.T) {
	db, cleanup := newDB(t)
	defer cleanup()

	orgA := model.Organization{Name: "write-guard-cross-a"}
	orgB := model.Organization{Name: "write-guard-cross-b"}
	require.NoError(t, db.Create(&orgA).Error)
	require.NoError(t, db.Create(&orgB).Error)

	m := model.Membership{OrganizationID: orgA.ID, UserID: 5, Role: model.RoleMember}
	require.NoError(t, db.Create(&m).Error)

	err := store.WithoutTenantScope(db).
		Model(&model.Membership{}).
		Where("id = ?", m.ID).
		Update("organization_id", orgB.ID).Error
	require.Error(t, err)
	require.ErrorIs(t, err, store.ErrTenantColumnWrite)
}
