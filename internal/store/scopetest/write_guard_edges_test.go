package scopetest

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// A pointer to a map is still a map for GORM's assignment builder, so the guard
// has to see through the pointer. This is the one-character bypass: Updates(&payload).
func TestScopedUpdate_RejectsTenantColumnInPointerMap(t *testing.T) {
	db, cleanup := newDB(t)
	defer cleanup()

	orgA := model.Organization{Name: "guard-ptr-a"}
	orgB := model.Organization{Name: "guard-ptr-b"}
	require.NoError(t, db.Create(&orgA).Error)
	require.NoError(t, db.Create(&orgB).Error)

	m := model.Membership{OrganizationID: orgA.ID, UserID: 10, Role: model.RoleMember}
	require.NoError(t, db.Create(&m).Error)

	payload := map[string]any{"organization_id": orgB.ID}
	err := store.ScopedByOrg(db, orgA.ID).
		Model(&model.Membership{}).
		Where("id = ?", m.ID).
		Updates(&payload).Error
	require.Error(t, err, "a pointer to a map must not bypass the guard")
	require.ErrorIs(t, err, store.ErrTenantColumnWrite)
}

// Omit is GORM's way of saying "this struct field is not part of the write".
// Rejecting it would leave read-modify-write with no legal spelling at all.
func TestScopedUpdate_AllowsOmittedTenantColumn(t *testing.T) {
	db, cleanup := newDB(t)
	defer cleanup()

	org := model.Organization{Name: "guard-omit"}
	require.NoError(t, db.Create(&org).Error)

	m := model.Membership{OrganizationID: org.ID, UserID: 11, Role: model.RoleMember}
	require.NoError(t, db.Create(&m).Error)

	// The loaded row carries OrganizationID; omitting it must make the write legal.
	require.NoError(t, store.ScopedByOrg(db, org.ID).
		Model(&model.Membership{}).
		Where("id = ?", m.ID).
		Omit("organization_id").
		Updates(model.Membership{OrganizationID: org.ID, Role: model.RoleAdmin}).Error)

	var reloaded model.Membership
	require.NoError(t, store.WithoutTenantScope(db).Where("id = ?", m.ID).First(&reloaded).Error)
	require.Equal(t, model.RoleAdmin, reloaded.Role)
	require.Equal(t, org.ID, reloaded.OrganizationID)
}

// Explicitly selecting the tenant column means "write it", even when the value
// is the zero value: silently writing 0 would hide the row from every tenant.
func TestScopedUpdate_RejectsExplicitlySelectedZeroTenantColumn(t *testing.T) {
	db, cleanup := newDB(t)
	defer cleanup()

	org := model.Organization{Name: "guard-select-zero"}
	require.NoError(t, db.Create(&org).Error)

	m := model.Membership{OrganizationID: org.ID, UserID: 12, Role: model.RoleMember}
	require.NoError(t, db.Create(&m).Error)

	err := store.ScopedByOrg(db, org.ID).
		Model(&model.Membership{}).
		Where("id = ?", m.ID).
		Select("organization_id").
		Updates(model.Membership{Role: model.RoleAdmin}).Error
	require.Error(t, err, "an explicitly selected tenant column with a zero value must not be written")
	require.ErrorIs(t, err, store.ErrTenantColumnWrite)
}

// A quoted or upper-cased table name must not slip past the scoped-table check.
func TestScopedUpdate_RejectsTenantColumnThroughQuotedTableName(t *testing.T) {
	db, cleanup := newDB(t)
	defer cleanup()

	orgA := model.Organization{Name: "guard-case-a"}
	orgB := model.Organization{Name: "guard-case-b"}
	require.NoError(t, db.Create(&orgA).Error)
	require.NoError(t, db.Create(&orgB).Error)

	m := model.Membership{OrganizationID: orgA.ID, UserID: 13, Role: model.RoleMember}
	require.NoError(t, db.Create(&m).Error)

	err := store.WithoutTenantScope(db).
		Table("MEMBERSHIPS").
		Where("id = ?", m.ID).
		Update("organization_id", orgB.ID).Error
	require.Error(t, err, "a differently-cased table name must still be recognised as scoped")
	require.ErrorIs(t, err, store.ErrTenantColumnWrite)
}

// The transfer permission must not outlive the statement it was granted for.
// A handle-scoped marker leaks into every later statement derived from it
// (including everything inside a transaction), which turns a one-off repair into
// a standing licence.
func TestAllowTenantTransfer_DoesNotOutliveTheStatement(t *testing.T) {
	db, cleanup := newDB(t)
	defer cleanup()

	orgA := model.Organization{Name: "transfer-scope-a"}
	orgB := model.Organization{Name: "transfer-scope-b"}
	require.NoError(t, db.Create(&orgA).Error)
	require.NoError(t, db.Create(&orgB).Error)

	first := model.Membership{OrganizationID: orgA.ID, UserID: 14, Role: model.RoleMember}
	second := model.Membership{OrganizationID: orgA.ID, UserID: 15, Role: model.RoleMember}
	require.NoError(t, db.Create(&first).Error)
	require.NoError(t, db.Create(&second).Error)

	store.RegisterTransferRecorder(func(*gorm.DB, store.TransferAudit) error { return nil })
	t.Cleanup(func() { store.RegisterTransferRecorder(nil) })

	// The explicit transfer succeeds…
	require.NoError(t, store.AllowTenantTransfer(db,
		store.TransferAudit{OrganizationID: orgA.ID, Reason: "test repair"},
		func(tx *gorm.DB) error {
			return store.ScopedByOrg(tx, orgA.ID).
				Model(&model.Membership{}).
				Where("id = ?", first.ID).
				Update("organization_id", orgB.ID).Error
		}))

	// …and a second, unrelated statement from the same handle must not inherit it.
	err := store.ScopedByOrg(db, orgA.ID).
		Model(&model.Membership{}).
		Where("id = ?", second.ID).
		Update("organization_id", orgB.ID).Error
	require.Error(t, err, "the transfer permission must not persist on the base handle")
	require.ErrorIs(t, err, store.ErrTenantColumnWrite)
}

// GORM dereferences any depth of pointer, so the guard must too: two ampersands
// used to be enough to move a row.
func TestScopedUpdate_RejectsTenantColumnInDoublePointerMap(t *testing.T) {
	db, cleanup := newDB(t)
	defer cleanup()

	orgA := model.Organization{Name: "guard-ptr2-a"}
	orgB := model.Organization{Name: "guard-ptr2-b"}
	require.NoError(t, db.Create(&orgA).Error)
	require.NoError(t, db.Create(&orgB).Error)

	m := model.Membership{OrganizationID: orgA.ID, UserID: 16, Role: model.RoleMember}
	require.NoError(t, db.Create(&m).Error)

	inner := map[string]any{"organization_id": orgB.ID}
	pointer := &inner
	err := store.ScopedByOrg(db, orgA.ID).
		Model(&model.Membership{}).
		Where("id = ?", m.ID).
		Updates(&pointer).Error
	require.Error(t, err, "a multi-level pointer payload must not bypass the guard")
	require.ErrorIs(t, err, store.ErrTenantColumnWrite)
}

// Save(&[]T{{...}}) is a legal batch update in GORM; every element has to be
// checked, not just the first struct shape.
func TestScopedUpdate_RejectsTenantColumnInSliceSave(t *testing.T) {
	db, cleanup := newDB(t)
	defer cleanup()

	orgA := model.Organization{Name: "guard-slice-a"}
	orgB := model.Organization{Name: "guard-slice-b"}
	require.NoError(t, db.Create(&orgA).Error)
	require.NoError(t, db.Create(&orgB).Error)

	m := model.Membership{OrganizationID: orgA.ID, UserID: 17, Role: model.RoleMember}
	require.NoError(t, db.Create(&m).Error)

	rows := []model.Membership{{ID: m.ID, OrganizationID: orgB.ID, UserID: 17, Role: model.RoleMember}}
	err := store.ScopedByOrg(db, orgA.ID).Save(&rows).Error
	require.Error(t, err, "a slice save must not bypass the guard")
	require.ErrorIs(t, err, store.ErrTenantColumnWrite)
}

// A map payload that omits the tenant column is a legal write: Omit applies to
// maps as well as structs.
func TestScopedUpdate_AllowsOmittedTenantColumnInMap(t *testing.T) {
	db, cleanup := newDB(t)
	defer cleanup()

	org := model.Organization{Name: "guard-map-omit"}
	require.NoError(t, db.Create(&org).Error)

	m := model.Membership{OrganizationID: org.ID, UserID: 18, Role: model.RoleMember}
	require.NoError(t, db.Create(&m).Error)

	require.NoError(t, store.ScopedByOrg(db, org.ID).
		Model(&model.Membership{}).
		Where("id = ?", m.ID).
		Omit("organization_id").
		Updates(map[string]any{"organization_id": org.ID, "role": model.RoleAdmin}).Error)
}

// An unaudited transfer is refused before it can touch a row.
func TestAllowTenantTransfer_RequiresRecorderAndReason(t *testing.T) {
	db, cleanup := newDB(t)
	defer cleanup()

	orgA := model.Organization{Name: "transfer-audit-a"}
	orgB := model.Organization{Name: "transfer-audit-b"}
	require.NoError(t, db.Create(&orgA).Error)
	require.NoError(t, db.Create(&orgB).Error)

	m := model.Membership{OrganizationID: orgA.ID, UserID: 19, Role: model.RoleMember}
	require.NoError(t, db.Create(&m).Error)

	store.RegisterTransferRecorder(nil)
	t.Cleanup(func() { store.RegisterTransferRecorder(nil) })

	move := func(tx *gorm.DB) error {
		return store.ScopedByOrg(tx, orgA.ID).
			Model(&model.Membership{}).
			Where("id = ?", m.ID).
			Update("organization_id", orgB.ID).Error
	}

	err := store.AllowTenantTransfer(db, store.TransferAudit{OrganizationID: orgA.ID, Reason: "x"}, move)
	require.ErrorIs(t, err, store.ErrTransferAuditMissing,
		"a transfer without a registered recorder must be refused")

	store.RegisterTransferRecorder(func(*gorm.DB, store.TransferAudit) error { return nil })
	err = store.AllowTenantTransfer(db, store.TransferAudit{OrganizationID: orgA.ID}, move)
	require.Error(t, err, "a transfer without a reason must be refused")
	require.NotErrorIs(t, err, store.ErrTransferAuditMissing)

	var reloaded model.Membership
	require.NoError(t, store.WithoutTenantScope(db).Where("id = ?", m.ID).First(&reloaded).Error)
	require.Equal(t, orgA.ID, reloaded.OrganizationID, "refused transfers must not move anything")
}

// The recorder runs inside the transfer, so a failing audit aborts the move.
func TestAllowTenantTransfer_AuditFailureSurfaces(t *testing.T) {
	db, cleanup := newDB(t)
	defer cleanup()

	orgA := model.Organization{Name: "transfer-fail-a"}
	orgB := model.Organization{Name: "transfer-fail-b"}
	require.NoError(t, db.Create(&orgA).Error)
	require.NoError(t, db.Create(&orgB).Error)

	m := model.Membership{OrganizationID: orgA.ID, UserID: 20, Role: model.RoleMember}
	require.NoError(t, db.Create(&m).Error)

	auditErr := errors.New("audit store unavailable")
	store.RegisterTransferRecorder(func(*gorm.DB, store.TransferAudit) error { return auditErr })
	t.Cleanup(func() { store.RegisterTransferRecorder(nil) })

	err := store.AllowTenantTransfer(db,
		store.TransferAudit{OrganizationID: orgA.ID, Reason: "test"},
		func(tx *gorm.DB) error {
			return store.ScopedByOrg(tx, orgA.ID).
				Model(&model.Membership{}).
				Where("id = ?", m.ID).
				Update("organization_id", orgB.ID).Error
		})
	require.ErrorIs(t, err, auditErr, "the audit error must reach the caller")

	// The move and the audit share a transaction: a failed audit must roll the
	// move back, not leave a row that changed hands with no record.
	var reloaded model.Membership
	require.NoError(t, store.WithoutTenantScope(db).Where("id = ?", m.ID).First(&reloaded).Error)
	require.Equal(t, orgA.ID, reloaded.OrganizationID,
		"a failed audit must not leave the row in the other organization")
}
