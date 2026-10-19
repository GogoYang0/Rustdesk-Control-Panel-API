package scopetest

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/config"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

func newDB(t *testing.T) (*gorm.DB, func()) {
	t.Helper()
	s, err := store.Open(config.DatabaseConfig{Driver: "sqlite", DSN: "file::memory:?cache=shared"})
	require.NoError(t, err)
	require.NoError(t, s.DB.AutoMigrate(
		&model.Organization{}, &model.Membership{},
	))
	return s.DB, func() { _ = s.Close() }
}

// Review Focus #1: two organizations must never see each other's rows.
func TestTenantIsolation_TwoOrgs(t *testing.T) {
	db, cleanup := newDB(t)
	defer cleanup()

	orgA := model.Organization{Name: "org-a"}
	orgB := model.Organization{Name: "org-b"}
	require.NoError(t, db.Create(&orgA).Error)
	require.NoError(t, db.Create(&orgB).Error)

	require.NoError(t, db.Create(&model.Membership{OrganizationID: orgA.ID, UserID: 1, Role: model.RoleOwner}).Error)
	require.NoError(t, db.Create(&model.Membership{OrganizationID: orgB.ID, UserID: 2, Role: model.RoleMember}).Error)

	var fromA []model.Membership
	require.NoError(t, store.ScopedByOrg(db, orgA.ID).Find(&fromA).Error)
	require.Len(t, fromA, 1)
	require.EqualValues(t, 1, fromA[0].UserID, "org A must only see its own member")

	var crossOrg []model.Membership
	require.NoError(t, store.ScopedByOrg(db, orgA.ID).Where("user_id = ?", 2).Find(&crossOrg).Error)
	require.Empty(t, crossOrg, "org A must not see org B rows even with explicit filters")

	var fromB []model.Membership
	require.NoError(t, store.ScopedByOrg(db, orgB.ID).Find(&fromB).Error)
	require.Len(t, fromB, 1)
	require.EqualValues(t, 2, fromB[0].UserID)
}

func TestRequireOrgID(t *testing.T) {
	require.Error(t, store.RequireOrgID(0))
	require.NoError(t, store.RequireOrgID(7))
}

// Every registered scoped model must expose an OrganizationID field.
func TestScopedModels_HaveOrgIDField(t *testing.T) {
	_, cleanup := newDB(t)
	defer cleanup()

	models := store.ScopedModels()
	require.NotEmpty(t, models, "at least one scoped model must be registered")

	for _, m := range models {
		typ := reflect.TypeOf(m).Elem()
		f, ok := typ.FieldByName("OrganizationID")
		require.True(t, ok, "%s must carry an OrganizationID field", typ.Name())
		require.Equal(t, reflect.TypeOf(uint(0)), f.Type)
	}
}

// A zero orgID must fail closed instead of matching organization_id = 0.
func TestScopedByOrg_ZeroOrgFailsClosed(t *testing.T) {
	db, cleanup := newDB(t)
	defer cleanup()

	org := model.Organization{Name: "org-zero"}
	require.NoError(t, db.Create(&org).Error)
	require.NoError(t, db.Create(&model.Membership{OrganizationID: org.ID, UserID: 3, Role: model.RoleMember}).Error)

	var rows []model.Membership
	require.NoError(t, store.ScopedByOrg(db, 0).Find(&rows).Error)
	require.Empty(t, rows, "zero orgID must not return any tenant rows")
}

// Review Focus #1: a caller-side .Or(...) must not escape the tenant condition.
func TestScopedByOrg_OrCannotEscapeTenant(t *testing.T) {
	db, cleanup := newDB(t)
	defer cleanup()

	orgA := model.Organization{Name: "org-a-or"}
	orgB := model.Organization{Name: "org-b-or"}
	require.NoError(t, db.Create(&orgA).Error)
	require.NoError(t, db.Create(&orgB).Error)

	require.NoError(t, db.Create(&model.Membership{OrganizationID: orgA.ID, UserID: 10, Role: model.RoleOwner}).Error)
	require.NoError(t, db.Create(&model.Membership{OrganizationID: orgB.ID, UserID: 20, Role: model.RoleMember}).Error)

	// Org A queries with an OR on user 20 (a user of org B): must return nothing.
	var escaped []model.Membership
	require.NoError(t, store.ScopedByOrg(db, orgA.ID).Or("user_id = ?", 20).Find(&escaped).Error)
	require.Empty(t, escaped, ".Or must not escape the tenant condition")

	// Zero org id must stay empty even with .Or.
	var zero []model.Membership
	require.NoError(t, store.ScopedByOrg(db, 0).Or("user_id = ?", 20).Find(&zero).Error)
	require.Empty(t, zero, ".Or must not escape fail-closed zero org")

	// A disjunction inside the tenant still works: caller conditions are grouped.
	var inTenant []model.Membership
	require.NoError(t, store.ScopedByOrg(db, orgA.ID).Or("user_id = ?", 10).Find(&inTenant).Error)
	require.Len(t, inTenant, 1, "in-tenant OR must keep working")

	// OR smuggled inside a raw SQL fragment must not escape the tenant either.
	var embedded []model.Membership
	require.NoError(t, store.ScopedByOrg(db, orgA.ID).
		Where("user_id = ? OR(user_id = ?)", 20, 32).
		Find(&embedded).Error)
	require.Empty(t, embedded, "OR inside a raw SQL fragment must not escape the tenant")
}

// Scan/Row go through the Row callback chain and must be scoped too.
func TestScopedByOrg_ScanIsScoped(t *testing.T) {
	db, cleanup := newDB(t)
	defer cleanup()

	orgA := model.Organization{Name: "org-a-scan"}
	orgB := model.Organization{Name: "org-b-scan"}
	require.NoError(t, db.Create(&orgA).Error)
	require.NoError(t, db.Create(&orgB).Error)
	require.NoError(t, db.Create(&model.Membership{OrganizationID: orgA.ID, UserID: 31, Role: model.RoleOwner}).Error)
	require.NoError(t, db.Create(&model.Membership{OrganizationID: orgB.ID, UserID: 32, Role: model.RoleMember}).Error)

	type count struct{ N int }
	var c count
	require.NoError(t, store.ScopedByOrg(db, orgA.ID).
		Model(&model.Membership{}).
		Select("count(*) as n").
		Scan(&c).Error)
	require.Equal(t, 1, c.N, "Scan must stay inside the tenant")

}

// Forgetting ScopedByOrg entirely must not expose other tenants' rows.
func TestUnscopedQuery_FailsClosed(t *testing.T) {
	db, cleanup := newDB(t)
	defer cleanup()

	org := model.Organization{Name: "org-no-ctx"}
	require.NoError(t, db.Create(&org).Error)
	require.NoError(t, db.Create(&model.Membership{OrganizationID: org.ID, UserID: 41, Role: model.RoleOwner}).Error)

	var rows []model.Membership
	require.NoError(t, db.Find(&rows).Error)
	require.Empty(t, rows, "a missing tenant context must return no rows")
}

// Querying a scoped table through .Table(...) into maps leaves Schema nil; the
// tenant condition must still be applied.
func TestScopedByOrg_TableQueryIsScoped(t *testing.T) {
	db, cleanup := newDB(t)
	defer cleanup()

	orgA := model.Organization{Name: "org-a-table"}
	orgB := model.Organization{Name: "org-b-table"}
	require.NoError(t, db.Create(&orgA).Error)
	require.NoError(t, db.Create(&orgB).Error)
	require.NoError(t, db.Create(&model.Membership{OrganizationID: orgA.ID, UserID: 51, Role: model.RoleOwner}).Error)
	require.NoError(t, db.Create(&model.Membership{OrganizationID: orgB.ID, UserID: 52, Role: model.RoleMember}).Error)

	var rows []map[string]any
	require.NoError(t, store.ScopedByOrg(db, orgA.ID).Table("memberships").Find(&rows).Error)
	require.Len(t, rows, 1, ".Table(...) into maps must stay inside the tenant")

	// A non-scoped table must not receive the tenant condition.
	var orgs []map[string]any
	require.NoError(t, store.ScopedByOrg(db, orgA.ID).Table("organizations").Find(&orgs).Error)
	require.Len(t, orgs, 2, "unregistered tables must be left untouched")
}

// Aliased table references and explicit .Table over a model must both stay scoped.
func TestScopedByOrg_TableAliasAndExplicitTable(t *testing.T) {
	db, cleanup := newDB(t)
	defer cleanup()

	orgA := model.Organization{Name: "org-a-alias"}
	orgB := model.Organization{Name: "org-b-alias"}
	require.NoError(t, db.Create(&orgA).Error)
	require.NoError(t, db.Create(&orgB).Error)
	require.NoError(t, db.Create(&model.Membership{OrganizationID: orgA.ID, UserID: 61, Role: model.RoleOwner}).Error)
	require.NoError(t, db.Create(&model.Membership{OrganizationID: orgB.ID, UserID: 62, Role: model.RoleMember}).Error)

	// Aliased reference: GORM keeps the alias in Statement.Table and the real
	// name in TableExpr.
	var aliased []map[string]any
	require.NoError(t, store.ScopedByOrg(db, orgA.ID).Table("memberships AS m").Find(&aliased).Error)
	require.Len(t, aliased, 1, "aliased table must stay inside the tenant")

	// Explicit .Table must win over the model schema.
	var overModel []map[string]any
	require.NoError(t, store.ScopedByOrg(db, orgA.ID).Model(&model.Organization{}).Table("memberships").Find(&overModel).Error)
	require.Len(t, overModel, 1, "explicit .Table must override the model schema")

	// A model-only query on a non-scoped table is untouched.
	var orgs []model.Organization
	require.NoError(t, store.ScopedByOrg(db, orgA.ID).Find(&orgs).Error)
	require.Len(t, orgs, 2, "non-scoped models must not receive the tenant condition")
}

// A derived table cannot be scoped; with a tenant context the query must be
// rejected instead of silently reading every tenant.
func TestScopedByOrg_DerivedTableRejected(t *testing.T) {
	db, cleanup := newDB(t)
	defer cleanup()

	org := model.Organization{Name: "org-derived"}
	require.NoError(t, db.Create(&org).Error)
	require.NoError(t, db.Create(&model.Membership{OrganizationID: org.ID, UserID: 71, Role: model.RoleOwner}).Error)

	var rows []map[string]any
	err := store.ScopedByOrg(db, org.ID).Table("(SELECT * FROM memberships) AS m").Find(&rows).Error
	require.Error(t, err, "derived tables must be rejected under a tenant context")
	require.Empty(t, rows)
}

// A derived table must be rejected even without a tenant context.
func TestDerivedTable_RejectedWithoutContext(t *testing.T) {
	db, cleanup := newDB(t)
	defer cleanup()

	org := model.Organization{Name: "org-derived-noctx"}
	require.NoError(t, db.Create(&org).Error)
	require.NoError(t, db.Create(&model.Membership{OrganizationID: org.ID, UserID: 72, Role: model.RoleOwner}).Error)

	var rows []map[string]any
	err := db.Table("(SELECT * FROM memberships) AS m").Find(&rows).Error
	require.Error(t, err, "derived tables must be rejected regardless of tenant context")
	require.Empty(t, rows)
}

// Joining a scoped table must be rejected: the tenant condition cannot be
// attached reliably to the joined side.
func TestScopedByOrg_JoinOnScopedTableRejected(t *testing.T) {
	db, cleanup := newDB(t)
	defer cleanup()

	orgA := model.Organization{Name: "org-a-join"}
	orgB := model.Organization{Name: "org-b-join"}
	require.NoError(t, db.Create(&orgA).Error)
	require.NoError(t, db.Create(&orgB).Error)
	require.NoError(t, db.Create(&model.Membership{OrganizationID: orgA.ID, UserID: 81, Role: model.RoleOwner}).Error)
	require.NoError(t, db.Create(&model.Membership{OrganizationID: orgB.ID, UserID: 82, Role: model.RoleMember}).Error)

	var rows []map[string]any
	err := store.ScopedByOrg(db, orgA.ID).
		Table("organizations").
		Joins("JOIN memberships ON memberships.organization_id = organizations.id").
		Find(&rows).Error
	require.Error(t, err, "joins touching a scoped table must be rejected")
	require.Empty(t, rows)
}

// M2 Task 3: every address book table must be tenant-isolated (Review Focus #1).
func TestTenantIsolation_AddressBookTables(t *testing.T) {
	db, cleanup := newDB(t)
	defer cleanup()

	require.NoError(t, db.AutoMigrate(
		&model.AddressBook{}, &model.AddressBookPeer{},
		&model.AddressBookTag{}, &model.SyncCursor{},
	))

	orgA := model.Organization{Name: "org-ab-a"}
	orgB := model.Organization{Name: "org-ab-b"}
	require.NoError(t, db.Create(&orgA).Error)
	require.NoError(t, db.Create(&orgB).Error)

	owner := uint(101)
	bookA := model.AddressBook{OrganizationID: orgA.ID, OwnerID: &owner, Scope: model.AddressBookScopePersonal, Name: "personal-a"}
	require.NoError(t, db.Create(&bookA).Error)
	require.NoError(t, db.Create(&model.AddressBookPeer{
		OrganizationID: orgA.ID, BookID: bookA.ID, PeerID: "111111", Alias: "alpha",
	}).Error)
	require.NoError(t, db.Create(&model.AddressBookTag{
		OrganizationID: orgA.ID, BookID: bookA.ID, Name: "infra", Color: 16711680,
	}).Error)
	require.NoError(t, db.Create(&model.SyncCursor{
		OrganizationID: orgA.ID, UserID: owner, BookID: bookA.ID, LastRevision: 3,
	}).Error)

	// Org B must see nothing in any of the four tables.
	var books []model.AddressBook
	require.NoError(t, store.ScopedByOrg(db, orgB.ID).Find(&books).Error)
	require.Empty(t, books, "org B must not see org A address books")

	var peers []model.AddressBookPeer
	require.NoError(t, store.ScopedByOrg(db, orgB.ID).Find(&peers).Error)
	require.Empty(t, peers, "org B must not see org A peers")

	var tags []model.AddressBookTag
	require.NoError(t, store.ScopedByOrg(db, orgB.ID).Find(&tags).Error)
	require.Empty(t, tags, "org B must not see org A tags")

	var cursors []model.SyncCursor
	require.NoError(t, store.ScopedByOrg(db, orgB.ID).Find(&cursors).Error)
	require.Empty(t, cursors, "org B must not see org A sync cursors")

	// Org A still sees its own rows.
	var own []model.AddressBook
	require.NoError(t, store.ScopedByOrg(db, orgA.ID).Find(&own).Error)
	require.Len(t, own, 1)
}

// The (book_id, peer_id) pair is unique: re-inserting the same peer into the
// same book must surface gorm.ErrDuplicatedKey (TranslateError is enabled).
func TestAddressBookPeer_UniqueConstraint(t *testing.T) {
	db, cleanup := newDB(t)
	defer cleanup()

	require.NoError(t, db.AutoMigrate(&model.AddressBook{}, &model.AddressBookPeer{}))

	org := model.Organization{Name: "org-ab-uniq"}
	require.NoError(t, db.Create(&org).Error)
	owner := uint(201)
	book := model.AddressBook{OrganizationID: org.ID, OwnerID: &owner, Scope: model.AddressBookScopePersonal, Name: "uniq"}
	require.NoError(t, db.Create(&book).Error)

	peer := model.AddressBookPeer{OrganizationID: org.ID, BookID: book.ID, PeerID: "222222"}
	require.NoError(t, db.Create(&peer).Error)

	err := db.Create(&model.AddressBookPeer{OrganizationID: org.ID, BookID: book.ID, PeerID: "222222"}).Error
	require.ErrorIs(t, err, gorm.ErrDuplicatedKey, "duplicate (book_id, peer_id) must raise ErrDuplicatedKey")
}
