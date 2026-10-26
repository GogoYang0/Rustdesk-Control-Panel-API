package addressbook

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/config"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// TestMigrateGrantSubjectIndex_RebuildsFourColumnIndex covers an upgraded
// database: the pre-upgrade index covered three columns, so every user_group
// grant collapsed onto the 0 sentinel and only one of them could exist per
// book. The migration must replace that index, not add a second one.
func TestMigrateGrantSubjectIndex_RebuildsFourColumnIndex(t *testing.T) {
	dsn := fmt.Sprintf("file:abindex_%d?mode=memory&cache=shared", time.Now().UnixNano())
	st, err := store.Open(config.DatabaseConfig{Driver: "sqlite", DSN: dsn})
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	require.NoError(t, st.DB.AutoMigrate(
		&model.Organization{}, &model.AddressBook{}, &model.AddressBookGrant{}, &model.MigrationMark{}))

	// Simulate the pre-upgrade shape: same index name, three columns.
	require.NoError(t, st.DB.Exec("DROP INDEX idx_abg_book_subject").Error)
	require.NoError(t, st.DB.Exec(
		"CREATE UNIQUE INDEX idx_abg_book_subject ON address_book_grants(book_id, subject_kind, subject_user_id)").Error)

	require.NoError(t, MigrateGrantSubjectIndex(st.DB))

	var mark model.MigrationMark
	require.NoError(t, st.DB.Where("name = ?", GrantSubjectIndexMark).First(&mark).Error)

	org := model.Organization{Name: "ab-index"}
	require.NoError(t, st.DB.Create(&org).Error)
	book := model.AddressBook{OrganizationID: org.ID, Scope: model.AddressBookScopeShared, Name: "shared"}
	require.NoError(t, st.DB.Create(&book).Error)

	everyone := model.AddressBookGrant{
		OrganizationID: org.ID, BookID: book.ID,
		SubjectKind: model.GrantSubjectUserGroup, SubjectGroupID: 0, Access: model.GrantAccessRead,
	}
	require.NoError(t, st.DB.Create(&everyone).Error)

	specific := everyone
	specific.ID = 0
	specific.SubjectGroupID = 7
	require.NoError(t, st.DB.Create(&specific).Error,
		"two user-group grants must be distinguishable by group id")

	duplicate := specific
	duplicate.ID = 0
	require.Error(t, st.DB.Create(&duplicate).Error,
		"the same (book, kind, user, group) tuple must still be unique")
}

// TestMigrateGrantSubjectIndex_RunsOnce pins the marker: a second boot must not
// drop and rebuild the (potentially large) index again. The proof is that the
// migration does not repair an index it did not create: a three-column index
// recreated after the mark stays in place and keeps collapsing group grants.
func TestMigrateGrantSubjectIndex_RunsOnce(t *testing.T) {
	dsn := fmt.Sprintf("file:abindexonce_%d?mode=memory&cache=shared", time.Now().UnixNano())
	st, err := store.Open(config.DatabaseConfig{Driver: "sqlite", DSN: dsn})
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	require.NoError(t, st.DB.AutoMigrate(
		&model.Organization{}, &model.AddressBook{}, &model.AddressBookGrant{}, &model.MigrationMark{}))

	require.NoError(t, MigrateGrantSubjectIndex(st.DB))

	// Recreate the legacy shape behind the migration's back: the guard must
	// leave it alone, because the rebuild is not supposed to run on every boot.
	require.NoError(t, st.DB.Exec("DROP INDEX idx_abg_book_subject").Error)
	require.NoError(t, st.DB.Exec(
		"CREATE UNIQUE INDEX idx_abg_book_subject ON address_book_grants(book_id, subject_kind, subject_user_id)").Error)
	require.NoError(t, MigrateGrantSubjectIndex(st.DB))
	require.NoError(t, MigrateGrantSubjectIndex(st.DB), "repeated boots stay no-ops")

	org := model.Organization{Name: "ab-index-once"}
	require.NoError(t, st.DB.Create(&org).Error)
	book := model.AddressBook{OrganizationID: org.ID, Scope: model.AddressBookScopeShared, Name: "shared"}
	require.NoError(t, st.DB.Create(&book).Error)

	first := model.AddressBookGrant{
		OrganizationID: org.ID, BookID: book.ID,
		SubjectKind: model.GrantSubjectUserGroup, SubjectGroupID: 7, Access: model.GrantAccessRead,
	}
	require.NoError(t, st.DB.Create(&first).Error)
	second := first
	second.ID = 0
	second.SubjectGroupID = 8
	require.Error(t, st.DB.Create(&second).Error,
		"the legacy index is still in place: the migration must not have run a second time")
}
