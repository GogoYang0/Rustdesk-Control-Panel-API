package addressbook

import (
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/authz"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/config"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

func newGrantFixture(t *testing.T) (*Service, uint, uint, uint) {
	t.Helper()
	dsn := "file:abgrants_" + fmt.Sprint(time.Now().UnixNano()) + "?mode=memory&cache=shared"
	st, err := store.Open(config.DatabaseConfig{Driver: "sqlite", DSN: dsn})
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	require.NoError(t, st.DB.AutoMigrate(
		&model.Organization{}, &model.Membership{},
		&model.AddressBook{}, &model.AddressBookPeer{}, &model.AddressBookTag{},
		&model.AddressBookGrant{},
		&model.UserGroup{}, &model.UserGroupMember{},
	))
	org := model.Organization{Name: "grants-acme"}
	require.NoError(t, st.DB.Create(&org).Error)
	owner := model.Membership{OrganizationID: org.ID, UserID: 7, RoleID: 1}
	member := model.Membership{OrganizationID: org.ID, UserID: 8, RoleID: 3}
	require.NoError(t, st.DB.Create(&owner).Error)
	require.NoError(t, st.DB.Create(&member).Error)
	return NewService(st.DB), org.ID, 7, 8
}

func sharedBook() *model.AddressBook {
	return &model.AddressBook{ID: 1, Scope: model.AddressBookScopeShared, Name: "team"}
}

func ptr(v uint) *uint { return &v }

func TestAccessFor_UserGrantOverridesEveryone(t *testing.T) {
	grants := []model.AddressBookGrant{
		{SubjectKind: model.GrantSubjectEveryone, Access: model.GrantAccessRead},
		{SubjectKind: model.GrantSubjectUser, SubjectUserID: 7, Access: model.GrantAccessFull},
	}
	require.Equal(t, AccessFull, AccessFor(nil, sharedBook(), 7, nil, grants))
	require.Equal(t, AccessRead, AccessFor(nil, sharedBook(), 8, nil, grants))
	require.Equal(t, AccessFull, AccessFor([]string{authz.PermAddressBook}, sharedBook(), 9, nil, grants),
		"the addressbook.write permission is full access")

	// A user-specific grant caps a broader everyone grant.
	capped := []model.AddressBookGrant{
		{SubjectKind: model.GrantSubjectEveryone, Access: model.GrantAccessFull},
		{SubjectKind: model.GrantSubjectUser, SubjectUserID: 7, Access: model.GrantAccessRead},
	}
	require.Equal(t, AccessRead, AccessFor(nil, sharedBook(), 7, nil, capped))
	require.Equal(t, AccessFull, AccessFor(nil, sharedBook(), 8, nil, capped))
}

// TestAccessFor_UserGroupGrantHighestWins pins D8: a user_group grant applies
// to the explicit members of the target group, and the effective level is the
// highest of every subject that matches the caller.
func TestAccessFor_UserGroupGrantHighestWins(t *testing.T) {
	grants := []model.AddressBookGrant{
		{SubjectKind: model.GrantSubjectUserGroup, SubjectGroupID: 11, Access: model.GrantAccessRead},
		{SubjectKind: model.GrantSubjectUserGroup, SubjectGroupID: 12, Access: model.GrantAccessWrite},
	}
	require.Equal(t, AccessWrite, AccessFor(nil, sharedBook(), 7, []uint{11, 12}, grants))
	require.Equal(t, AccessRead, AccessFor(nil, sharedBook(), 7, []uint{11}, grants))
	require.Equal(t, AccessRead, AccessFor(nil, sharedBook(), 7, nil, grants),
		"without a matching group the shared default stays read")
	require.Equal(t, AccessRead, AccessFor(nil, sharedBook(), 7, []uint{99}, grants),
		"only the caller's own groups count")

	// A group grant unions with the everyone grant: the highest wins.
	withEveryone := []model.AddressBookGrant{
		{SubjectKind: model.GrantSubjectEveryone, Access: model.GrantAccessFull},
		{SubjectKind: model.GrantSubjectUserGroup, SubjectGroupID: 11, Access: model.GrantAccessRead},
	}
	require.Equal(t, AccessFull, AccessFor(nil, sharedBook(), 7, []uint{11}, withEveryone))
	require.Equal(t, AccessRead, AccessFor(nil, sharedBook(), 7, []uint{11}, []model.AddressBookGrant{
		{SubjectKind: model.GrantSubjectUserGroup, SubjectGroupID: 11, Access: model.GrantAccessRead},
	}))

	// The explicit user grant keeps its precedence: it caps everything below it,
	// group grants included (M2 semantics, unchanged).
	capped := []model.AddressBookGrant{
		{SubjectKind: model.GrantSubjectUserGroup, SubjectGroupID: 11, Access: model.GrantAccessFull},
		{SubjectKind: model.GrantSubjectUser, SubjectUserID: 7, Access: model.GrantAccessRead},
	}
	require.Equal(t, AccessRead, AccessFor(nil, sharedBook(), 7, []uint{11}, capped))

	// The builtin write permission outranks every grant.
	require.Equal(t, AccessFull, AccessFor([]string{authz.PermAddressBook}, sharedBook(), 7, nil, grants))
}

func TestAccessFor_DefaultsAndPersonalPrivacy(t *testing.T) {
	// Every member may read a shared book, even without grants (M2 behavior).
	require.Equal(t, AccessRead, AccessFor(nil, sharedBook(), 42, nil, nil))
	require.Equal(t, AccessWrite, AccessFor(nil, sharedBook(), 42, nil, []model.AddressBookGrant{
		{SubjectKind: model.GrantSubjectEveryone, Access: model.GrantAccessWrite},
	}))

	personal := &model.AddressBook{ID: 2, Scope: model.AddressBookScopePersonal, OwnerID: ptr(7)}
	require.Equal(t, AccessFull, AccessFor(nil, personal, 7, nil, nil))
	require.Equal(t, AccessNone, AccessFor(nil, personal, 8, nil, nil))
	require.Equal(t, AccessNone, AccessFor([]string{authz.PermAddressBook}, personal, 8, nil, nil),
		"the write permission must not open someone else's personal book")
}

func TestUpsertGrant_UpsertsAndValidates(t *testing.T) {
	svc, orgID, ownerID, memberID := newGrantFixture(t)
	book, err := svc.Create(ownerID, orgID, model.AddressBookScopeShared, "team")
	require.NoError(t, err)
	perms := []string{authz.PermAddressBook}

	grant, created, err := svc.UpsertGrant(ownerID, orgID, book.ID, memberID, 0,
		model.GrantSubjectUser, model.GrantAccessWrite, perms)
	require.NoError(t, err)
	require.True(t, created)
	require.Equal(t, model.GrantAccessWrite, grant.Access)

	updated, created, err := svc.UpsertGrant(ownerID, orgID, book.ID, memberID, 0,
		model.GrantSubjectUser, model.GrantAccessFull, perms)
	require.NoError(t, err)
	require.False(t, created)
	require.Equal(t, model.GrantAccessFull, updated.Access)

	list, err := svc.ListGrants(ownerID, orgID, book.ID, perms)
	require.NoError(t, err)
	require.Len(t, list, 1)

	// everyone normalizes the subject id to the sentinel 0.
	everyone, _, err := svc.UpsertGrant(ownerID, orgID, book.ID, 999, 0,
		model.GrantSubjectEveryone, model.GrantAccessRead, perms)
	require.NoError(t, err)
	require.Zero(t, everyone.SubjectUserID)

	_, _, err = svc.UpsertGrant(ownerID, orgID, book.ID, 0, 0,
		model.GrantSubjectUser, model.GrantAccessRead, perms)
	require.ErrorIs(t, err, ErrInvalidGrant)

	_, _, err = svc.UpsertGrant(ownerID, orgID, book.ID, 424242, 0,
		model.GrantSubjectUser, model.GrantAccessRead, perms)
	require.ErrorIs(t, err, ErrSubjectNotMember)

	_, _, err = svc.UpsertGrant(ownerID, orgID, book.ID, memberID, 0,
		model.GrantSubjectUser, "admin", perms)
	require.ErrorIs(t, err, ErrInvalidGrant)

	personal, err := svc.Create(ownerID, orgID, model.AddressBookScopePersonal, "mine")
	require.NoError(t, err)
	_, _, err = svc.UpsertGrant(ownerID, orgID, personal.ID, memberID, 0,
		model.GrantSubjectUser, model.GrantAccessRead, perms)
	require.ErrorIs(t, err, ErrGrantNotShared)
}

func TestGrants_DelegatedLevelsAndRevocation(t *testing.T) {
	svc, orgID, ownerID, memberID := newGrantFixture(t)
	book, err := svc.Create(ownerID, orgID, model.AddressBookScopeShared, "team")
	require.NoError(t, err)
	perms := []string{authz.PermAddressBook}

	// Without a grant a member can read but not write.
	_, _, _, err = svc.Get(memberID, orgID, book.ID)
	require.NoError(t, err)
	_, err = svc.ReplacePeers(memberID, nil, orgID, book.ID, []PeerInput{{PeerID: "1"}})
	require.ErrorIs(t, err, ErrForbidden)
	_, err = svc.ListGrants(memberID, orgID, book.ID, nil)
	require.ErrorIs(t, err, ErrForbidden)

	// A write grant enables peers/tags but not rename, delete, or grants.
	_, _, err = svc.UpsertGrant(ownerID, orgID, book.ID, memberID, 0,
		model.GrantSubjectUser, model.GrantAccessWrite, perms)
	require.NoError(t, err)
	_, err = svc.ReplacePeers(memberID, nil, orgID, book.ID, []PeerInput{{PeerID: "1"}})
	require.NoError(t, err)
	_, err = svc.ReplaceTags(memberID, nil, orgID, book.ID, []TagInput{{Name: "lab"}})
	require.NoError(t, err)
	_, err = svc.Update(memberID, nil, orgID, book.ID, "renamed")
	require.ErrorIs(t, err, ErrForbidden)
	_, err = svc.Delete(memberID, nil, orgID, book.ID)
	require.ErrorIs(t, err, ErrForbidden)

	// A full grant opens the management surfaces.
	_, _, err = svc.UpsertGrant(ownerID, orgID, book.ID, memberID, 0,
		model.GrantSubjectUser, model.GrantAccessFull, perms)
	require.NoError(t, err)
	grants, err := svc.ListGrants(memberID, orgID, book.ID, nil)
	require.NoError(t, err)
	require.NotEmpty(t, grants)

	// Revoking returns the member to read-only.
	require.NoError(t, svc.DeleteGrant(ownerID, orgID, book.ID, grants[0].ID, perms))
	_, err = svc.ReplacePeers(memberID, nil, orgID, book.ID, []PeerInput{{PeerID: "2"}})
	require.ErrorIs(t, err, ErrForbidden)

	err = svc.DeleteGrant(ownerID, orgID, book.ID, grants[0].ID, perms)
	require.ErrorIs(t, err, ErrGrantNotFound)
}

func TestGrants_EveryoneWriteReachesMembers(t *testing.T) {
	svc, orgID, ownerID, memberID := newGrantFixture(t)
	book, err := svc.Create(ownerID, orgID, model.AddressBookScopeShared, "team")
	require.NoError(t, err)
	perms := []string{authz.PermAddressBook}

	_, _, err = svc.UpsertGrant(ownerID, orgID, book.ID, 0, 0,
		model.GrantSubjectEveryone, model.GrantAccessWrite, perms)
	require.NoError(t, err)
	_, err = svc.ReplacePeers(memberID, nil, orgID, book.ID, []PeerInput{{PeerID: "1"}})
	require.NoError(t, err)

	// A user-specific read grant deliberately caps that member again.
	_, _, err = svc.UpsertGrant(ownerID, orgID, book.ID, memberID, 0,
		model.GrantSubjectUser, model.GrantAccessRead, perms)
	require.NoError(t, err)
	_, err = svc.ReplacePeers(memberID, nil, orgID, book.ID, []PeerInput{{PeerID: "2"}})
	require.ErrorIs(t, err, ErrForbidden)
}

// TestUpsertGrant_UserGroupSubject pins the group subject: the row stores the
// group id (never a user id), the upsert is idempotent on the same group, and a
// group outside the organization is refused.
func TestUpsertGrant_UserGroupSubject(t *testing.T) {
	svc, orgID, ownerID, memberID := newGrantFixture(t)
	book, err := svc.Create(ownerID, orgID, model.AddressBookScopeShared, "team")
	require.NoError(t, err)
	perms := []string{authz.PermAddressBook}

	group := model.UserGroup{OrganizationID: orgID, Name: "ops", Kind: model.UserGroupKindCustom}
	require.NoError(t, svc.db.Create(&group).Error)
	otherOrg := model.Organization{Name: "grants-other"}
	require.NoError(t, svc.db.Create(&otherOrg).Error)
	foreign := model.UserGroup{OrganizationID: otherOrg.ID, Name: "foreign", Kind: model.UserGroupKindCustom}
	require.NoError(t, svc.db.Create(&foreign).Error)

	grant, created, err := svc.UpsertGrant(ownerID, orgID, book.ID, 0, group.ID,
		model.GrantSubjectUserGroup, model.GrantAccessWrite, perms)
	require.NoError(t, err)
	require.True(t, created)
	require.Equal(t, model.GrantSubjectUserGroup, grant.SubjectKind)
	require.EqualValues(t, group.ID, grant.SubjectGroupID)
	require.Zero(t, grant.SubjectUserID, "a group subject never stores a user id")

	updated, created, err := svc.UpsertGrant(ownerID, orgID, book.ID, memberID, group.ID,
		model.GrantSubjectUserGroup, model.GrantAccessFull, perms)
	require.NoError(t, err)
	require.False(t, created, "the same group upserts the same row")
	require.EqualValues(t, grant.ID, updated.ID)
	require.Equal(t, model.GrantAccessFull, updated.Access)
	require.Zero(t, updated.SubjectUserID, "a stray subject_user_id is normalized away")

	list, err := svc.ListGrants(ownerID, orgID, book.ID, perms)
	require.NoError(t, err)
	require.Len(t, list, 1)

	_, _, err = svc.UpsertGrant(ownerID, orgID, book.ID, 0, 0,
		model.GrantSubjectUserGroup, model.GrantAccessRead, perms)
	require.ErrorIs(t, err, ErrInvalidGrant, "a group subject needs a group id")

	_, _, err = svc.UpsertGrant(ownerID, orgID, book.ID, 0, foreign.ID,
		model.GrantSubjectUserGroup, model.GrantAccessRead, perms)
	require.ErrorIs(t, err, ErrGrantSubjectNotFound, "another organization's group is not a subject")

	// The reserved everyone group has no explicit members: a grant on it would
	// never match anybody, so it is refused instead of silently dead.
	everyone := model.UserGroup{OrganizationID: orgID, Name: "everyone", Kind: model.UserGroupKindEveryone}
	require.NoError(t, svc.db.Create(&everyone).Error)
	_, _, err = svc.UpsertGrant(ownerID, orgID, book.ID, 0, everyone.ID,
		model.GrantSubjectUserGroup, model.GrantAccessRead, perms)
	require.ErrorIs(t, err, ErrInvalidGrant)
	require.Contains(t, err.Error(), "subject_kind=everyone")
}

// TestUpsertGrant_ChecksPermissionBeforeSubjectExistence pins the order of the
// checks: an unauthorized caller learns nothing about stored subjects, so the
// grant-management permission must be resolved before any subject lookup.
func TestUpsertGrant_ChecksPermissionBeforeSubjectExistence(t *testing.T) {
	svc, orgID, ownerID, memberID := newGrantFixture(t)
	book, err := svc.Create(ownerID, orgID, model.AddressBookScopeShared, "team")
	require.NoError(t, err)

	// The plain member reads shared books but manages no grants.
	_, _, err = svc.UpsertGrant(memberID, orgID, book.ID, 0, 424242,
		model.GrantSubjectUserGroup, model.GrantAccessRead, nil)
	require.ErrorIs(t, err, ErrForbidden, "a missing group must not be distinguishable from a forbidden call")

	_, _, err = svc.UpsertGrant(memberID, orgID, book.ID, 424242, 0,
		model.GrantSubjectUser, model.GrantAccessRead, nil)
	require.ErrorIs(t, err, ErrForbidden, "a missing member must not be distinguishable from a forbidden call")
}

// TestUpsertGrant_ValidatesSubjectInsideTheWriteTransaction pins where the
// subject lookup runs: on the same transaction as the grant insert, after the
// organization row lock DeleteUserGroup takes. A lookup outside the transaction
// leaves a window in which the deletion commits first and the grant outlives
// the group it points at (CWE-367): the orphan row would silently come back to
// life if a new group ever reused that id, which is precisely what the delete
// cascade exists to prevent.
func TestUpsertGrant_ValidatesSubjectInsideTheWriteTransaction(t *testing.T) {
	svc, orgID, ownerID, _ := newGrantFixture(t)
	book, err := svc.Create(ownerID, orgID, model.AddressBookScopeShared, "team")
	require.NoError(t, err)
	perms := []string{authz.PermAddressBook}
	group := model.UserGroup{OrganizationID: orgID, Name: "ops", Kind: model.UserGroupKindCustom}
	require.NoError(t, svc.db.Create(&group).Error)

	// Test-only probe: GORM runs the query callbacks with the statement the
	// caller issued, so the connection type tells whether the subject lookup
	// rode the transaction.
	var seen, insideTx bool
	require.NoError(t, svc.db.Callback().Query().After("gorm:query").
		Register("test:probe_user_group_lookup", func(db *gorm.DB) {
			if db.Statement.Table != "user_groups" {
				return
			}
			seen = true
			_, isTx := db.Statement.ConnPool.(*sql.Tx)
			insideTx = isTx
		}))
	t.Cleanup(func() { _ = svc.db.Callback().Query().Remove("test:probe_user_group_lookup") })

	_, _, err = svc.UpsertGrant(ownerID, orgID, book.ID, 0, group.ID,
		model.GrantSubjectUserGroup, model.GrantAccessRead, perms)
	require.NoError(t, err)
	require.True(t, seen, "the subject lookup must run at all")
	require.True(t, insideTx,
		"the subject must be validated on the grant transaction, not on a bare connection")
}

// TestGrants_UserGroupReachesItsMembers walks the group grant through the
// service: the member of the granted group gains the level, a member outside it
// does not.
func TestGrants_UserGroupReachesItsMembers(t *testing.T) {
	svc, orgID, ownerID, memberID := newGrantFixture(t)
	book, err := svc.Create(ownerID, orgID, model.AddressBookScopeShared, "team")
	require.NoError(t, err)
	perms := []string{authz.PermAddressBook}

	group := model.UserGroup{OrganizationID: orgID, Name: "ops", Kind: model.UserGroupKindCustom}
	require.NoError(t, svc.db.Create(&group).Error)
	require.NoError(t, svc.db.Create(&model.UserGroupMember{
		OrganizationID: orgID, GroupID: group.ID, UserID: memberID,
	}).Error)

	// Without the grant the member can read but not write.
	_, err = svc.ReplacePeers(memberID, nil, orgID, book.ID, []PeerInput{{PeerID: "1"}})
	require.ErrorIs(t, err, ErrForbidden)

	_, _, err = svc.UpsertGrant(ownerID, orgID, book.ID, 0, group.ID,
		model.GrantSubjectUserGroup, model.GrantAccessWrite, perms)
	require.NoError(t, err)
	_, err = svc.ReplacePeers(memberID, nil, orgID, book.ID, []PeerInput{{PeerID: "1"}})
	require.NoError(t, err)

	// A user outside the group keeps the default read level.
	outsider := model.Membership{OrganizationID: orgID, UserID: 9, RoleID: 3}
	require.NoError(t, svc.db.Create(&outsider).Error)
	_, err = svc.ReplacePeers(9, nil, orgID, book.ID, []PeerInput{{PeerID: "2"}})
	require.ErrorIs(t, err, ErrForbidden)
}
