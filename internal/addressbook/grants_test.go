package addressbook

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

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
	require.Equal(t, AccessFull, AccessFor(nil, sharedBook(), 7, grants))
	require.Equal(t, AccessRead, AccessFor(nil, sharedBook(), 8, grants))
	require.Equal(t, AccessFull, AccessFor([]string{authz.PermAddressBook}, sharedBook(), 9, grants),
		"the addressbook.write permission is full access")

	// A user-specific grant caps a broader everyone grant.
	capped := []model.AddressBookGrant{
		{SubjectKind: model.GrantSubjectEveryone, Access: model.GrantAccessFull},
		{SubjectKind: model.GrantSubjectUser, SubjectUserID: 7, Access: model.GrantAccessRead},
	}
	require.Equal(t, AccessRead, AccessFor(nil, sharedBook(), 7, capped))
	require.Equal(t, AccessFull, AccessFor(nil, sharedBook(), 8, capped))
}

func TestAccessFor_DefaultsAndPersonalPrivacy(t *testing.T) {
	// Every member may read a shared book, even without grants (M2 behavior).
	require.Equal(t, AccessRead, AccessFor(nil, sharedBook(), 42, nil))
	require.Equal(t, AccessWrite, AccessFor(nil, sharedBook(), 42, []model.AddressBookGrant{
		{SubjectKind: model.GrantSubjectEveryone, Access: model.GrantAccessWrite},
	}))

	personal := &model.AddressBook{ID: 2, Scope: model.AddressBookScopePersonal, OwnerID: ptr(7)}
	require.Equal(t, AccessFull, AccessFor(nil, personal, 7, nil))
	require.Equal(t, AccessNone, AccessFor(nil, personal, 8, nil))
	require.Equal(t, AccessNone, AccessFor([]string{authz.PermAddressBook}, personal, 8, nil),
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
