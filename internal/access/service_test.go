package access_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/access"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/audit"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// newGroupFixture seeds one organization with the access defaults and one
// membership, and returns a service backed by the real transactional auditor.
func newGroupFixture(t *testing.T) (*store.Store, *access.Service, model.Organization, model.User) {
	t.Helper()
	st := accessTestStore(t)
	org := model.Organization{Name: "group-org"}
	require.NoError(t, st.DB.Create(&org).Error)
	user := model.User{Email: "member@example.com", PasswordHash: "x", EmailVerified: true}
	require.NoError(t, st.DB.Create(&user).Error)
	require.NoError(t, st.DB.Create(&model.Membership{
		OrganizationID: org.ID, UserID: user.ID, Role: model.RoleMember,
	}).Error)
	require.NoError(t, access.Migrate(st.DB))
	svc := access.NewService(st.DB, audit.NewGormAuditor(st.DB), nil)
	return st, svc, org, user
}

func everyoneGroup(t *testing.T, st *store.Store, orgID uint) model.UserGroup {
	t.Helper()
	var group model.UserGroup
	require.NoError(t, store.ScopedByOrg(st.DB, orgID).
		Where("kind = ?", model.UserGroupKindEveryone).First(&group).Error)
	return group
}

// TestAccess_ReservedUserGroupGuard pins the reserved-name policy: everyone is
// created only by the seed, cannot be renamed or deleted, its member set is
// implicit, and a custom group cannot claim the name in any casing.
func TestAccess_ReservedUserGroupGuard(t *testing.T) {
	ctx := context.Background()
	st, svc, org, _ := newGroupFixture(t)
	everyone := everyoneGroup(t, st, org.ID)

	_, err := svc.CreateUserGroup(ctx, org.ID, 1, "Everyone")
	require.ErrorIs(t, err, access.ErrReservedGroup)

	_, err = svc.RenameUserGroup(ctx, org.ID, 1, everyone.ID, "staff")
	require.ErrorIs(t, err, access.ErrReservedGroup)

	_, err = svc.DeleteUserGroup(ctx, org.ID, 1, everyone.ID)
	require.ErrorIs(t, err, access.ErrReservedGroup)

	_, _, err = svc.ReplaceUserGroupMembers(ctx, org.ID, 1, everyone.ID, []uint{2})
	require.ErrorIs(t, err, access.ErrReservedGroup)
}

// TestAccess_UserGroupCreateListAndMembers covers the happy path plus the
// idempotent full replacement: the second identical call changes nothing and
// the list reports the stored member ids for PUT round-tripping.
func TestAccess_UserGroupCreateListAndMembers(t *testing.T) {
	ctx := context.Background()
	_, svc, org, user := newGroupFixture(t)

	group, err := svc.CreateUserGroup(ctx, org.ID, 1, "  Team A  ")
	require.NoError(t, err)
	require.Equal(t, "Team A", group.Name)
	require.Equal(t, model.UserGroupKindCustom, group.Kind)

	// Case-insensitive duplicate: the reserved/unique comparison must not depend
	// on the database's collation.
	_, err = svc.CreateUserGroup(ctx, org.ID, 1, "team a")
	require.ErrorIs(t, err, access.ErrGroupNameTaken)

	removed, added, err := svc.ReplaceUserGroupMembers(ctx, org.ID, 1, group.ID, []uint{user.ID})
	require.NoError(t, err)
	require.Zero(t, removed)
	require.Equal(t, 1, added)

	removed, added, err = svc.ReplaceUserGroupMembers(ctx, org.ID, 1, group.ID, []uint{user.ID})
	require.NoError(t, err)
	require.Zero(t, removed, "an identical replacement removes nothing")
	require.Zero(t, added, "an identical replacement adds nothing")

	views, err := svc.ListUserGroups(ctx, org.ID)
	require.NoError(t, err)
	require.Len(t, views, 2)

	byKind := map[string]access.GroupView{}
	for _, v := range views {
		byKind[v.Group.Kind] = v
	}
	require.Empty(t, byKind[model.UserGroupKindEveryone].MemberIDs, "everyone membership is implicit")
	require.Equal(t, []uint{user.ID}, byKind[model.UserGroupKindCustom].MemberIDs)
}

// TestAccess_ReplaceMembersRejectsForeignUser pins the all-or-nothing member
// rule: a user outside the organization (or an id that does not exist) rejects
// the whole request and writes nothing.
func TestAccess_ReplaceMembersRejectsForeignUser(t *testing.T) {
	ctx := context.Background()
	st, svc, org, user := newGroupFixture(t)

	other := model.Organization{Name: "other-org"}
	require.NoError(t, st.DB.Create(&other).Error)
	foreign := model.User{Email: "foreign@example.com", PasswordHash: "x", EmailVerified: true}
	require.NoError(t, st.DB.Create(&foreign).Error)
	require.NoError(t, st.DB.Create(&model.Membership{
		OrganizationID: other.ID, UserID: foreign.ID, Role: model.RoleMember,
	}).Error)

	group, err := svc.CreateUserGroup(ctx, org.ID, 1, "Team")
	require.NoError(t, err)

	_, _, err = svc.ReplaceUserGroupMembers(ctx, org.ID, 1, group.ID, []uint{user.ID, foreign.ID})
	require.ErrorIs(t, err, access.ErrInvalidMember)

	_, _, err = svc.ReplaceUserGroupMembers(ctx, org.ID, 1, group.ID, []uint{user.ID, 999999})
	require.ErrorIs(t, err, access.ErrInvalidMember)

	var members int64
	require.NoError(t, store.ScopedByOrg(st.DB, org.ID).
		Model(&model.UserGroupMember{}).Where("group_id = ?", group.ID).Count(&members).Error)
	require.Zero(t, members, "a rejected replacement must not keep the valid ids")
}

// TestAccess_DeleteUserGroupCascades covers deletion of a custom group: its
// member rows and the rules whose source is the group disappear with it.
func TestAccess_DeleteUserGroupCascades(t *testing.T) {
	ctx := context.Background()
	st, svc, org, user := newGroupFixture(t)

	group, err := svc.CreateUserGroup(ctx, org.ID, 1, "Team")
	require.NoError(t, err)
	_, _, err = svc.ReplaceUserGroupMembers(ctx, org.ID, 1, group.ID, []uint{user.ID})
	require.NoError(t, err)

	rule := model.AccessRule{
		OrganizationID: org.ID, SourceGroupID: group.ID,
		TargetKind: model.AccessTargetKindAllDevices, TargetGroupID: 0,
	}
	require.NoError(t, st.DB.Create(&rule).Error)

	_, err = svc.DeleteUserGroup(ctx, org.ID, 1, group.ID)
	require.NoError(t, err)

	var groups int64
	require.NoError(t, store.ScopedByOrg(st.DB, org.ID).
		Model(&model.UserGroup{}).Where("id = ?", group.ID).Count(&groups).Error)
	require.Zero(t, groups)

	var members int64
	require.NoError(t, store.ScopedByOrg(st.DB, org.ID).
		Model(&model.UserGroupMember{}).Where("group_id = ?", group.ID).Count(&members).Error)
	require.Zero(t, members)

	var rules int64
	require.NoError(t, store.ScopedByOrg(st.DB, org.ID).
		Model(&model.AccessRule{}).Where("source_group_id = ?", group.ID).Count(&rules).Error)
	require.Zero(t, rules)

	// The default everyone rule is untouched by deleting a custom group.
	var defaultRules int64
	require.NoError(t, store.ScopedByOrg(st.DB, org.ID).
		Model(&model.AccessRule{}).Count(&defaultRules).Error)
	require.EqualValues(t, 1, defaultRules)
}

// TestAccess_UserGroupWriteFailsClosed pins the audit contract: without a
// transactional recorder the mutation must not happen at all.
func TestAccess_UserGroupWriteFailsClosed(t *testing.T) {
	ctx := context.Background()
	st, _, org, _ := newGroupFixture(t)
	unaudited := access.NewService(st.DB, nil, nil)

	_, err := unaudited.CreateUserGroup(ctx, org.ID, 1, "Team")
	require.ErrorIs(t, err, access.ErrAuditUnavailable)

	var count int64
	require.NoError(t, store.ScopedByOrg(st.DB, org.ID).
		Model(&model.UserGroup{}).Where("kind = ?", model.UserGroupKindCustom).Count(&count).Error)
	require.Zero(t, count)
}
