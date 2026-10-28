package account_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/account"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/authz"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/config"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

type fixture struct {
	db    *gorm.DB
	roles *authz.RoleService
	svc   *account.Service
}

var seq int

func newFixture(t *testing.T) *fixture {
	t.Helper()
	db := openDB(t)
	require.NoError(t, db.AutoMigrate(
		&model.Organization{}, &model.User{}, &model.Membership{},
		&model.Role{}, &model.UserTOTP{},
	))
	roles := authz.NewRoleService(db)
	return &fixture{db: db, roles: roles, svc: account.NewService(db, roles)}
}

func openDB(t *testing.T) *gorm.DB {
	t.Helper()
	var (
		st  *store.Store
		err error
	)
	switch {
	case os.Getenv("TEST_POSTGRES_DSN") != "":
		st, err = store.Open(config.DatabaseConfig{Driver: "postgres", DSN: os.Getenv("TEST_POSTGRES_DSN")})
	case os.Getenv("TEST_MYSQL_DSN") != "":
		st, err = store.Open(config.DatabaseConfig{Driver: "mysql", DSN: os.Getenv("TEST_MYSQL_DSN")})
	default:
		seq++
		st, err = store.Open(config.DatabaseConfig{
			Driver: "sqlite",
			DSN:    fmt.Sprintf("file:account_%d?mode=memory&cache=shared", seq),
		})
	}
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	return st.DB
}

// orgWithRole creates an organization with the builtin roles and a user whose
// membership carries the role of the given kind.
func (f *fixture) orgWithRole(t *testing.T, name, kind string) (model.Organization, model.User) {
	t.Helper()
	org := model.Organization{Name: name}
	require.NoError(t, f.db.Create(&org).Error)
	require.NoError(t, f.roles.EnsureBuiltins(org.ID))
	var stored model.Role
	require.NoError(t, store.WithoutTenantScope(f.db).
		Where("organization_id = ? AND kind = ?", org.ID, kind).First(&stored).Error)

	user := model.User{Email: fmt.Sprintf("%s-%d@example.com", name, seq), PasswordHash: "hash", EmailVerified: true}
	require.NoError(t, f.db.Create(&user).Error)
	require.NoError(t, f.db.Create(&model.Membership{
		OrganizationID: org.ID, UserID: user.ID, RoleID: stored.ID,
	}).Error)
	return org, user
}

func TestMe_BuiltinRolesCarryTheirPermissions(t *testing.T) {
	for _, kind := range []string{model.RoleKindOwner, model.RoleKindAdmin, model.RoleKindMember} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			org, user := f.orgWithRole(t, "acme-"+kind, kind)

			me, err := f.svc.Me(context.Background(), user.ID)
			require.NoError(t, err)
			require.Len(t, me.Orgs, 1)
			require.Equal(t, org.ID, me.Orgs[0].ID)
			require.Equal(t, org.Name, me.Orgs[0].Name)
			require.Equal(t, kind, me.Orgs[0].RoleKind)
			require.ElementsMatch(t, authz.BuiltinPermissions(kind), me.Orgs[0].Permissions)
			require.Equal(t, user.Email, me.User.Email)
			require.True(t, me.User.EmailVerified)
		})
	}
}

func TestMe_CustomRoleUsesItsStoredPermissions(t *testing.T) {
	f := newFixture(t)
	org, user := f.orgWithRole(t, "acme-custom", model.RoleKindMember)

	custom := model.Role{OrganizationID: org.ID, Name: "auditor", Kind: model.RoleKindCustom, AuditScope: "org"}
	require.NoError(t, custom.SetPermissions([]string{"audit.read", "device.read"}))
	require.NoError(t, f.db.Create(&custom).Error)
	require.NoError(t, store.ScopedByOrg(f.db, org.ID).Model(&model.Membership{}).
		Where("user_id = ?", user.ID).
		Update("role_id", custom.ID).Error)

	me, err := f.svc.Me(context.Background(), user.ID)
	require.NoError(t, err)
	require.Len(t, me.Orgs, 1)
	require.Equal(t, model.RoleKindCustom, me.Orgs[0].RoleKind)
	require.ElementsMatch(t, []string{"audit.read", "device.read"}, me.Orgs[0].Permissions)
}

func TestMe_OmitsDisabledMembership(t *testing.T) {
	f := newFixture(t)
	org, user := f.orgWithRole(t, "acme-disabled", model.RoleKindMember)
	require.NoError(t, store.ScopedByOrg(f.db, org.ID).Model(&model.Membership{}).
		Where("user_id = ?", user.ID).Update("disabled", true).Error)

	me, err := f.svc.Me(context.Background(), user.ID)
	require.NoError(t, err)
	require.Empty(t, me.Orgs, "a disabled membership authorizes nothing and must not be listed")
}

func TestMe_OmitsUnresolvableRole(t *testing.T) {
	f := newFixture(t)
	org, user := f.orgWithRole(t, "acme-dangling", model.RoleKindMember)
	// A membership pointing at a role row that does not exist authorizes
	// nothing; listing it with an empty permission set would tell the console the
	// user still belongs to the organization.
	require.NoError(t, store.ScopedByOrg(f.db, org.ID).Model(&model.Membership{}).
		Where("user_id = ?", user.ID).Update("role_id", 424242).Error)

	me, err := f.svc.Me(context.Background(), user.ID)
	require.NoError(t, err)
	require.Empty(t, me.Orgs)
}

func TestMe_OnlyReturnsOwnOrganizations(t *testing.T) {
	f := newFixture(t)
	mine, me := f.orgWithRole(t, "acme-mine", model.RoleKindMember)
	other, otherUser := f.orgWithRole(t, "acme-other", model.RoleKindOwner)
	require.NotEqual(t, me.ID, otherUser.ID)

	got, err := f.svc.Me(context.Background(), me.ID)
	require.NoError(t, err)
	require.Len(t, got.Orgs, 1)
	require.Equal(t, mine.ID, got.Orgs[0].ID)
	require.NotEqual(t, other.ID, got.Orgs[0].ID)
}

func TestMe_OrgsAreOrderedAndNeverNull(t *testing.T) {
	f := newFixture(t)
	user := model.User{Email: "multi@example.com", PasswordHash: "hash", EmailVerified: true}
	require.NoError(t, f.db.Create(&user).Error)
	var first, second uint
	for i, name := range []string{"zeta", "alpha"} {
		org := model.Organization{Name: name}
		require.NoError(t, f.db.Create(&org).Error)
		require.NoError(t, f.roles.EnsureBuiltins(org.ID))
		var role model.Role
		require.NoError(t, store.WithoutTenantScope(f.db).
			Where("organization_id = ? AND kind = ?", org.ID, model.RoleKindMember).First(&role).Error)
		require.NoError(t, f.db.Create(&model.Membership{OrganizationID: org.ID, UserID: user.ID, RoleID: role.ID}).Error)
		if i == 0 {
			first = org.ID
		} else {
			second = org.ID
		}
	}

	got, err := f.svc.Me(context.Background(), user.ID)
	require.NoError(t, err)
	require.Len(t, got.Orgs, 2)
	require.Less(t, got.Orgs[0].ID, got.Orgs[1].ID, "orgs are ordered by id")
	require.Equal(t, first, got.Orgs[0].ID)
	require.Equal(t, second, got.Orgs[1].ID)

	raw, err := json.Marshal(got)
	require.NoError(t, err)
	require.Contains(t, string(raw), `"orgs":[`, "an empty or single list is still an array")

	// A user with no memberships at all serializes to [] rather than null.
	lonely := model.User{Email: "lonely@example.com", PasswordHash: "hash", EmailVerified: true}
	require.NoError(t, f.db.Create(&lonely).Error)
	none, err := f.svc.Me(context.Background(), lonely.ID)
	require.NoError(t, err)
	require.NotNil(t, none.Orgs)
	noneRaw, err := json.Marshal(none)
	require.NoError(t, err)
	require.Contains(t, string(noneRaw), `"orgs":[]`)
}

func TestMe_PasskeyOnlyAccountHasNoPassword(t *testing.T) {
	f := newFixture(t)
	_, user := f.orgWithRole(t, "acme-passkey", model.RoleKindMember)
	require.NoError(t, f.db.Model(&model.User{}).Where("id = ?", user.ID).
		Update("password_hash", "").Error)

	me, err := f.svc.Me(context.Background(), user.ID)
	require.NoError(t, err)
	require.False(t, me.User.HasPassword)

	now := time.Now()
	require.NoError(t, f.db.Create(&model.UserTOTP{
		UserID: user.ID, SecretCiphertext: "x", RecoveryCodes: "[]", EnabledAt: &now,
	}).Error)
	me, err = f.svc.Me(context.Background(), user.ID)
	require.NoError(t, err)
	require.True(t, me.User.TOTPEnabled)
}

func TestMe_UnknownUserIsNotFound(t *testing.T) {
	f := newFixture(t)
	_, err := f.svc.Me(context.Background(), 999)
	require.ErrorIs(t, err, account.ErrNotFound)
	require.False(t, errors.Is(err, account.ErrInvalidInput))

	_, err = f.svc.Me(context.Background(), 0)
	require.ErrorIs(t, err, account.ErrInvalidInput)
}
