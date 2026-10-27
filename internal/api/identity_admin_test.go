package api_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/api"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

func identityAdminFixture(t *testing.T) (*harness, int64, model.User, string, string) {
	t.Helper()

	h, orgID, _, _, member, ownerToken, adminToken, _ := m4OrgWith(t, func(d *api.Deps) {})
	row := model.UserIdentity{
		UserID:   member.ID,
		Provider: model.IdentityProviderOIDC,
		Issuer:   "https://idp.example.com",
		Subject:  "subject-admin-reset",
		Email:    "oidc-admin-reset@example.com",
		LinkedAt: time.Now(),
	}
	require.NoError(t, h.db.DB.Create(&row).Error)
	return h, orgID, member, ownerToken, adminToken
}

func TestResetMemberIdentity_OwnerResetsMember(t *testing.T) {
	h, orgID, member, ownerToken, _ := identityAdminFixture(t)

	w := h.do(t, http.MethodPost, "/api/v1/orgs/"+itoa(orgID)+"/members/"+itoa(int64(member.ID))+"/identity/reset", nil, ownerToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var count int64
	require.NoError(t, h.db.DB.Model(&model.UserIdentity{}).Where("user_id = ?", member.ID).Count(&count).Error)
	require.Zero(t, count)

	var audits int64
	// audit_logs is tenant-scoped: the raw handle needs an explicit bypass.
	require.NoError(t, store.WithoutTenantScope(h.db.DB).Model(&model.AuditLog{}).
		Where("action = ?", "user.identity.reset").Count(&audits).Error)
	require.EqualValues(t, 1, audits)
}

func TestResetMemberIdentity_Guards(t *testing.T) {
	h, orgID, member, ownerToken, adminToken := identityAdminFixture(t)

	// An admin cannot reset an owner.
	w := h.do(t, http.MethodPost, "/api/v1/orgs/"+itoa(orgID)+"/members/1/identity/reset", nil, adminToken)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

	// Nobody resets their own bindings.
	w = h.do(t, http.MethodPost, "/api/v1/orgs/"+itoa(orgID)+"/members/1/identity/reset", nil, ownerToken)
	require.Equal(t, http.StatusConflict, w.Code, w.Body.String())

	// A member without member.manage is refused before anything else.
	memberJWT := h.login(t, member.Email, "password123")
	w = h.do(t, http.MethodPost, "/api/v1/orgs/"+itoa(orgID)+"/members/"+itoa(int64(member.ID))+"/identity/reset", nil, memberJWT)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

	var count int64
	require.NoError(t, h.db.DB.Model(&model.UserIdentity{}).Where("user_id = ?", member.ID).Count(&count).Error)
	require.EqualValues(t, 1, count, "refused resets must not delete anything")
}

func TestResetMemberIdentity_CrossOrgTargetRefused(t *testing.T) {
	h, orgID, member, ownerToken, _ := identityAdminFixture(t)

	memberJWT := h.login(t, member.Email, "password123")
	require.NotZero(t, createOrg(t, h, memberJWT, "oidc-second-org"))

	w := h.do(t, http.MethodPost, "/api/v1/orgs/"+itoa(orgID)+"/members/"+itoa(int64(member.ID))+"/identity/reset", nil, ownerToken)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

	var count int64
	require.NoError(t, h.db.DB.Model(&model.UserIdentity{}).Where("user_id = ?", member.ID).Count(&count).Error)
	require.EqualValues(t, 1, count)
}

func TestResetMemberIdentity_WorkingBindingIsLockout(t *testing.T) {
	h, orgID, member, ownerToken, _ := identityAdminFixture(t)
	// No password, no passkeys: the working SSO binding is the only credential.
	require.NoError(t, h.db.DB.Model(&model.User{}).Where("id = ?", member.ID).Update("password_hash", "").Error)

	w := h.do(t, http.MethodPost, "/api/v1/orgs/"+itoa(orgID)+"/members/"+itoa(int64(member.ID))+"/identity/reset", nil, ownerToken)
	require.Equal(t, http.StatusConflict, w.Code, w.Body.String())

	var count int64
	require.NoError(t, h.db.DB.Model(&model.UserIdentity{}).Where("user_id = ?", member.ID).Count(&count).Error)
	require.EqualValues(t, 1, count, "the refused reset must not delete bindings")
}

// TestResetMemberIdentity_ConflictedBindingAllowed pins the O14 exception: a
// binding marked conflict_at is already unusable, so resetting it is the only
// way to repair the account.
func TestResetMemberIdentity_ConflictedBindingAllowed(t *testing.T) {
	h, orgID, member, ownerToken, _ := identityAdminFixture(t)
	require.NoError(t, h.db.DB.Model(&model.User{}).Where("id = ?", member.ID).Update("password_hash", "").Error)
	conflict := time.Now()
	require.NoError(t, h.db.DB.Model(&model.UserIdentity{}).
		Where("user_id = ?", member.ID).Update("conflict_at", conflict).Error)

	w := h.do(t, http.MethodPost, "/api/v1/orgs/"+itoa(orgID)+"/members/"+itoa(int64(member.ID))+"/identity/reset", nil, ownerToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var count int64
	require.NoError(t, h.db.DB.Model(&model.UserIdentity{}).Where("user_id = ?", member.ID).Count(&count).Error)
	require.Zero(t, count)
}
