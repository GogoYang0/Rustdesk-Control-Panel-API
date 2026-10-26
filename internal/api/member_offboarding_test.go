package api_test

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

func seedMember(t *testing.T, h *harness, orgID int64, userID uint, role string) {
	t.Helper()
	require.NoError(t, store.ScopedByOrg(h.db.DB, uint(orgID)).Create(&model.Membership{
		OrganizationID: uint(orgID), UserID: userID, RoleID: h.roleID(t, uint(orgID), role),
	}).Error)
}

func seedCompatSession(t *testing.T, h *harness, orgID int64, userID uint, jti string) uint {
	t.Helper()
	row := model.CompatSession{
		OrganizationID: uint(orgID),
		UserID:         userID,
		JTI:            jti,
		ExpiresAt:      time.Now().Add(time.Hour),
	}
	require.NoError(t, store.ScopedByOrg(h.db.DB, uint(orgID)).Create(&row).Error)
	return row.ID
}

func sessionRevoked(t *testing.T, h *harness, id uint) bool {
	t.Helper()
	var row model.CompatSession
	require.NoError(t, store.WithoutTenantScope(h.db.DB).First(&row, id).Error)
	return row.RevokedAt != nil
}

func TestRemoveMember_RevokesSessionsInOrg(t *testing.T) {
	h := newHarness(t)
	h.seedUser(t, "owner-rm@example.com", "password123")
	ownerToken := h.login(t, "owner-rm@example.com", "password123")
	orgID := createOrg(t, h, ownerToken, "rm-org")
	otherOrg := createOrg(t, h, ownerToken, "rm-other")

	target := h.seedUser(t, "target-rm@example.com", "password123")
	seedMember(t, h, orgID, target.ID, model.RoleMember)
	seedMember(t, h, otherOrg, target.ID, model.RoleMember)

	inOrg := seedCompatSession(t, h, orgID, target.ID, "jti-rm-in")
	other := seedCompatSession(t, h, otherOrg, target.ID, "jti-rm-out")

	w := h.do(t, http.MethodDelete, "/api/v1/orgs/"+itoa(orgID)+"/members/"+itoa(int64(target.ID)), nil, ownerToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var resp struct {
		Data struct {
			RevokedSessions int64 `json:"revoked_sessions"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.EqualValues(t, 1, resp.Data.RevokedSessions)

	var count int64
	require.NoError(t, store.ScopedByOrg(h.db.DB, uint(orgID)).Model(&model.Membership{}).
		Where("user_id = ?", target.ID).Count(&count).Error)
	require.Zero(t, count, "the membership must be gone")
	require.True(t, sessionRevoked(t, h, inOrg), "the org session must be revoked")
	require.False(t, sessionRevoked(t, h, other), "sessions in another org must survive")

	require.EqualValues(t, 1, countAudit(t, h, "action = ?", "organization.member.remove"))
}

func TestRemoveMember_Rules(t *testing.T) {
	h := newHarness(t)
	creator := h.seedUser(t, "owner-rules@example.com", "password123")
	ownerToken := h.login(t, "owner-rules@example.com", "password123")
	orgID := createOrg(t, h, ownerToken, "rules-org")
	owner := h.seedUser(t, "owner2-rules@example.com", "password123")
	seedMember(t, h, orgID, owner.ID, model.RoleOwner)
	admin := h.seedUser(t, "admin-rules@example.com", "password123")
	seedMember(t, h, orgID, admin.ID, model.RoleAdmin)
	adminToken := h.login(t, "admin-rules@example.com", "password123")
	member := h.seedUser(t, "member-rules@example.com", "password123")
	seedMember(t, h, orgID, member.ID, model.RoleMember)

	// An admin may remove a member.
	w := h.do(t, http.MethodDelete, "/api/v1/orgs/"+itoa(orgID)+"/members/"+itoa(int64(member.ID)), nil, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	// But not an owner.
	seedMember(t, h, orgID, member.ID, model.RoleMember)
	w = h.do(t, http.MethodDelete, "/api/v1/orgs/"+itoa(orgID)+"/members/"+itoa(int64(owner.ID)), nil, adminToken)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

	// Nobody can walk out through this endpoint, not even an owner.
	w = h.do(t, http.MethodDelete, "/api/v1/orgs/"+itoa(orgID)+"/members/"+itoa(int64(creator.ID)), nil, ownerToken)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())

	// Non-members are refused as callers, unknown users are 404.
	h.seedUser(t, "outsider-rules@example.com", "password123")
	outsiderToken := h.login(t, "outsider-rules@example.com", "password123")
	w = h.do(t, http.MethodDelete, "/api/v1/orgs/"+itoa(orgID)+"/members/"+itoa(int64(member.ID)), nil, outsiderToken)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	w = h.do(t, http.MethodDelete, "/api/v1/orgs/"+itoa(orgID)+"/members/999999", nil, ownerToken)
	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())

	// The other owner can be removed; the remaining owner then cannot be
	// removed by anyone (self is a 400, and no other owner exists to ask).
	w = h.do(t, http.MethodDelete, "/api/v1/orgs/"+itoa(orgID)+"/members/"+itoa(int64(owner.ID)), nil, ownerToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
}

func TestUpdateMemberRole(t *testing.T) {
	h := newHarness(t)
	creator := h.seedUser(t, "owner-role@example.com", "password123")
	ownerToken := h.login(t, "owner-role@example.com", "password123")
	orgID := createOrg(t, h, ownerToken, "role-org")
	owner2 := h.seedUser(t, "owner2-role@example.com", "password123")
	seedMember(t, h, orgID, owner2.ID, model.RoleOwner)
	admin := h.seedUser(t, "admin-role@example.com", "password123")
	seedMember(t, h, orgID, admin.ID, model.RoleAdmin)
	member := h.seedUser(t, "member-role@example.com", "password123")
	seedMember(t, h, orgID, member.ID, model.RoleMember)
	adminToken := h.login(t, "admin-role@example.com", "password123")
	memberToken := h.login(t, "member-role@example.com", "password123")

	path := func(uid uint) string {
		return "/api/v1/orgs/" + itoa(orgID) + "/members/" + itoa(int64(uid))
	}
	adminRoleID := int64(h.roleID(t, uint(orgID), model.RoleAdmin))
	memberRoleID := int64(h.roleID(t, uint(orgID), model.RoleMember))
	ownerRoleID := int64(h.roleID(t, uint(orgID), model.RoleOwner))

	// Promote: no session revocation.
	w := h.do(t, http.MethodPatch, path(member.ID), map[string]any{"role_id": adminRoleID}, ownerToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var promoted struct {
		Data struct {
			UserId uint   `json:"user_id"`
			Role   string `json:"role"`
			Email  string `json:"email"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &promoted))
	require.Equal(t, model.RoleAdmin, promoted.Data.Role)
	require.Equal(t, "member-role@example.com", promoted.Data.Email)

	// Demote: revokes the target's compat sessions.
	session := seedCompatSession(t, h, orgID, member.ID, "jti-role-demote")
	w = h.do(t, http.MethodPatch, path(member.ID), map[string]any{"role_id": memberRoleID}, ownerToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.True(t, sessionRevoked(t, h, session), "a demotion must revoke compat sessions")

	// Admin, member, self, owner target, non-grantable role, unknown role.
	w = h.do(t, http.MethodPatch, path(member.ID), map[string]any{"role_id": memberRoleID}, adminToken)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	w = h.do(t, http.MethodPatch, path(member.ID), map[string]any{"role_id": memberRoleID}, memberToken)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	w = h.do(t, http.MethodPatch, path(admin.ID), map[string]any{"role_id": memberRoleID}, ownerToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	w = h.do(t, http.MethodPatch, path(admin.ID), map[string]any{"role_id": memberRoleID}, adminToken)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	w = h.do(t, http.MethodPatch, path(creator.ID), map[string]any{"role_id": memberRoleID}, ownerToken)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	w = h.do(t, http.MethodPatch, path(owner2.ID), map[string]any{"role_id": adminRoleID}, ownerToken)
	require.Equal(t, http.StatusConflict, w.Code, w.Body.String())
	w = h.do(t, http.MethodPatch, path(member.ID), map[string]any{"role_id": ownerRoleID}, ownerToken)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	w = h.do(t, http.MethodPatch, path(member.ID), map[string]any{"role_id": 999999}, ownerToken)
	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())
	w = h.do(t, http.MethodPatch, path(999999), map[string]any{"role_id": memberRoleID}, ownerToken)
	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())

	require.NotZero(t, countAudit(t, h, "action = ?", "organization.member.role"))
}
