package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/api"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/audit"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// failingRevokeAuditor is transactional (so organization creation succeeds) but
// refuses the revoke entry, letting the rollback path be exercised.
type failingRevokeAuditor struct{ base audit.TxRecorder }

func (f failingRevokeAuditor) Record(ctx context.Context, e audit.Entry) error {
	return f.base.(audit.Auditor).Record(ctx, e)
}

func (f failingRevokeAuditor) RecordTx(tx *gorm.DB, e audit.Entry) error {
	if e.Action == "organization.invitation.revoke" {
		return errors.New("audit down")
	}
	return f.base.RecordTx(tx, e)
}

func invitationIDForEmail(t *testing.T, h *harness, orgID uint, email string) uint {
	t.Helper()
	var inv model.Invitation
	require.NoError(t, store.WithoutTenantScope(h.db.DB).
		Where("organization_id = ? AND email = ?", orgID, email).
		First(&inv).Error)
	return inv.ID
}

func countRenameAudits(t *testing.T, h *harness, orgID uint) int64 {
	t.Helper()
	var n int64
	require.NoError(t, store.WithoutTenantScope(h.db.DB).Model(&model.AuditLog{}).
		Where("organization_id = ? AND action = ?", orgID, "organization.invitation.revoke").
		Count(&n).Error)
	return n
}

func TestListInvitations_PendingOnlyWithPermissions(t *testing.T) {
	h := newHarness(t)
	h.seedUser(t, "owner@example.com", "password123")
	h.seedUser(t, "admin@example.com", "password123")
	h.seedUser(t, "member@example.com", "password123")
	h.seedUser(t, "outsider@example.com", "password123")
	ownerToken := h.login(t, "owner@example.com", "password123")
	adminToken := h.login(t, "admin@example.com", "password123")
	memberToken := h.login(t, "member@example.com", "password123")
	outsiderToken := h.login(t, "outsider@example.com", "password123")
	orgID := createOrgForTest(t, h, ownerToken, "team")
	org := uint(orgID)

	var adminUser, memberUser model.User
	require.NoError(t, h.db.DB.Where("email = ?", "admin@example.com").First(&adminUser).Error)
	require.NoError(t, h.db.DB.Where("email = ?", "member@example.com").First(&memberUser).Error)
	require.NoError(t, h.db.DB.Create(&model.Membership{
		OrganizationID: org, UserID: adminUser.ID,
		RoleID: h.roleID(t, org, model.RoleKindAdmin),
	}).Error)
	require.NoError(t, h.db.DB.Create(&model.Membership{
		OrganizationID: org, UserID: memberUser.ID,
		RoleID: h.roleID(t, org, model.RoleKindMember),
	}).Error)

	now := time.Now()
	accepted := now.Add(-time.Minute)
	revoked := now.Add(-time.Minute)
	rows := []model.Invitation{
		{OrganizationID: org, Email: "pending1@example.com", Role: model.RoleMember,
			TokenHash: strings.Repeat("a", 64), ExpiresAt: now.Add(time.Hour)},
		{OrganizationID: org, Email: "pending2@example.com", Role: model.RoleAdmin,
			TokenHash: strings.Repeat("b", 64), ExpiresAt: now.Add(2 * time.Hour)},
		{OrganizationID: org, Email: "expired@example.com", Role: model.RoleMember,
			TokenHash: strings.Repeat("c", 64), ExpiresAt: now.Add(-time.Minute)},
		{OrganizationID: org, Email: "accepted@example.com", Role: model.RoleMember,
			TokenHash: strings.Repeat("d", 64), ExpiresAt: now.Add(time.Hour), AcceptedAt: &accepted},
		{OrganizationID: org, Email: "revoked@example.com", Role: model.RoleMember,
			TokenHash: strings.Repeat("e", 64), ExpiresAt: now.Add(time.Hour), RevokedAt: &revoked},
	}
	require.NoError(t, h.db.DB.Create(&rows).Error)

	path := "/api/v1/orgs/" + itoa(orgID) + "/invitations"
	w := h.do(t, http.MethodGet, path, nil, ownerToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.NotContains(t, w.Body.String(), "token_hash")
	require.NotContains(t, w.Body.String(), "token")
	var resp struct {
		Data []struct {
			ID        int64  `json:"id"`
			Email     string `json:"email"`
			Role      string `json:"role"`
			ExpiresAt string `json:"expires_at"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.Len(t, resp.Data, 2)
	// id DESC: pending2 was created after pending1.
	require.Equal(t, "pending2@example.com", resp.Data[0].Email)
	require.Equal(t, "admin", resp.Data[0].Role)
	require.Equal(t, "pending1@example.com", resp.Data[1].Email)
	require.NotEmpty(t, resp.Data[0].ExpiresAt)

	require.Equal(t, http.StatusOK, h.do(t, http.MethodGet, path, nil, adminToken).Code)
	require.Equal(t, http.StatusForbidden, h.do(t, http.MethodGet, path, nil, memberToken).Code)
	require.Equal(t, http.StatusForbidden, h.do(t, http.MethodGet, path, nil, outsiderToken).Code)
	require.Equal(t, http.StatusUnauthorized, h.do(t, http.MethodGet, path, nil, "").Code)
	require.Equal(t, http.StatusNotFound,
		h.do(t, http.MethodGet, "/api/v1/orgs/9999999/invitations", nil, ownerToken).Code)

	// A second organization must not leak the first organization's rows.
	otherID := createOrgForTest(t, h, ownerToken, "other")
	other := h.do(t, http.MethodGet, "/api/v1/orgs/"+itoa(otherID)+"/invitations", nil, ownerToken)
	require.Equal(t, http.StatusOK, other.Code, other.Body.String())
	var empty struct {
		Data []struct{} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(other.Body.Bytes(), &empty))
	require.Empty(t, empty.Data)
}

func TestRevokeInvitation_AuditsIdempotently(t *testing.T) {
	h := newHarness(t)
	h.seedUser(t, "owner@example.com", "password123")
	ownerToken := h.login(t, "owner@example.com", "password123")
	orgID := createOrgForTest(t, h, ownerToken, "team")
	org := uint(orgID)

	h.newInvitationForTest(t, orgID, "pending@example.com", model.RoleMember)
	invID := invitationIDForEmail(t, h, org, "pending@example.com")
	path := fmt.Sprintf("/api/v1/orgs/%d/invitations/%d", orgID, invID)

	w := h.do(t, http.MethodDelete, path, nil, ownerToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var stored model.Invitation
	require.NoError(t, store.WithoutTenantScope(h.db.DB).First(&stored, invID).Error)
	require.NotNil(t, stored.RevokedAt)
	require.EqualValues(t, 1, countRenameAudits(t, h, org))

	var entry model.AuditLog
	require.NoError(t, store.WithoutTenantScope(h.db.DB).
		Where("organization_id = ? AND action = ?", org, "organization.invitation.revoke").
		First(&entry).Error)
	require.Contains(t, entry.Detail, `"email":"pending@example.com"`)
	require.Contains(t, entry.Detail, `"role":"member"`)

	// Repeating the revoke is 200 and does not append a second domain audit.
	require.Equal(t, http.StatusOK, h.do(t, http.MethodDelete, path, nil, ownerToken).Code)
	require.EqualValues(t, 1, countRenameAudits(t, h, org))

	list := h.do(t, http.MethodGet, "/api/v1/orgs/"+itoa(orgID)+"/invitations", nil, ownerToken)
	require.NotContains(t, list.Body.String(), "pending@example.com")
	require.Equal(t, http.StatusNotFound,
		h.do(t, http.MethodDelete, "/api/v1/orgs/"+itoa(orgID)+"/invitations/9999999", nil, ownerToken).Code)
}

func TestRevokeInvitation_RejectsAcceptedAndOtherOrgs(t *testing.T) {
	h := newHarness(t)
	h.seedUser(t, "owner@example.com", "password123")
	ownerToken := h.login(t, "owner@example.com", "password123")
	orgID := createOrgForTest(t, h, ownerToken, "team")
	org := uint(orgID)

	token := h.newInvitationForTest(t, orgID, "joined@example.com", model.RoleMember)
	w := h.do(t, http.MethodPost, "/api/v1/invitations/accept", map[string]string{
		"token": token, "password": "password123",
	}, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	invID := invitationIDForEmail(t, h, org, "joined@example.com")
	require.Equal(t, http.StatusConflict, h.do(t, http.MethodDelete,
		fmt.Sprintf("/api/v1/orgs/%d/invitations/%d", orgID, invID), nil, ownerToken).Code)

	otherID := createOrgForTest(t, h, ownerToken, "other")
	h.newInvitationForTest(t, otherID, "elsewhere@example.com", model.RoleMember)
	otherInv := invitationIDForEmail(t, h, uint(otherID), "elsewhere@example.com")
	require.Equal(t, http.StatusNotFound, h.do(t, http.MethodDelete,
		fmt.Sprintf("/api/v1/orgs/%d/invitations/%d", orgID, otherInv), nil, ownerToken).Code)
}

func TestRevokeInvitation_ExpiredAndPermissionChecks(t *testing.T) {
	h := newHarness(t)
	h.seedUser(t, "owner@example.com", "password123")
	h.seedUser(t, "member@example.com", "password123")
	ownerToken := h.login(t, "owner@example.com", "password123")
	memberToken := h.login(t, "member@example.com", "password123")
	orgID := createOrgForTest(t, h, ownerToken, "team")
	org := uint(orgID)

	var memberUser model.User
	require.NoError(t, h.db.DB.Where("email = ?", "member@example.com").First(&memberUser).Error)
	require.NoError(t, h.db.DB.Create(&model.Membership{
		OrganizationID: org, UserID: memberUser.ID,
		RoleID: h.roleID(t, org, model.RoleKindMember),
	}).Error)

	expired := model.Invitation{
		OrganizationID: org,
		Email:          "expired@example.com",
		Role:           model.RoleMember,
		TokenHash:      strings.Repeat("f", 64),
		ExpiresAt:      time.Now().Add(-time.Hour),
	}
	require.NoError(t, h.db.DB.Create(&expired).Error)
	path := fmt.Sprintf("/api/v1/orgs/%d/invitations/%d", orgID, expired.ID)
	require.Equal(t, http.StatusForbidden, h.do(t, http.MethodDelete, path, nil, memberToken).Code)
	require.Equal(t, http.StatusOK, h.do(t, http.MethodDelete, path, nil, ownerToken).Code)
	require.EqualValues(t, 1, countRenameAudits(t, h, org))
}

func TestRevokeInvitation_AuditFailureRollsBack(t *testing.T) {
	h := newHarnessWith(t, func(d *api.Deps) {
		d.Auditor = failingRevokeAuditor{base: audit.NewGormAuditor(d.DB)}
	})
	h.seedUser(t, "owner@example.com", "password123")
	ownerToken := h.login(t, "owner@example.com", "password123")
	orgID := createOrgForTest(t, h, ownerToken, "team")
	org := uint(orgID)

	h.newInvitationForTest(t, orgID, "pending@example.com", model.RoleMember)
	invID := invitationIDForEmail(t, h, org, "pending@example.com")
	w := h.do(t, http.MethodDelete,
		fmt.Sprintf("/api/v1/orgs/%d/invitations/%d", orgID, invID), nil, ownerToken)
	require.Equal(t, http.StatusInternalServerError, w.Code, w.Body.String())
	var stored model.Invitation
	require.NoError(t, store.WithoutTenantScope(h.db.DB).First(&stored, invID).Error)
	require.Nil(t, stored.RevokedAt)
}

func TestAcceptInvitation_ExistingMemberIsConflict(t *testing.T) {
	h := newHarness(t)
	h.seedUser(t, "owner@example.com", "password123")
	h.seedUser(t, "member@example.com", "password123")
	ownerToken := h.login(t, "owner@example.com", "password123")
	orgID := createOrgForTest(t, h, ownerToken, "team")
	org := uint(orgID)

	var memberUser model.User
	require.NoError(t, h.db.DB.Where("email = ?", "member@example.com").First(&memberUser).Error)
	require.NoError(t, h.db.DB.Create(&model.Membership{
		OrganizationID: org, UserID: memberUser.ID,
		RoleID: h.roleID(t, org, model.RoleKindMember),
	}).Error)
	token := h.newInvitationForTest(t, orgID, "member@example.com", model.RoleMember)

	w := h.do(t, http.MethodPost, "/api/v1/invitations/accept", map[string]string{
		"token": token, "password": "password123",
	}, "")
	require.Equal(t, http.StatusConflict, w.Code, w.Body.String())
}

func TestAcceptInvitation_RejectsRevokedToken(t *testing.T) {
	h := newHarness(t)
	h.seedUser(t, "owner@example.com", "password123")
	ownerToken := h.login(t, "owner@example.com", "password123")
	orgID := createOrgForTest(t, h, ownerToken, "team")
	org := uint(orgID)

	token := h.newInvitationForTest(t, orgID, "late@example.com", model.RoleMember)
	invID := invitationIDForEmail(t, h, org, "late@example.com")
	require.Equal(t, http.StatusOK, h.do(t, http.MethodDelete,
		fmt.Sprintf("/api/v1/orgs/%d/invitations/%d", orgID, invID), nil, ownerToken).Code)

	w := h.do(t, http.MethodPost, "/api/v1/invitations/accept", map[string]string{
		"token": token, "password": "password123",
	}, "")
	require.Equal(t, http.StatusConflict, w.Code, w.Body.String())

	var memberships int64
	require.NoError(t, store.WithoutTenantScope(h.db.DB).Model(&model.Membership{}).
		Where("organization_id = ?", org).Count(&memberships).Error)
	require.EqualValues(t, 1, memberships, "only the owner membership exists")
}
