package api_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/api"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/mail"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

type captureMailer struct {
	messages []mail.Message
	err      error
}

func (m *captureMailer) Send(_ context.Context, msg mail.Message) error {
	m.messages = append(m.messages, msg)
	return m.err
}

func tokenFromResetMail(t *testing.T, m *captureMailer) string {
	t.Helper()
	require.Len(t, m.messages, 1)
	body := m.messages[0].TextBody
	idx := strings.Index(body, "/reset-password#token=")
	require.NotEqual(t, -1, idx)
	rest := body[idx+len("/reset-password#token="):]
	token := strings.SplitN(rest, "\n", 2)[0]
	require.NotEmpty(t, token)
	return token
}

func addMembership(t *testing.T, h *harness, orgID, userID uint, kind string) {
	t.Helper()
	require.NoError(t, h.db.DB.Create(&model.Membership{
		OrganizationID: orgID, UserID: userID,
		RoleID: h.roleID(t, orgID, kind),
	}).Error)
}

func addRefreshToken(t *testing.T, h *harness, userID uint) uint {
	t.Helper()
	row := model.RefreshToken{
		UserID:    userID,
		TokenHash: strings.Repeat("r", 40) + time.Now().Format("150405.000000000"),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	require.NoError(t, h.db.DB.Create(&row).Error)
	return row.ID
}

func TestRequestMemberPasswordReset_SendsSingleUseLink(t *testing.T) {
	mails := &captureMailer{}
	h := newHarnessWith(t, func(d *api.Deps) { d.Mailer = mails })
	h.seedUser(t, "owner@example.com", "password123")
	h.seedUser(t, "member@example.com", "old-password")
	ownerToken := h.login(t, "owner@example.com", "password123")
	orgID := createOrgForTest(t, h, ownerToken, "team")
	org := uint(orgID)
	var member model.User
	require.NoError(t, h.db.DB.Where("email = ?", "member@example.com").First(&member).Error)
	addMembership(t, h, org, member.ID, model.RoleKindMember)
	refreshID := addRefreshToken(t, h, member.ID)
	compatID := seedCompatSession(t, h, orgID, member.ID, "jti-reset")

	path := "/api/v1/orgs/" + itoa(orgID) + "/members/" + itoa(int64(member.ID)) + "/password/reset"
	w := h.do(t, http.MethodPost, path, nil, ownerToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.NotContains(t, w.Body.String(), "token")

	var vt model.VerificationToken
	require.NoError(t, store.WithoutTenantScope(h.db.DB).
		Where("user_id = ? AND purpose = ?", member.ID, model.VerificationPurposePasswordReset).
		First(&vt).Error)
	require.WithinDuration(t, time.Now().Add(time.Hour), vt.ExpiresAt, 2*time.Minute)

	var entry model.AuditLog
	require.NoError(t, store.WithoutTenantScope(h.db.DB).
		Where("action = ? AND target_id = ?", "user.password.reset_requested", itoa(int64(member.ID))).
		First(&entry).Error)
	require.NotContains(t, entry.Detail, "token")

	token := tokenFromResetMail(t, mails)
	reset := h.do(t, http.MethodPost, "/api/v1/auth/password/reset", map[string]string{
		"token": token, "new_password": "new-password",
	}, "")
	require.Equal(t, http.StatusOK, reset.Code, reset.Body.String())

	// The new hash works and the old one no longer does.
	require.Equal(t, http.StatusOK, h.do(t, http.MethodPost, "/api/v1/auth/login", map[string]string{
		"email": "member@example.com", "password": "new-password",
	}, "").Code)
	require.Equal(t, http.StatusUnauthorized, h.do(t, http.MethodPost, "/api/v1/auth/login", map[string]string{
		"email": "member@example.com", "password": "old-password",
	}, "").Code)

	// Refresh and compat sessions are revoked in the same reset transaction.
	var refresh model.RefreshToken
	require.NoError(t, h.db.DB.First(&refresh, refreshID).Error)
	require.NotNil(t, refresh.RevokedAt)
	var compat model.CompatSession
	require.NoError(t, h.db.DB.First(&compat, compatID).Error)
	require.NotNil(t, compat.RevokedAt)

	// Replaying the link is refused.
	replay := h.do(t, http.MethodPost, "/api/v1/auth/password/reset", map[string]string{
		"token": token, "new_password": "another-password",
	}, "")
	require.Equal(t, http.StatusConflict, replay.Code)
}

func TestRequestMemberPasswordReset_Guards(t *testing.T) {
	mails := &captureMailer{}
	h := newHarnessWith(t, func(d *api.Deps) { d.Mailer = mails })
	h.seedUser(t, "owner@example.com", "password123")
	h.seedUser(t, "admin@example.com", "password123")
	h.seedUser(t, "member@example.com", "password123")
	h.seedUser(t, "owner-target@example.com", "password123")
	h.seedUser(t, "nopass@example.com", "password123")
	h.seedUser(t, "disabled@example.com", "password123")
	ownerToken := h.login(t, "owner@example.com", "password123")
	adminToken := h.login(t, "admin@example.com", "password123")
	orgID := createOrgForTest(t, h, ownerToken, "team")
	org := uint(orgID)
	var admin, member, ownerTarget, noPass, disabled model.User
	require.NoError(t, h.db.DB.Where("email = ?", "admin@example.com").First(&admin).Error)
	require.NoError(t, h.db.DB.Where("email = ?", "member@example.com").First(&member).Error)
	require.NoError(t, h.db.DB.Where("email = ?", "owner-target@example.com").First(&ownerTarget).Error)
	require.NoError(t, h.db.DB.Where("email = ?", "nopass@example.com").First(&noPass).Error)
	require.NoError(t, h.db.DB.Where("email = ?", "disabled@example.com").First(&disabled).Error)
	addMembership(t, h, org, admin.ID, model.RoleKindAdmin)
	addMembership(t, h, org, member.ID, model.RoleKindMember)
	addMembership(t, h, org, ownerTarget.ID, model.RoleKindOwner)
	addMembership(t, h, org, noPass.ID, model.RoleKindMember)
	addMembership(t, h, org, disabled.ID, model.RoleKindMember)
	require.NoError(t, store.ScopedByOrg(h.db.DB, org).Model(&model.Membership{}).
		Where("user_id = ?", disabled.ID).
		Update("disabled", true).Error)
	require.NoError(t, h.db.DB.Model(&model.User{}).Where("id = ?", noPass.ID).Update("password_hash", "").Error)
	var noPassCheck model.User
	require.NoError(t, h.db.DB.First(&noPassCheck, noPass.ID).Error)
	require.Empty(t, noPassCheck.PasswordHash, "fixture must be passkey-only")

	ownerID := int64(1)
	require.Equal(t, http.StatusConflict, h.do(t, http.MethodPost,
		"/api/v1/orgs/"+itoa(orgID)+"/members/"+itoa(ownerID)+"/password/reset", nil, ownerToken).Code)
	// Admin holds member.manage and may reset a plain member.
	require.Equal(t, http.StatusOK, h.do(t, http.MethodPost,
		"/api/v1/orgs/"+itoa(orgID)+"/members/"+itoa(int64(member.ID))+"/password/reset", nil, adminToken).Code)
	require.Equal(t, http.StatusForbidden, h.do(t, http.MethodPost,
		"/api/v1/orgs/"+itoa(orgID)+"/members/"+itoa(int64(ownerTarget.ID))+"/password/reset", nil, adminToken).Code)
	require.Equal(t, http.StatusConflict, h.do(t, http.MethodPost,
		"/api/v1/orgs/"+itoa(orgID)+"/members/"+itoa(int64(noPass.ID))+"/password/reset", nil, ownerToken).Code)
	require.Equal(t, http.StatusNotFound, h.do(t, http.MethodPost,
		"/api/v1/orgs/"+itoa(orgID)+"/members/999999/password/reset", nil, ownerToken).Code)

	// Disabled membership is not resettable.
	require.Equal(t, http.StatusConflict, h.do(t, http.MethodPost,
		"/api/v1/orgs/"+itoa(orgID)+"/members/"+itoa(int64(disabled.ID))+"/password/reset", nil, ownerToken).Code)
}

func TestRequestMemberPasswordReset_MultiOrgAndCooldown(t *testing.T) {
	mails := &captureMailer{}
	h := newHarnessWith(t, func(d *api.Deps) { d.Mailer = mails })
	h.seedUser(t, "owner@example.com", "password123")
	h.seedUser(t, "member@example.com", "password123")
	ownerToken := h.login(t, "owner@example.com", "password123")
	orgID := createOrgForTest(t, h, ownerToken, "team")
	otherID := createOrgForTest(t, h, ownerToken, "other")
	var member model.User
	require.NoError(t, h.db.DB.Where("email = ?", "member@example.com").First(&member).Error)
	addMembership(t, h, uint(orgID), member.ID, model.RoleKindMember)
	addMembership(t, h, uint(otherID), member.ID, model.RoleKindMember)

	path := "/api/v1/orgs/" + itoa(orgID) + "/members/" + itoa(int64(member.ID)) + "/password/reset"
	require.Equal(t, http.StatusForbidden, h.do(t, http.MethodPost, path, nil, ownerToken).Code)

	// A single-org target succeeds once, then the cooldown blocks a resend.
	require.NoError(t, store.WithoutTenantScope(h.db.DB).
		Where("organization_id = ? AND user_id = ?", otherID, member.ID).
		Delete(&model.Membership{}).Error)
	require.Equal(t, http.StatusOK, h.do(t, http.MethodPost, path, nil, ownerToken).Code)
	require.Equal(t, http.StatusTooManyRequests, h.do(t, http.MethodPost, path, nil, ownerToken).Code)
}

func TestRequestMemberPasswordReset_MailFailureRemovesToken(t *testing.T) {
	mails := &captureMailer{err: errors.New("smtp down")}
	h := newHarnessWith(t, func(d *api.Deps) { d.Mailer = mails })
	h.seedUser(t, "owner@example.com", "password123")
	h.seedUser(t, "member@example.com", "password123")
	ownerToken := h.login(t, "owner@example.com", "password123")
	orgID := createOrgForTest(t, h, ownerToken, "team")
	var member model.User
	require.NoError(t, h.db.DB.Where("email = ?", "member@example.com").First(&member).Error)
	addMembership(t, h, uint(orgID), member.ID, model.RoleKindMember)

	w := h.do(t, http.MethodPost,
		"/api/v1/orgs/"+itoa(orgID)+"/members/"+itoa(int64(member.ID))+"/password/reset", nil, ownerToken)
	require.Equal(t, http.StatusInternalServerError, w.Code, w.Body.String())
	var count int64
	require.NoError(t, store.WithoutTenantScope(h.db.DB).Model(&model.VerificationToken{}).
		Where("user_id = ? AND purpose = ?", member.ID, model.VerificationPurposePasswordReset).
		Count(&count).Error)
	require.Zero(t, count, "definite delivery failure must not leave a token")
}

func TestResetPassword_ValidationAndExpiry(t *testing.T) {
	h := newHarness(t)
	h.seedUser(t, "member@example.com", "password123")
	var member model.User
	require.NoError(t, h.db.DB.Where("email = ?", "member@example.com").First(&member).Error)

	require.Equal(t, http.StatusConflict, h.do(t, http.MethodPost, "/api/v1/auth/password/reset", map[string]string{
		"token": strings.Repeat("x", 32), "new_password": "new-password",
	}, "").Code)
	require.Equal(t, http.StatusBadRequest, h.do(t, http.MethodPost, "/api/v1/auth/password/reset", map[string]string{
		"token": strings.Repeat("x", 32), "new_password": "short",
	}, "").Code)

	token := "expired-reset-token-0123456789abcdef"
	require.NoError(t, store.WithoutTenantScope(h.db.DB).Create(&model.VerificationToken{
		UserID:    member.ID,
		TokenHash: hashForTest(token),
		Purpose:   model.VerificationPurposePasswordReset,
		ExpiresAt: time.Now().Add(-time.Minute),
	}).Error)
	require.Equal(t, http.StatusConflict, h.do(t, http.MethodPost, "/api/v1/auth/password/reset", map[string]string{
		"token": token, "new_password": "new-password",
	}, "").Code)
}

// hashForTest mirrors the server's SHA-256 storage rule without exporting it.
func hashForTest(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
