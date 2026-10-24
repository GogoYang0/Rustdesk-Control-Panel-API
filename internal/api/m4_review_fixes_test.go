package api_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/api"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/audit"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/authz"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/session"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// Tenant creation is auditable security state: without a transactional
// auditor the row must not commit at all (fail closed), instead of relying on
// the post-commit middleware fallback.
func TestOrg_CreateRefusesWithoutTransactionalAuditor(t *testing.T) {
	spy := &spyAuditor{inner: audit.Nop{}}
	h := newHarnessWith(t, func(d *api.Deps) {
		d.Auditor = spy
		d.Tickets = session.NewService(d.DB, audit.NewGormAuditor(d.DB), nil)
	})
	h.seedUser(t, "closed-owner@example.com", "password123")
	token := h.login(t, "closed-owner@example.com", "password123")

	w := h.do(t, http.MethodPost, "/api/v1/orgs", map[string]string{"name": "closed-org"}, token)
	require.Equal(t, http.StatusInternalServerError, w.Code, w.Body.String())

	var orgs int64
	require.NoError(t, h.db.DB.Model(&model.Organization{}).Count(&orgs).Error)
	require.Zero(t, orgs, "the organization must not exist without its audit row")
}

// Accepting an invitation grants a role; without a transactional auditor the
// membership must roll back with the account it would have created.
func TestInvitation_AcceptRefusesWithoutTransactionalAuditor(t *testing.T) {
	spy := &spyAuditor{inner: audit.Nop{}}
	h := newHarnessWith(t, func(d *api.Deps) {
		d.Auditor = spy
		d.Tickets = session.NewService(d.DB, audit.NewGormAuditor(d.DB), nil)
	})

	org := model.Organization{Name: "closed-invite-org"}
	require.NoError(t, h.db.DB.Create(&org).Error)
	require.NoError(t, authz.NewRoleService(h.db.DB).EnsureBuiltins(org.ID))
	token := h.newInvitationForTest(t, int64(org.ID), "closed-invitee@example.com", model.RoleMember)

	w := h.do(t, http.MethodPost, "/api/v1/invitations/accept",
		map[string]string{"token": token, "password": "newpass123"}, "")
	require.Equal(t, http.StatusInternalServerError, w.Code, w.Body.String())

	var users, members int64
	require.NoError(t, h.db.DB.Where("email = ?", "closed-invitee@example.com").
		Model(&model.User{}).Count(&users).Error)
	require.Zero(t, users, "the account must not exist")
	require.NoError(t, store.ScopedByOrg(h.db.DB, org.ID).
		Model(&model.Membership{}).Count(&members).Error)
	require.Zero(t, members, "the membership must not exist")
}

// The login second step is a credential oracle: repeated attempts from one
// address hit the same per-IP bucket as /auth/login.
func TestTOTP_VerifyIsRateLimited(t *testing.T) {
	h := newHarness(t)
	for i := 0; i < 5; i++ {
		w := h.do(t, http.MethodPost, "/api/v1/auth/2fa/verify",
			map[string]string{"challenge_token": "not-a-challenge", "code": "123456"}, "")
		require.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())
	}
	w := h.do(t, http.MethodPost, "/api/v1/auth/2fa/verify",
		map[string]string{"challenge_token": "not-a-challenge", "code": "123456"}, "")
	require.Equal(t, http.StatusTooManyRequests, w.Code, w.Body.String())
}

// The admin reset endpoint must not become a second-factor bypass: nobody
// resets their own configuration through it.
func TestTOTP_AdminCannotResetOwnFactor(t *testing.T) {
	h := newHarness(t)
	owner := h.seedUser(t, "self-reset@example.com", "password123")
	token := h.login(t, "self-reset@example.com", "password123")

	w := h.do(t, http.MethodPost, "/api/v1/orgs", map[string]string{"name": "self-reset-org"}, token)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var orgResp struct {
		Data struct {
			Id int64 `json:"id"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &orgResp))

	w = h.do(t, http.MethodPost, "/api/v1/orgs/"+itoa(orgResp.Data.Id)+"/members/"+itoa(int64(owner.ID))+"/2fa/reset", nil, token)
	require.Equal(t, http.StatusConflict, w.Code, w.Body.String())
}

// Listing devices is gated by device.read, so a custom role that omits the
// code cannot read the inventory even though it can manage other domains.
func TestDevices_ListRequiresDeviceRead(t *testing.T) {
	h := newHarness(t)
	h.seedUser(t, "dev-owner@example.com", "password123")
	ownerToken := h.login(t, "dev-owner@example.com", "password123")

	w := h.do(t, http.MethodPost, "/api/v1/orgs", map[string]string{"name": "dev-org"}, ownerToken)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var orgResp struct {
		Data struct {
			Id int64 `json:"id"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &orgResp))
	orgPath := "/api/v1/orgs/" + itoa(orgResp.Data.Id)

	w = h.do(t, http.MethodPost, orgPath+"/roles", map[string]any{
		"name": "no-device-read", "permissions": []string{authz.PermAuditRead},
	}, ownerToken)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var roleResp struct {
		Data struct {
			Id int64 `json:"id"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &roleResp))

	// The invitation creates the account: seeding it first would make the
	// accept path demand the seeded password instead.
	inviteToken := h.newInvitationForTest(t, orgResp.Data.Id, "dev-member@example.com", model.RoleMember)
	w = h.do(t, http.MethodPost, "/api/v1/invitations/accept",
		map[string]string{"token": inviteToken, "password": "newpass123"}, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var memberResp struct {
		Data struct {
			UserId int64 `json:"user_id"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &memberResp))

	w = h.do(t, http.MethodPatch, orgPath+"/members/"+itoa(memberResp.Data.UserId),
		map[string]any{"role_id": roleResp.Data.Id}, ownerToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	// Invitation-created accounts start unverified; login requires a verified
	// mailbox, and this test exercises authorization rather than the mail flow.
	require.NoError(t, h.db.DB.Model(&model.User{}).
		Where("email = ?", "dev-member@example.com").
		Update("email_verified", true).Error)
	memberToken := h.login(t, "dev-member@example.com", "newpass123")
	w = h.do(t, http.MethodGet, orgPath+"/devices", nil, memberToken)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
}
