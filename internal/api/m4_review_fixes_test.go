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

// inviteAndVerify joins an email to the organization through the real
// invitation flow and marks the mailbox verified, returning its user id.
func inviteAndVerify(t *testing.T, h *harness, orgID int64, email, role string) int64 {
	t.Helper()
	invite := h.newInvitationForTest(t, orgID, email, role)
	w := h.do(t, http.MethodPost, "/api/v1/invitations/accept",
		map[string]string{"token": invite, "password": "newpass123"}, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var resp struct {
		Data struct {
			UserId int64 `json:"user_id"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.NoError(t, h.db.DB.Model(&model.User{}).
		Where("email = ?", email).Update("email_verified", true).Error)
	return resp.Data.UserId
}

// The second factor is global, so an organization admin must not be able to
// clear an owner's configuration: only an owner (org.admin) may.
func TestTOTP_AdminCannotResetOwner(t *testing.T) {
	h := newHarness(t)
	owner := h.seedUser(t, "totp-owner@example.com", "password123")
	ownerToken := h.login(t, "totp-owner@example.com", "password123")
	w := h.do(t, http.MethodPost, "/api/v1/orgs", map[string]string{"name": "totp-owner-org"}, ownerToken)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var orgResp struct {
		Data struct {
			Id int64 `json:"id"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &orgResp))
	orgID := orgResp.Data.Id

	inviteAndVerify(t, h, orgID, "totp-admin@example.com", model.RoleAdmin)
	adminToken := h.login(t, "totp-admin@example.com", "newpass123")

	w = h.do(t, http.MethodPost, "/api/v1/orgs/"+itoa(orgID)+"/members/"+itoa(int64(owner.ID))+"/2fa/reset", nil, adminToken)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

	// The owner can reset another member, which pins that the guard is about
	// authority over the target rather than a blanket refusal.
	memberID := inviteAndVerify(t, h, orgID, "totp-member@example.com", model.RoleMember)
	w = h.do(t, http.MethodPost, "/api/v1/orgs/"+itoa(orgID)+"/members/"+itoa(memberID)+"/2fa/reset", nil, ownerToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
}

// A user who owns another tenant keeps that tenant's login protection even when
// they are only a member here: the local admin must not be able to clear it.
func TestTOTP_AdminCannotResetOtherOrgOwner(t *testing.T) {
	h := newHarness(t)
	h.seedUser(t, "other-owner-admin@example.com", "password123")
	ownerToken := h.login(t, "other-owner-admin@example.com", "password123")
	w := h.do(t, http.MethodPost, "/api/v1/orgs", map[string]string{"name": "tenant-a"}, ownerToken)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var orgA struct {
		Data struct {
			Id int64 `json:"id"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &orgA))

	inviteAndVerify(t, h, orgA.Data.Id, "tenant-b-owner@example.com", model.RoleMember)
	memberToken := h.login(t, "tenant-b-owner@example.com", "newpass123")
	w = h.do(t, http.MethodPost, "/api/v1/orgs", map[string]string{"name": "tenant-b"}, memberToken)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var orgB struct {
		Data struct {
			Id int64 `json:"id"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &orgB))
	require.NotZero(t, orgB.Data.Id, "the target must own a second organization")

	inviteAndVerify(t, h, orgA.Data.Id, "tenant-a-admin@example.com", model.RoleAdmin)
	adminToken := h.login(t, "tenant-a-admin@example.com", "newpass123")

	var target model.User
	require.NoError(t, h.db.DB.Where("email = ?", "tenant-b-owner@example.com").First(&target).Error)
	w = h.do(t, http.MethodPost, "/api/v1/orgs/"+itoa(orgA.Data.Id)+"/members/"+itoa(int64(target.ID))+"/2fa/reset", nil, adminToken)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
}

// A disabled co-owner is outside the active owner set, so the remaining owner
// must be able to remove them (the old count guard refused this case).
func TestRemoveMember_DisabledCoOwnerCanBeRemoved(t *testing.T) {
	h := newHarness(t)
	h.seedUser(t, "remove-owner@example.com", "password123")
	token := h.login(t, "remove-owner@example.com", "password123")
	orgID := createOrg(t, h, token, "remove-disabled-owner-org")

	co := h.seedUser(t, "remove-co-owner@example.com", "password123")
	ownerRole := h.roleID(t, uint(orgID), model.RoleOwner)
	require.NoError(t, h.db.DB.Create(&model.Membership{
		OrganizationID: uint(orgID), UserID: co.ID, RoleID: ownerRole,
		Role: model.RoleOwner, Disabled: true,
	}).Error)

	w := h.do(t, http.MethodDelete, "/api/v1/orgs/"+itoa(orgID)+"/members/"+itoa(int64(co.ID)), nil, token)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
}

// The personal token's permission set is an upper bound, including where
// ownership or a grant would otherwise authorize a write: a token without
// addressbook.write must not mutate books at all.
func TestToken_CannotMutateAddressBooksBeyondScope(t *testing.T) {
	h, orgID, _, _, member, ownerToken, _, memberToken := m4Org(t)
	orgPath := "/api/v1/orgs/" + itoa(orgID)
	booksPath := orgPath + "/address-books"
	narrow := createTokenAPI(t, h, orgID, ownerToken, "narrow", []string{authz.PermDeviceRead})

	// Personal books authorize their owner independently of the role permission.
	w := h.do(t, http.MethodPost, booksPath, map[string]any{"name": "own", "scope": "personal"}, ownerToken)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var personal struct {
		Data struct {
			Id int64 `json:"id"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &personal))
	personalPath := booksPath + "/" + itoa(personal.Data.Id)

	w = h.do(t, http.MethodDelete, personalPath, nil, narrow.Plaintext)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	w = h.do(t, http.MethodPost, booksPath, map[string]any{"name": "via-token", "scope": "personal"}, narrow.Plaintext)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	w = h.do(t, http.MethodDelete, personalPath, nil, ownerToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	// A full grant on a shared book raises the member's access, not the token's
	// ceiling: deleting the book still requires addressbook.write.
	w = h.do(t, http.MethodPost, booksPath, map[string]any{"name": "team", "scope": "shared"}, ownerToken)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var shared struct {
		Data struct {
			Id int64 `json:"id"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &shared))
	sharedPath := booksPath + "/" + itoa(shared.Data.Id)
	w = h.do(t, http.MethodPost, sharedPath+"/grants", map[string]any{
		"subject_kind": "user", "subject_user_id": member.ID, "access": "full",
	}, ownerToken)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())

	memberNarrow := createTokenAPI(t, h, orgID, memberToken, "narrow-member", []string{authz.PermDeviceRead})
	w = h.do(t, http.MethodDelete, sharedPath, nil, memberNarrow.Plaintext)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	w = h.do(t, http.MethodDelete, sharedPath, nil, memberToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
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
