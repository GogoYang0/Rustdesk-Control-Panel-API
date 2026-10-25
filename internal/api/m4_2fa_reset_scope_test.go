package api_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
)

// The second factor is account-wide, so clearing it from one organization must
// not weaken the login protection the same user holds in another tenant — even
// when they are "only" an administrator there rather than its owner.
func TestTOTP_AdminCannotResetCrossOrgAdministrator(t *testing.T) {
	h := newHarness(t)

	h.seedUser(t, "scope-a-owner@example.com", "password123")
	aOwnerToken := h.login(t, "scope-a-owner@example.com", "password123")
	orgA := createOrg(t, h, aOwnerToken, "scope-org-a")

	h.seedUser(t, "scope-b-owner@example.com", "password123")
	bOwnerToken := h.login(t, "scope-b-owner@example.com", "password123")
	orgB := createOrg(t, h, bOwnerToken, "scope-org-b")

	// The target administers tenant B and is a plain member of tenant A.
	targetID := inviteAndVerify(t, h, orgB, "scope-target@example.com", model.RoleAdmin)
	inviteAndVerify(t, h, orgA, "scope-target@example.com", model.RoleMember)

	// An administrator of tenant A holds member.manage there, but the target's
	// factor also protects tenant B, which the administrator does not control.
	admin := h.seedUser(t, "scope-a-admin@example.com", "password123")
	adminRole := h.roleID(t, uint(orgA), model.RoleAdmin)
	require.NoError(t, h.db.DB.Create(&model.Membership{
		OrganizationID: uint(orgA), UserID: admin.ID, RoleID: adminRole, Role: model.RoleAdmin,
	}).Error)
	adminToken := h.login(t, "scope-a-admin@example.com", "password123")

	w := h.do(t, http.MethodPost, "/api/v1/orgs/"+itoa(orgA)+"/members/"+itoa(targetID)+"/2fa/reset", nil, adminToken)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
}
