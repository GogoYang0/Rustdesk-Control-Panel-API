package api_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/authz"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

type meBody struct {
	Code string `json:"code"`
	Data struct {
		User struct {
			Id            int64  `json:"id"`
			Email         string `json:"email"`
			EmailVerified bool   `json:"email_verified"`
			TotpEnabled   bool   `json:"totp_enabled"`
			HasPassword   bool   `json:"has_password"`
		} `json:"user"`
		Orgs []struct {
			Id          int64    `json:"id"`
			Name        string   `json:"name"`
			RoleId      int64    `json:"role_id"`
			RoleKind    string   `json:"role_kind"`
			Permissions []string `json:"permissions"`
		} `json:"orgs"`
	} `json:"data"`
}

func TestMe_RequiresAuthentication(t *testing.T) {
	h, _, _, _, _, _, _, _ := m4Org(t)
	w := h.do(t, http.MethodGet, "/api/v1/me", nil, "")
	require.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())
}

func TestMe_ReturnsProfileAndEffectiveOrgs(t *testing.T) {
	h, orgID, _, _, member, _, _, memberToken := m4Org(t)

	w := h.do(t, http.MethodGet, "/api/v1/me", nil, memberToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var body meBody
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	require.Equal(t, "ok", body.Code)
	require.EqualValues(t, member.ID, body.Data.User.Id)
	require.Equal(t, member.Email, body.Data.User.Email)
	require.True(t, body.Data.User.EmailVerified)
	require.True(t, body.Data.User.HasPassword)

	require.Len(t, body.Data.Orgs, 1)
	org := body.Data.Orgs[0]
	require.EqualValues(t, orgID, org.Id)
	require.Equal(t, model.RoleKindMember, org.RoleKind)
	require.ElementsMatch(t, authz.BuiltinPermissions(model.RoleKindMember), org.Permissions)
	require.NotEmpty(t, org.Permissions)

	// The response is the caller's own data only: no credential material may
	// appear anywhere in the payload.
	raw := w.Body.String()
	for _, leaked := range []string{"password_hash", "totp_secret", "secret_ciphertext", "recovery_codes", "refresh_token"} {
		require.NotContains(t, raw, leaked)
	}
}

func TestMe_DisabledMembershipDisappears(t *testing.T) {
	h, orgID, _, _, member, _, _, memberToken := m4Org(t)

	// The admin PATCH path is covered elsewhere; here the row is flipped
	// directly so the test pins /me's projection, not the disable workflow.
	require.NoError(t, store.WithoutTenantScope(h.db.DB).Model(&model.Membership{}).
		Where("organization_id = ? AND user_id = ?", orgID, member.ID).
		Update("disabled", true).Error)

	w := h.do(t, http.MethodGet, "/api/v1/me", nil, memberToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var body meBody
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	require.Empty(t, body.Data.Orgs, "a disabled membership authorizes nothing")
	require.EqualValues(t, member.ID, body.Data.User.Id, "the profile itself is still returned")
}

// /me has no organization in its path, so the request-audit middleware produces
// a tenant-less entry and the auditor drops it. That is the behaviour we want:
// the console calls /me on every load and it must not flood the trail. This
// test pins it so a later "audit everything" change has to think about it.
func TestMe_LeavesNoAuditRow(t *testing.T) {
	h, _, _, _, _, _, _, memberToken := m4Org(t)
	require.Equal(t, http.StatusOK, h.do(t, http.MethodGet, "/api/v1/me", nil, memberToken).Code)

	var rows int64
	require.NoError(t, store.WithoutTenantScope(h.db.DB).Model(&model.AuditLog{}).
		Where("action = ?", "GET /api/v1/me").Count(&rows).Error)
	require.Zero(t, rows)
}
