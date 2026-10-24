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

type issuedTokenView struct {
	Token struct {
		Id          int64  `json:"id"`
		TokenPrefix string `json:"token_prefix"`
	} `json:"token"`
	Plaintext string `json:"plaintext"`
}

func createTokenAPI(t *testing.T, h *harness, orgID int64, jwt, name string, perms []string) issuedTokenView {
	t.Helper()
	body := map[string]any{"name": name, "organization_id": orgID}
	if perms != nil {
		body["permissions"] = perms
	}
	w := h.do(t, http.MethodPost, "/api/v1/auth/tokens", body, jwt)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var view issuedTokenView
	decodeData(t, w, &view)
	require.NotEmpty(t, view.Plaintext)
	require.NotZero(t, view.Token.Id)
	return view
}

func TestToken_UseNarrowedAndJWTOnlySurfaces(t *testing.T) {
	h, orgID, _, _, _, ownerToken, _, _ := m4Org(t)
	view := createTokenAPI(t, h, orgID, ownerToken, "ci", []string{"device.read"})

	// The token works on organization endpoints with its narrowed permissions.
	w := h.do(t, http.MethodGet, "/api/v1/orgs/"+itoa(orgID)+"/devices", nil, view.Plaintext)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	w = h.do(t, http.MethodPost, "/api/v1/orgs/"+itoa(orgID)+"/devices",
		map[string]string{"name": "x", "rustdesk_id": "999"}, view.Plaintext)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

	// Non-organization endpoints require a JWT: a personal token has no tenant.
	w = h.do(t, http.MethodGet, "/api/v1/orgs", nil, view.Plaintext)
	require.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())
	w = h.do(t, http.MethodGet, "/api/v1/auth/tokens?organizationId="+itoa(orgID), nil, view.Plaintext)
	require.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())
	w = h.do(t, http.MethodPost, "/api/v1/auth/tokens",
		map[string]any{"name": "nested", "organization_id": orgID}, view.Plaintext)
	require.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())

	// The list uses the JWT and never returns the plaintext.
	w = h.do(t, http.MethodGet, "/api/v1/auth/tokens?organizationId="+itoa(orgID), nil, ownerToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var tokens []struct {
		Id          int64    `json:"id"`
		TokenPrefix string   `json:"token_prefix"`
		Permissions []string `json:"permissions"`
	}
	decodeData(t, w, &tokens)
	require.Len(t, tokens, 1)
	require.Equal(t, view.Token.TokenPrefix, tokens[0].TokenPrefix)
	require.Equal(t, []string{"device.read"}, tokens[0].Permissions)
	require.NotContains(t, w.Body.String(), view.Plaintext, "the plaintext must never be listed")
}

func TestToken_DowngradedRoleNarrowsAndDisabledMembershipRejected(t *testing.T) {
	h, orgID, _, admin, _, ownerToken, adminToken, memberToken := m4Org(t)
	_ = memberToken
	view := createTokenAPI(t, h, orgID, adminToken, "ops", []string{"device.read", "device.write"})

	// The admin's token can write devices while the role holds device.write.
	w := h.do(t, http.MethodPost, "/api/v1/orgs/"+itoa(orgID)+"/devices",
		map[string]string{"name": "x", "rustdesk_id": "123123123"}, view.Plaintext)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())

	// Demoting the admin to member narrows the token to the intersection.
	memberRoleID := int64(h.roleID(t, uint(orgID), model.RoleMember))
	w = h.do(t, http.MethodPatch, "/api/v1/orgs/"+itoa(orgID)+"/members/"+itoa(int64(admin.ID)),
		map[string]any{"role_id": memberRoleID}, ownerToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	w = h.do(t, http.MethodGet, "/api/v1/orgs/"+itoa(orgID)+"/devices", nil, view.Plaintext)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	w = h.do(t, http.MethodPost, "/api/v1/orgs/"+itoa(orgID)+"/devices",
		map[string]string{"name": "y", "rustdesk_id": "456456456"}, view.Plaintext)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

	// Disabling the membership kills the token entirely.
	w = h.do(t, http.MethodPatch, "/api/v1/orgs/"+itoa(orgID)+"/members/"+itoa(int64(admin.ID)),
		map[string]any{"disabled": true}, ownerToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	w = h.do(t, http.MethodGet, "/api/v1/orgs/"+itoa(orgID)+"/devices", nil, view.Plaintext)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
}

func TestToken_CreationCeilingAndOrgBinding(t *testing.T) {
	h, orgID, _, _, _, ownerToken, _, memberToken := m4Org(t)
	// A member may create a token only within its own role.
	w := h.do(t, http.MethodPost, "/api/v1/auth/tokens", map[string]any{
		"name": "elevated", "organization_id": orgID, "permissions": []string{"device.write"},
	}, memberToken)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

	view := createTokenAPI(t, h, orgID, memberToken, "read-only", nil)
	w = h.do(t, http.MethodGet, "/api/v1/orgs/"+itoa(orgID)+"/devices", nil, view.Plaintext)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	// Unknown permission code is rejected as input.
	w = h.do(t, http.MethodPost, "/api/v1/auth/tokens", map[string]any{
		"name": "bad", "organization_id": orgID, "permissions": []string{"org.nuke"},
	}, memberToken)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())

	// A token bound to org A cannot be used against org B.
	otherOrg := createOrg(t, h, ownerToken, "token-other-org")
	w = h.do(t, http.MethodGet, "/api/v1/orgs/"+itoa(otherOrg)+"/devices", nil, view.Plaintext)
	require.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())

	// Another user's token ids are invisible to revocation.
	w = h.do(t, http.MethodDelete, "/api/v1/auth/tokens/"+itoa(view.Token.Id), nil, ownerToken)
	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())
	w = h.do(t, http.MethodDelete, "/api/v1/auth/tokens/"+itoa(view.Token.Id), nil, memberToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	w = h.do(t, http.MethodGet, "/api/v1/orgs/"+itoa(orgID)+"/devices", nil, view.Plaintext)
	require.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())
}

func TestToken_ExpiryAndLimit(t *testing.T) {
	h, orgID, _, _, _, ownerToken, _, _ := m4Org(t)
	view := createTokenAPI(t, h, orgID, ownerToken, "short", []string{"device.read"})
	require.NoError(t, store.WithoutTenantScope(h.db.DB).Model(&model.APIToken{}).
		Where("id = ?", view.Token.Id).Update("expires_at", time.Now().UTC().Add(-time.Minute)).Error)
	w := h.do(t, http.MethodGet, "/api/v1/orgs/"+itoa(orgID)+"/devices", nil, view.Plaintext)
	require.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())

	// The expired token no longer counts as active; fill all 20 slots.
	for i := 0; i < 20; i++ {
		createTokenAPI(t, h, orgID, ownerToken, "bulk", []string{"device.read"})
	}
	w = h.do(t, http.MethodPost, "/api/v1/auth/tokens", map[string]any{
		"name": "over", "organization_id": orgID,
	}, ownerToken)
	require.Equal(t, http.StatusConflict, w.Code, w.Body.String())
}

func TestToken_ResponseNeverContainsPlaintextAfterCreation(t *testing.T) {
	h, orgID, _, _, _, ownerToken, _, _ := m4Org(t)
	view := createTokenAPI(t, h, orgID, ownerToken, "once", []string{"device.read"})
	require.NotEmpty(t, view.Token.TokenPrefix)
	w := h.do(t, http.MethodGet, "/api/v1/auth/tokens?organizationId="+itoa(orgID), nil, ownerToken)
	require.Equal(t, http.StatusOK, w.Code)
	var raw struct {
		Data []map[string]any `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &raw))
	require.Len(t, raw.Data, 1)
	require.NotContains(t, raw.Data[0], "plaintext")
	require.NotContains(t, raw.Data[0], "token_hash")
}
