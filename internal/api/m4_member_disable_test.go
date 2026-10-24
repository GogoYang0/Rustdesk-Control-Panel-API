package api_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// compatLogin authenticates a RustDesk client through the compat layer and
// returns its bearer token.
func compatLogin(t *testing.T, h *harness, email, password, deviceID, uuid string) string {
	t.Helper()
	w := h.do(t, http.MethodPost, "/api/login", map[string]string{
		"username": email, "password": password, "id": deviceID, "uuid": uuid,
	}, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var resp struct {
		AccessToken string `json:"access_token"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.NotEmpty(t, resp.AccessToken)
	return resp.AccessToken
}

// compatLoginCode returns the HTTP status of a compat login attempt.
func compatLoginCode(t *testing.T, h *harness, email, password, deviceID, uuid string) int {
	t.Helper()
	w := h.do(t, http.MethodPost, "/api/login", map[string]string{
		"username": email, "password": password, "id": deviceID, "uuid": uuid,
	}, "")
	return w.Code
}

func TestMemberDisable_RevokesSessionsAndBlocksLogin(t *testing.T) {
	h, orgID, owner, _, member, ownerToken, adminToken, memberToken := m4Org(t)

	token := compatLogin(t, h, "m4-member@example.com", "password123", "disable-device", "uuid-disable")
	w := h.do(t, http.MethodGet, "/api/peers", nil, token)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	memberPath := "/api/v1/orgs/" + itoa(orgID) + "/members/" + itoa(int64(member.ID))
	w = h.do(t, http.MethodPatch, memberPath, map[string]any{"disabled": true}, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var disabled m4MemberView
	decodeData(t, w, &disabled)
	require.True(t, disabled.Disabled)
	require.Equal(t, "member", disabled.RoleName)

	// The live compat session dies with the membership.
	w = h.do(t, http.MethodGet, "/api/peers", nil, token)
	require.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())

	// A disabled member cannot log in again.
	require.Equal(t, http.StatusForbidden,
		compatLoginCode(t, h, "m4-member@example.com", "password123", "disable-device-2", "uuid-disable-2"))

	// The management token stays cryptographically valid, but the disabled
	// membership must not open any organization endpoint.
	w = h.do(t, http.MethodGet, "/api/v1/orgs/"+itoa(orgID)+"/members", nil, memberToken)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

	// An admin cannot disable an owner; nobody may disable themselves.
	ownerPath := "/api/v1/orgs/" + itoa(orgID) + "/members/" + itoa(int64(owner.ID))
	w = h.do(t, http.MethodPatch, ownerPath, map[string]any{"disabled": true}, adminToken)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	w = h.do(t, http.MethodPatch, ownerPath, map[string]any{"disabled": true}, ownerToken)
	require.Equal(t, http.StatusConflict, w.Code, w.Body.String())

	// Restoring the membership lets the user sign in again.
	w = h.do(t, http.MethodPatch, memberPath, map[string]any{"disabled": false}, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var restored m4MemberView
	decodeData(t, w, &restored)
	require.False(t, restored.Disabled)
	token = compatLogin(t, h, "m4-member@example.com", "password123", "disable-device-3", "uuid-disable-3")
	w = h.do(t, http.MethodGet, "/api/peers", nil, token)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	// A plain member lacks member.manage and cannot disable anyone.
	w = h.do(t, http.MethodPatch, memberPath, map[string]any{"disabled": true}, memberToken)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

	require.EqualValues(t, 1, countAudit(t, h, "action = ?", "organization.member.disable"))
	require.EqualValues(t, 1, countAudit(t, h, "action = ?", "organization.member.enable"))
}

func TestMemberDisable_IdempotentAndLastOwner(t *testing.T) {
	h, orgID, owner, _, member, ownerToken, adminToken, _ := m4Org(t)

	memberPath := "/api/v1/orgs/" + itoa(orgID) + "/members/" + itoa(int64(member.ID))
	w := h.do(t, http.MethodPatch, memberPath, map[string]any{"disabled": true}, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	// Repeating the same state is a 200 no-op and writes no second audit row.
	w = h.do(t, http.MethodPatch, memberPath, map[string]any{"disabled": true}, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.EqualValues(t, 1, countAudit(t, h, "action = ?", "organization.member.disable"))

	// A second owner makes the first owner non-last; disabling that target is
	// allowed for an owner actor, and the last remaining owner is then
	// protected from an admin.
	second := h.seedUser(t, "m4-owner2@example.com", "password123")
	seedMember(t, h, orgID, second.ID, "owner")
	secondPath := "/api/v1/orgs/" + itoa(orgID) + "/members/" + itoa(int64(second.ID))
	// The creator may disable the second owner while at least one owner stays.
	w = h.do(t, http.MethodPatch, secondPath, map[string]any{"disabled": true}, ownerToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Zero(t, countAudit(t, h, "action = ?", "organization.member.enable"))

	// Only a non-self owner remains; an admin must not disable them.
	require.NotZero(t, owner.ID)
	w = h.do(t, http.MethodPatch, "/api/v1/orgs/"+itoa(orgID)+"/members/"+itoa(int64(owner.ID)),
		map[string]any{"disabled": true}, adminToken)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
}
