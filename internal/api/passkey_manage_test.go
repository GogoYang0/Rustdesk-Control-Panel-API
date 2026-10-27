package api_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/passkey/testauth"
)

func TestPasskeyList_ReportsAccountState(t *testing.T) {
	h, svc, u, jwt := passkeyLoginHarness(t)
	authn := testauth.New(t, passkeyRPID, passkeyOrigin)
	seedPasskey(t, svc, u, authn)

	w := h.do(t, http.MethodGet, "/api/v1/auth/passkeys", nil, jwt)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var view struct {
		Items []struct {
			Id   int64  `json:"id"`
			Name string `json:"name"`
		} `json:"items"`
		HasPassword bool `json:"has_password"`
		TotpEnabled bool `json:"totp_enabled"`
	}
	decodeData(t, w, &view)
	require.Len(t, view.Items, 1)
	require.Equal(t, "Phone", view.Items[0].Name)
	require.True(t, view.HasPassword)
	require.False(t, view.TotpEnabled)
}

func TestPasskeyRename_OwnOnly(t *testing.T) {
	h, svc, u, jwt := passkeyLoginHarness(t)
	ownerAuthn := testauth.New(t, passkeyRPID, passkeyOrigin)
	seedPasskey(t, svc, u, ownerAuthn)

	other := h.seedUser(t, "passkey-rename-other@example.com", "password123")
	otherAuthn := testauth.New(t, passkeyRPID, passkeyOrigin)
	seedPasskey(t, svc, other, otherAuthn)

	var list struct {
		Items []struct {
			Id int64 `json:"id"`
		} `json:"items"`
	}
	w := h.do(t, http.MethodGet, "/api/v1/auth/passkeys", nil, jwt)
	require.Equal(t, http.StatusOK, w.Code)
	decodeData(t, w, &list)
	require.Len(t, list.Items, 1)

	w = h.do(t, http.MethodPatch, "/api/v1/auth/passkeys/"+itoa(list.Items[0].Id), map[string]string{"name": "  Desk  "}, jwt)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var renamed struct {
		Name string `json:"name"`
	}
	decodeData(t, w, &renamed)
	require.Equal(t, "Desk", renamed.Name)

	// The other account's credential id must be invisible (404, not 403).
	var otherList struct {
		Items []struct {
			Id int64 `json:"id"`
		} `json:"items"`
	}
	w = h.do(t, http.MethodGet, "/api/v1/auth/passkeys", nil, h.login(t, "passkey-rename-other@example.com", "password123"))
	require.Equal(t, http.StatusOK, w.Code)
	decodeData(t, w, &otherList)
	require.Len(t, otherList.Items, 1)

	w = h.do(t, http.MethodPatch, "/api/v1/auth/passkeys/"+itoa(otherList.Items[0].Id), map[string]string{"name": "Stolen"}, jwt)
	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())
}

func TestPasskeyDelete_LastCredentialWithPasswordAllowed(t *testing.T) {
	h, svc, u, jwt := passkeyLoginHarness(t)
	seedPasskey(t, svc, u, testauth.New(t, passkeyRPID, passkeyOrigin))

	var list struct {
		Items []struct {
			Id int64 `json:"id"`
		} `json:"items"`
	}
	w := h.do(t, http.MethodGet, "/api/v1/auth/passkeys", nil, jwt)
	require.Equal(t, http.StatusOK, w.Code)
	decodeData(t, w, &list)

	w = h.do(t, http.MethodDelete, "/api/v1/auth/passkeys/"+itoa(list.Items[0].Id), nil, jwt)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var count int64
	require.NoError(t, h.db.DB.Model(&model.UserPasskey{}).Where("user_id = ?", u.ID).Count(&count).Error)
	require.Zero(t, count)
}

func TestPasskeyDelete_LastCredentialPasswordlessConflicts(t *testing.T) {
	h, svc, u, jwt := passkeyLoginHarness(t)
	seedPasskey(t, svc, u, testauth.New(t, passkeyRPID, passkeyOrigin))

	// Turn the account into passkey-only behind the API's back: the endpoint
	// being tested is the delete guard, not the removal flow (task 9).
	require.NoError(t, h.db.DB.Model(&model.User{}).Where("id = ?", u.ID).Update("password_hash", "").Error)

	var list struct {
		Items []struct {
			Id int64 `json:"id"`
		} `json:"items"`
	}
	w := h.do(t, http.MethodGet, "/api/v1/auth/passkeys", nil, jwt)
	require.Equal(t, http.StatusOK, w.Code)
	decodeData(t, w, &list)

	w = h.do(t, http.MethodDelete, "/api/v1/auth/passkeys/"+itoa(list.Items[0].Id), nil, jwt)
	require.Equal(t, http.StatusConflict, w.Code, w.Body.String())
}

func TestPasskeyList_DisabledReturns503(t *testing.T) {
	h := newHarness(t)
	u := h.seedUser(t, "passkey-list-off@example.com", "password123")
	_ = u
	jwt := h.login(t, "passkey-list-off@example.com", "password123")

	w := h.do(t, http.MethodGet, "/api/v1/auth/passkeys", nil, jwt)
	require.Equal(t, http.StatusServiceUnavailable, w.Code, w.Body.String())
}
