package api_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/passkey/testauth"
)

// stepupToken drives the whole step-up flow for a seeded passkey.
func stepupToken(t *testing.T, h *harness, jwt string, authn *testauth.Authenticator, userID uint, signCount uint32) string {
	t.Helper()

	w := h.do(t, http.MethodPost, "/api/v1/auth/passkey/stepup/begin", nil, jwt)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var begin ceremonyView
	decodeData(t, w, &begin)

	w = h.do(t, http.MethodPost, "/api/v1/auth/passkey/stepup/finish", map[string]any{
		"ceremony_token": begin.CeremonyToken,
		"credential": mustDecode(t, authn.Assertion(t, begin.Options.PublicKey.Challenge, signCount,
			passkeyHandle(userID))),
	}, jwt)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var view struct {
		StepupToken string `json:"stepup_token"`
	}
	decodeData(t, w, &view)
	require.NotEmpty(t, view.StepupToken)
	return view.StepupToken
}

func TestPasswordRemove_RequiresTwoPasskeys(t *testing.T) {
	h, svc, u, jwt := passkeyLoginHarness(t)
	authn := testauth.New(t, passkeyRPID, passkeyOrigin)
	seedPasskey(t, svc, u, authn)

	stepup := stepupToken(t, h, jwt, authn, u.ID, 1)
	w := h.do(t, http.MethodPost, "/api/v1/auth/password/remove", map[string]any{
		"password":     "password123",
		"stepup_token": stepup,
	}, jwt)
	require.Equal(t, http.StatusConflict, w.Code, w.Body.String())
}

func TestPasswordRemove_RefusesWhenTOTPConfigured(t *testing.T) {
	h, svc, u, jwt := passkeyLoginHarness(t)
	authn := testauth.New(t, passkeyRPID, passkeyOrigin)
	seedPasskey(t, svc, u, authn)
	seedPasskey(t, svc, u, testauth.New(t, passkeyRPID, passkeyOrigin))

	require.NoError(t, h.db.DB.Create(&model.UserTOTP{
		UserID:           u.ID,
		SecretCiphertext: "x",
		RecoveryCodes:    "[]",
	}).Error)

	stepup := stepupToken(t, h, jwt, authn, u.ID, 1)
	w := h.do(t, http.MethodPost, "/api/v1/auth/password/remove", map[string]any{
		"password":     "password123",
		"stepup_token": stepup,
	}, jwt)
	require.Equal(t, http.StatusConflict, w.Code, w.Body.String())
}

func TestPasswordRemove_WrongPasswordRejected(t *testing.T) {
	h, svc, u, jwt := passkeyLoginHarness(t)
	authn := testauth.New(t, passkeyRPID, passkeyOrigin)
	seedPasskey(t, svc, u, authn)
	seedPasskey(t, svc, u, testauth.New(t, passkeyRPID, passkeyOrigin))

	stepup := stepupToken(t, h, jwt, authn, u.ID, 1)
	w := h.do(t, http.MethodPost, "/api/v1/auth/password/remove", map[string]any{
		"password":     "wrong-password",
		"stepup_token": stepup,
	}, jwt)
	require.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())
}

func TestPasswordRemove_ThenPasswordLoginFailsGenerically(t *testing.T) {
	h, svc, u, jwt := passkeyLoginHarness(t)
	authn := testauth.New(t, passkeyRPID, passkeyOrigin)
	seedPasskey(t, svc, u, authn)
	seedPasskey(t, svc, u, testauth.New(t, passkeyRPID, passkeyOrigin))

	stepup := stepupToken(t, h, jwt, authn, u.ID, 1)
	w := h.do(t, http.MethodPost, "/api/v1/auth/password/remove", map[string]any{
		"password":     "password123",
		"stepup_token": stepup,
	}, jwt)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var stale model.User
	require.NoError(t, h.db.DB.Where("id = ?", u.ID).First(&stale).Error)
	require.Empty(t, stale.PasswordHash)

	// The password endpoint must not reveal that the account is passwordless.
	w = h.do(t, http.MethodPost, "/api/v1/auth/login", map[string]string{
		"email": u.Email, "password": "password123",
	}, "")
	require.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())
	require.NotContains(t, w.Body.String(), "passkey")
}

func TestPasswordRemove_InvalidStepupRejected(t *testing.T) {
	h, svc, u, jwt := passkeyLoginHarness(t)
	authn := testauth.New(t, passkeyRPID, passkeyOrigin)
	seedPasskey(t, svc, u, authn)
	seedPasskey(t, svc, u, testauth.New(t, passkeyRPID, passkeyOrigin))

	w := h.do(t, http.MethodPost, "/api/v1/auth/password/remove", map[string]any{
		"password":     "password123",
		"stepup_token": "not-a-token",
	}, jwt)
	require.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())
}

func TestPasswordSet_OnlyWhenAbsent(t *testing.T) {
	h, svc, u, jwt := passkeyLoginHarness(t)
	authn := testauth.New(t, passkeyRPID, passkeyOrigin)
	seedPasskey(t, svc, u, authn)

	// Existing password: setting is refused.
	stepup := stepupToken(t, h, jwt, authn, u.ID, 1)
	w := h.do(t, http.MethodPost, "/api/v1/auth/password/set", map[string]any{
		"new_password": "another-password",
		"stepup_token": stepup,
	}, jwt)
	require.Equal(t, http.StatusConflict, w.Code, w.Body.String())

	// Remove it, then set it again.
	require.NoError(t, h.db.DB.Model(&model.User{}).Where("id = ?", u.ID).Update("password_hash", "").Error)
	stepup = stepupToken(t, h, jwt, authn, u.ID, 2)
	w = h.do(t, http.MethodPost, "/api/v1/auth/password/set", map[string]any{
		"new_password": "restored-password",
		"stepup_token": stepup,
	}, jwt)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	w = h.do(t, http.MethodPost, "/api/v1/auth/login", map[string]string{
		"email": u.Email, "password": "restored-password",
	}, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
}

func TestPasswordSet_InvalidStepupRejected(t *testing.T) {
	h, _, u, jwt := passkeyLoginHarness(t)
	require.NoError(t, h.db.DB.Model(&model.User{}).Where("id = ?", u.ID).Update("password_hash", "").Error)

	w := h.do(t, http.MethodPost, "/api/v1/auth/password/set", map[string]any{
		"new_password": "another-password",
		"stepup_token": "not-a-token",
	}, jwt)
	require.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())
}
