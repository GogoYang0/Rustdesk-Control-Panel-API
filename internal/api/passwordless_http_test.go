package api_test

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/passkey/testauth"
)

// TestLogin_MethodsReflectFactors keeps the 2FA challenge honest: the client
// must be told which factors can actually complete the login.
func TestLogin_MethodsReflectFactors(t *testing.T) {
	h, svc, u, _ := passkeyLoginHarness(t)

	now := time.Now()
	require.NoError(t, h.db.DB.Create(&model.UserTOTP{
		UserID:           u.ID,
		SecretCiphertext: "x",
		RecoveryCodes:    "[]",
		EnabledAt:        &now,
	}).Error)

	// TOTP only.
	w := h.do(t, http.MethodPost, "/api/v1/auth/login", map[string]string{
		"email": u.Email, "password": "password123",
	}, "")
	require.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())
	var challenge struct {
		Code string `json:"code"`
		Data struct {
			Methods []string `json:"methods"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &challenge))
	require.Equal(t, "two_factor_required", challenge.Code)
	require.Equal(t, []string{"totp"}, challenge.Data.Methods)

	// TOTP plus a passkey.
	seedPasskey(t, svc, u, testauth.New(t, passkeyRPID, passkeyOrigin))
	w = h.do(t, http.MethodPost, "/api/v1/auth/login", map[string]string{
		"email": u.Email, "password": "password123",
	}, "")
	require.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &challenge))
	require.Equal(t, []string{"totp", "passkey"}, challenge.Data.Methods)
}

// TestTwoFactorEndpoints_RejectPasswordlessAccount keeps the account state
// coherent: TOTP cannot complete a second step without a password, so letting a
// passwordless account enrol would create a factor that can never be used.
func TestTwoFactorEndpoints_RejectPasswordlessAccount(t *testing.T) {
	h, _, u, _ := passkeyLoginHarness(t)
	require.NoError(t, h.db.DB.Model(&model.User{}).Where("id = ?", u.ID).Update("password_hash", "").Error)

	access, _, err := h.issuer.Issue(u.ID)
	require.NoError(t, err)

	cases := []struct {
		name string
		path string
		body any
	}{
		{"setup", "/api/v1/auth/2fa/setup", nil},
		{"enable", "/api/v1/auth/2fa/enable", map[string]string{"code": "123456"}},
		{"disable", "/api/v1/auth/2fa/disable", map[string]string{"password": "x", "code": "123456"}},
		{"recovery", "/api/v1/auth/2fa/recovery-codes", map[string]string{"password": "x", "code": "123456"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := h.do(t, http.MethodPost, tc.path, tc.body, access)
			require.Equal(t, http.StatusConflict, w.Code, w.Body.String())
		})
	}
}
