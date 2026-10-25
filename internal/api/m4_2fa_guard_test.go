package api_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// messageOf returns the human-readable error message of a response.
func messageOf(t *testing.T, body []byte) string {
	t.Helper()
	var resp struct {
		Message string `json:"message"`
	}
	require.NoError(t, json.Unmarshal(body, &resp))
	return resp.Message
}

// The self-service second-factor endpoints verify a password and a TOTP code,
// so they are credential oracles like the login second step: the same
// account/IP budget must stop brute force, and the response must not reveal
// which factor was wrong.
func TestTOTP_SelfServiceDisableIsRateLimited(t *testing.T) {
	h, now := newTOTPHarness(t)
	h.seedUser(t, "guard-disable@example.com", "password123")
	jwt := h.login(t, "guard-disable@example.com", "password123")
	secret := enableTOTPAPIAt(t, h, jwt, *now)

	wrongPassword := h.do(t, http.MethodPost, "/api/v1/auth/2fa/disable", map[string]string{
		"password": "wrong-password", "code": apiTOTPCode(secret, *now),
	}, jwt)
	require.Equal(t, http.StatusUnauthorized, wrongPassword.Code, wrongPassword.Body.String())
	wrongCode := h.do(t, http.MethodPost, "/api/v1/auth/2fa/disable", map[string]string{
		"password": "password123", "code": "000000",
	}, jwt)
	require.Equal(t, http.StatusUnauthorized, wrongCode.Code, wrongCode.Body.String())
	require.Equal(t, messageOf(t, wrongPassword.Body.Bytes()), messageOf(t, wrongCode.Body.Bytes()),
		"the error must not disclose which factor failed")

	// The shared guard allows five failures; the sixth attempt is refused even
	// with the correct password and a current code.
	for i := 0; i < 3; i++ {
		w := h.do(t, http.MethodPost, "/api/v1/auth/2fa/disable", map[string]string{
			"password": "wrong-password", "code": "000000",
		}, jwt)
		require.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())
	}
	w := h.do(t, http.MethodPost, "/api/v1/auth/2fa/disable", map[string]string{
		"password": "password123", "code": apiTOTPCode(secret, *now),
	}, jwt)
	require.Equal(t, http.StatusTooManyRequests, w.Code, w.Body.String())
}

// Regenerating recovery codes checks the same two factors, so it needs the
// same throttle; otherwise it is an unguarded password+TOTP oracle.
func TestTOTP_RecoveryRegenerationIsRateLimited(t *testing.T) {
	h, now := newTOTPHarness(t)
	h.seedUser(t, "guard-recovery@example.com", "password123")
	jwt := h.login(t, "guard-recovery@example.com", "password123")
	secret := enableTOTPAPIAt(t, h, jwt, *now)

	for i := 0; i < 5; i++ {
		w := h.do(t, http.MethodPost, "/api/v1/auth/2fa/recovery-codes", map[string]string{
			"password": "wrong-password", "code": "000000",
		}, jwt)
		require.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())
	}
	w := h.do(t, http.MethodPost, "/api/v1/auth/2fa/recovery-codes", map[string]string{
		"password": "password123", "code": apiTOTPCode(secret, *now),
	}, jwt)
	require.Equal(t, http.StatusTooManyRequests, w.Code, w.Body.String())
}
