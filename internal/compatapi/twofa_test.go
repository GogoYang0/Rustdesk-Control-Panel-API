package compatapi_test

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// compatTOTPCode computes the RFC 6238 code for a secret at a moment.
func compatTOTPCode(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	require.NoError(t, err)
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(at.Unix()/30))
	mac := hmac.New(sha1.New, raw)
	mac.Write(buf)
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", value%1000000)
}

// seed2FAUser creates a verified user with a membership and TOTP enabled.
func seed2FAUser(t *testing.T, h *harness) (model.User, model.Organization, string) {
	t.Helper()
	user := h.seedUser(t, "twofa@example.com", "password123", true)
	org := h.seedOrg(t, "twofa-org")
	h.seedMembership(t, user.ID, org.ID)
	secret, _, err := h.totp.Setup(user.ID)
	require.NoError(t, err)
	require.NoError(t, h.totp.Enable(user.ID, compatTOTPCode(t, secret, h.now)))
	// Enrolment consumes the code for the current 30s step; move past it so the
	// login below is not judged a replay (the same protection the panel login
	// relies on).
	h.now = h.now.Add(30 * time.Second)
	return user, org, secret
}

func (h *harness) loginBody(deviceID, uuid string) map[string]any {
	return map[string]any{
		"username": "twofa@example.com",
		"password": "password123",
		"id":       deviceID,
		"uuid":     uuid,
		"type":     "account",
	}
}

func TestLogin_2FARequiredReturnsChallenge(t *testing.T) {
	h := newHarness(t)
	_, _, _ = seed2FAUser(t, h)

	w := h.do(t, http.MethodPost, "/api/login", h.loginBody("600001", "uuid-2fa"), "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	body := decodeCompatBody(t, w)
	require.Equal(t, "email_check", body["type"])
	require.Equal(t, "totp", body["tfa_type"])
	require.NotEmpty(t, body["secret"])
	require.Nil(t, body["access_token"], "the first step must not issue a token")
}

func TestLogin_2FAValidCodeIssuesToken(t *testing.T) {
	h := newHarness(t)
	_, _, secret := seed2FAUser(t, h)

	w := h.do(t, http.MethodPost, "/api/login", h.loginBody("600001", "uuid-2fa"), "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	challenge := decodeCompatBody(t, w)

	code := compatTOTPCode(t, secret, h.now)
	w = h.do(t, http.MethodPost, "/api/login", map[string]any{
		"username":         "twofa@example.com",
		"id":               "600001",
		"uuid":             "uuid-2fa",
		"type":             "email_code",
		"verificationCode": code,
		"tfaCode":          code,
		"secret":           challenge["secret"],
	}, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	body := decodeCompatBody(t, w)
	require.NotEmpty(t, body["access_token"])
	require.Equal(t, "access_token", body["type"])

	// The device is now bound to the session the second step created.
	var dev model.Device
	require.NoError(t, store.WithoutTenantScope(h.db.DB).Where("rustdesk_id = ?", "600001").First(&dev).Error)
	require.Equal(t, "uuid-2fa", dev.BoundUUID)
}

func TestLogin_2FAWrongCodeRejects(t *testing.T) {
	h := newHarness(t)
	_, _, _ = seed2FAUser(t, h)

	w := h.do(t, http.MethodPost, "/api/login", h.loginBody("600001", "uuid-2fa"), "")
	challenge := decodeCompatBody(t, w)

	w = h.do(t, http.MethodPost, "/api/login", map[string]any{
		"username": "twofa@example.com", "id": "600001", "uuid": "uuid-2fa",
		"type": "email_code", "tfaCode": "000000", "secret": challenge["secret"],
	}, "")
	require.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())
}

func TestLogin_2FAChallengeBoundToDevice(t *testing.T) {
	h := newHarness(t)
	_, _, secret := seed2FAUser(t, h)

	w := h.do(t, http.MethodPost, "/api/login", h.loginBody("600001", "uuid-2fa"), "")
	challenge := decodeCompatBody(t, w)

	code := compatTOTPCode(t, secret, h.now)
	w = h.do(t, http.MethodPost, "/api/login", map[string]any{
		"username": "twofa@example.com", "id": "600001", "uuid": "another-uuid",
		"type": "email_code", "tfaCode": code, "secret": challenge["secret"],
	}, "")
	require.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())
}

func TestLogin_2FAChallengeIsSingleUse(t *testing.T) {
	h := newHarness(t)
	_, _, secret := seed2FAUser(t, h)

	w := h.do(t, http.MethodPost, "/api/login", h.loginBody("600001", "uuid-2fa"), "")
	challenge := decodeCompatBody(t, w)
	code := compatTOTPCode(t, secret, h.now)
	payload := map[string]any{
		"username": "twofa@example.com", "id": "600001", "uuid": "uuid-2fa",
		"type": "email_code", "tfaCode": code, "secret": challenge["secret"],
	}
	w = h.do(t, http.MethodPost, "/api/login", payload, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	w = h.do(t, http.MethodPost, "/api/login", payload, "")
	require.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())
}

func TestLogin_2FAChallengeExpires(t *testing.T) {
	h := newHarness(t)
	_, _, secret := seed2FAUser(t, h)

	w := h.do(t, http.MethodPost, "/api/login", h.loginBody("600001", "uuid-2fa"), "")
	challenge := decodeCompatBody(t, w)

	h.now = h.now.Add(6 * time.Minute)
	code := compatTOTPCode(t, secret, h.now)
	w = h.do(t, http.MethodPost, "/api/login", map[string]any{
		"username": "twofa@example.com", "id": "600001", "uuid": "uuid-2fa",
		"type": "email_code", "tfaCode": code, "secret": challenge["secret"],
	}, "")
	require.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())
}

func TestLogin_EmailCodeBranchWithoutChallengeRejects(t *testing.T) {
	h := newHarness(t)
	user := h.seedUser(t, "plain@example.com", "password123", true)
	org := h.seedOrg(t, "plain-org")
	h.seedMembership(t, user.ID, org.ID)

	w := h.do(t, http.MethodPost, "/api/login", map[string]any{
		"username": "plain@example.com", "id": "600002", "uuid": "uuid-plain",
		"type": "email_code", "tfaCode": "123456", "secret": "bogus",
	}, "")
	require.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())
}

// TestLogin_No2FAStillSingleStep keeps the old behaviour for accounts without a
// second factor: one request, one token.
func TestLogin_No2FAStillSingleStep(t *testing.T) {
	h := newHarness(t)
	user := h.seedUser(t, "plain@example.com", "password123", true)
	org := h.seedOrg(t, "plain-org")
	h.seedMembership(t, user.ID, org.ID)

	w := h.do(t, http.MethodPost, "/api/login", map[string]any{
		"username": "plain@example.com", "password": "password123",
		"id": "600002", "uuid": "uuid-plain", "type": "account",
	}, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.NotEmpty(t, decodeCompatBody(t, w)["access_token"])
}

// decodeCompatBody reads a compat response body as a map.
func decodeCompatBody(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	return body
}

// TestLogin_2FAUsernameMustMatchChallenge pins the fix for lockout evasion:
// the second step must name the challenge's account, otherwise an attacker
// holding a challenge could rotate usernames to spread failures.
func TestLogin_2FAUsernameMustMatchChallenge(t *testing.T) {
	h := newHarness(t)
	_, _, secret := seed2FAUser(t, h)
	other := h.seedUser(t, "other@example.com", "password123", true)
	require.NotZero(t, other.ID)

	w := h.do(t, http.MethodPost, "/api/login", h.loginBody("600003", "uuid-2fa"), "")
	challenge := decodeCompatBody(t, w)

	code := compatTOTPCode(t, secret, h.now)
	w = h.do(t, http.MethodPost, "/api/login", map[string]any{
		"username": "other@example.com", "id": "600003", "uuid": "uuid-2fa",
		"type": "email_code", "tfaCode": code, "secret": challenge["secret"],
	}, "")
	require.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())
}
