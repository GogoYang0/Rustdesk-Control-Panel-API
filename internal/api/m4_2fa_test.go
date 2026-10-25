package api_test

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/api"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/auth"
)

// apiTOTPCode computes the RFC 6238 code for a secret at a moment.
func apiTOTPCode(secret string, at time.Time) string {
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		panic(err)
	}
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(at.Unix()/30))
	mac := hmac.New(sha1.New, raw)
	mac.Write(buf)
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", value%1000000)
}

// newTOTPHarness wires a controllable clock into the TOTP service so a test can
// advance time between steps without sleeping.
func newTOTPHarness(t *testing.T) (*harness, *time.Time) {
	t.Helper()
	start := time.Now().UTC().Truncate(30 * time.Second)
	h := newHarnessWith(t, func(d *api.Deps) {
		d.TOTP = auth.NewTOTPService(d.DB, "test-secret", func() time.Time { return start })
	})
	return h, &start
}

// enableTOTPAPIAt runs setup + enable with a code for the given instant.
func enableTOTPAPIAt(t *testing.T, h *harness, jwt string, at time.Time) string {
	t.Helper()
	w := h.do(t, http.MethodPost, "/api/v1/auth/2fa/setup", nil, jwt)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var setup struct {
		Data struct {
			Secret string `json:"secret"`
			Uri    string `json:"otpauth_uri"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &setup))
	require.NotEmpty(t, setup.Data.Secret)
	require.Contains(t, setup.Data.Uri, "otpauth://")

	w = h.do(t, http.MethodPost, "/api/v1/auth/2fa/enable", map[string]any{
		"code": apiTOTPCode(setup.Data.Secret, at),
	}, jwt)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	return setup.Data.Secret
}

// enableTOTPAPI runs setup + enable and returns the base32 secret.
func enableTOTPAPI(t *testing.T, h *harness, jwt string) string {
	t.Helper()
	w := h.do(t, http.MethodPost, "/api/v1/auth/2fa/setup", nil, jwt)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var setup struct {
		Data struct {
			Secret string `json:"secret"`
			Uri    string `json:"otpauth_uri"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &setup))
	require.NotEmpty(t, setup.Data.Secret)
	require.Contains(t, setup.Data.Uri, "otpauth://")

	w = h.do(t, http.MethodPost, "/api/v1/auth/2fa/enable", map[string]any{
		"code": apiTOTPCode(setup.Data.Secret, time.Now()),
	}, jwt)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	return setup.Data.Secret
}

// loginChallenge performs the password step and returns the challenge token.
func loginChallenge(t *testing.T, h *harness, email, password string) string {
	t.Helper()
	w := h.do(t, http.MethodPost, "/api/v1/auth/login", map[string]string{
		"email": email, "password": password,
	}, "")
	require.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())
	var resp struct {
		Code string `json:"code"`
		Data struct {
			ChallengeToken string `json:"challenge_token"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.Equal(t, "two_factor_required", resp.Code)
	require.NotEmpty(t, resp.Data.ChallengeToken)
	return resp.Data.ChallengeToken
}

func TestTOTP_EnableChallengeVerifyAndRecovery(t *testing.T) {
	h, now := newTOTPHarness(t)
	h.seedUser(t, "otp@example.com", "password123")
	jwt := h.login(t, "otp@example.com", "password123")
	secret := enableTOTPAPIAt(t, h, jwt, *now)

	// Setup again while enabled is a conflict.
	w := h.do(t, http.MethodPost, "/api/v1/auth/2fa/setup", nil, jwt)
	require.Equal(t, http.StatusConflict, w.Code, w.Body.String())

	// Password login now stops at the challenge; the next TOTP step verifies it.
	*now = now.Add(30 * time.Second)
	challenge := loginChallenge(t, h, "otp@example.com", "password123")
	nextCode := apiTOTPCode(secret, *now)
	w = h.do(t, http.MethodPost, "/api/v1/auth/2fa/verify", map[string]string{
		"challenge_token": challenge, "code": nextCode,
	}, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var tokens struct {
		Data struct {
			AccessToken string `json:"access_token"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &tokens))
	require.NotEmpty(t, tokens.Data.AccessToken)

	// The same challenge and code cannot be replayed.
	w = h.do(t, http.MethodPost, "/api/v1/auth/2fa/verify", map[string]string{
		"challenge_token": challenge, "code": nextCode,
	}, "")
	require.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())

	// Recovery codes: mint with password + a fresh code, then use one to log in.
	*now = now.Add(30 * time.Second)
	w = h.do(t, http.MethodPost, "/api/v1/auth/2fa/recovery-codes", map[string]string{
		"password": "password123", "code": apiTOTPCode(secret, *now),
	}, jwt)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var recovery struct {
		Data struct {
			Codes []string `json:"codes"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &recovery))
	require.Len(t, recovery.Data.Codes, 10)

	challenge = loginChallenge(t, h, "otp@example.com", "password123")
	w = h.do(t, http.MethodPost, "/api/v1/auth/2fa/verify", map[string]string{
		"challenge_token": challenge, "code": recovery.Data.Codes[0],
	}, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	challenge = loginChallenge(t, h, "otp@example.com", "password123")
	w = h.do(t, http.MethodPost, "/api/v1/auth/2fa/verify", map[string]string{
		"challenge_token": challenge, "code": recovery.Data.Codes[0],
	}, "")
	require.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())

	// Disabling requires password + a current code; afterwards login is direct.
	w = h.do(t, http.MethodPost, "/api/v1/auth/2fa/disable", map[string]string{
		"password": "wrong-password", "code": recovery.Data.Codes[1],
	}, jwt)
	require.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())
	w = h.do(t, http.MethodPost, "/api/v1/auth/2fa/disable", map[string]string{
		"password": "password123", "code": recovery.Data.Codes[1],
	}, jwt)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.NotEmpty(t, h.login(t, "otp@example.com", "password123"))
}

func TestTOTP_AdminReset(t *testing.T) {
	h, orgID, _, admin, _, ownerToken, adminToken, memberToken := m4Org(t)
	enableTOTPAPI(t, h, adminToken)
	require.NotEmpty(t, loginChallenge(t, h, "m4-admin@example.com", "password123"))

	// A plain member cannot reset another member's 2FA.
	w := h.do(t, http.MethodPost,
		"/api/v1/orgs/"+itoa(orgID)+"/members/"+itoa(int64(admin.ID))+"/2fa/reset", nil, memberToken)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

	// The owner can; the admin's next login no longer asks for a factor.
	w = h.do(t, http.MethodPost,
		"/api/v1/orgs/"+itoa(orgID)+"/members/"+itoa(int64(admin.ID))+"/2fa/reset", nil, ownerToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.NotEmpty(t, h.login(t, "m4-admin@example.com", "password123"))
	require.EqualValues(t, 1, countAudit(t, h, "action = ?", "user.2fa.reset"))

	// Reset is idempotent and audited again only for the action itself.
	w = h.do(t, http.MethodPost,
		"/api/v1/orgs/"+itoa(orgID)+"/members/"+itoa(int64(admin.ID))+"/2fa/reset", nil, ownerToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	// An unknown member is a 404.
	w = h.do(t, http.MethodPost, "/api/v1/orgs/"+itoa(orgID)+"/members/999999/2fa/reset", nil, ownerToken)
	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())
}
