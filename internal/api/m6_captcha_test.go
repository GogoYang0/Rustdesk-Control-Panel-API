package api_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	altchalib "github.com/altcha-org/altcha-lib-go"

	"github.com/GogoYang0/rustdesk-control-panel-api/gen"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/api"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/auth"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/captcha"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
)

// altchaService builds a real embedded provider for HTTP-level tests.
func altchaService(t *testing.T) *captcha.Service {
	t.Helper()
	svc, err := captcha.Build(captcha.Options{
		Provider:  "altcha",
		AltchaKey: "0123456789abcdef0123456789abcdef",
		MaxNumber: 10000,
	})
	require.NoError(t, err)
	return svc
}

// solveAltchaHTTP solves the challenge returned by GET /auth/captcha. The
// params went through JSON, so maxNumber arrives as float64.
func solveAltchaHTTP(t *testing.T, params map[string]any) map[string]string {
	t.Helper()
	algorithm, _ := params["algorithm"].(string)
	challenge, _ := params["challenge"].(string)
	salt, _ := params["salt"].(string)
	signature, _ := params["signature"].(string)
	maxNumber, _ := params["maxNumber"].(float64)

	solution, err := altchalib.SolveChallenge(challenge, salt, altchalib.Algorithm(algorithm), int(maxNumber), 0, nil)
	require.NoError(t, err)

	raw, err := json.Marshal(altchalib.Payload{
		Algorithm: algorithm,
		Challenge: challenge,
		Number:    int64(solution.Number),
		Salt:      salt,
		Signature: signature,
	})
	require.NoError(t, err)
	return map[string]string{"payload": base64.StdEncoding.EncodeToString(raw)}
}

func TestCaptcha_ChallengeDisabled(t *testing.T) {
	h := newHarness(t)
	w := h.do(t, http.MethodGet, "/api/v1/auth/captcha", nil, "")
	require.Equal(t, http.StatusOK, w.Code)

	var out gen.CaptchaChallengeResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &out))
	require.NotNil(t, out.Data)
	require.False(t, out.Data.Enabled)
	require.Nil(t, out.Data.Provider)
	require.Nil(t, out.Data.Challenge)
}

func TestCaptcha_ChallengeRequiresNoAuth(t *testing.T) {
	h := newHarnessWith(t, func(d *api.Deps) { d.Captcha = altchaService(t) })
	w := h.do(t, http.MethodGet, "/api/v1/auth/captcha", nil, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
}

func TestCaptcha_ChallengeShape(t *testing.T) {
	h := newHarnessWith(t, func(d *api.Deps) { d.Captcha = altchaService(t) })
	w := h.do(t, http.MethodGet, "/api/v1/auth/captcha", nil, "")
	require.Equal(t, http.StatusOK, w.Code)

	var out gen.CaptchaChallengeResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &out))
	require.NotNil(t, out.Data)
	require.True(t, out.Data.Enabled)
	require.NotNil(t, out.Data.Provider)
	require.Equal(t, "altcha", *out.Data.Provider)
	require.NotNil(t, out.Data.Challenge)
	for _, key := range []string{"algorithm", "challenge", "maxNumber", "salt", "signature"} {
		require.NotEmpty(t, out.Data.Challenge.Params[key], key)
	}
}

func TestCaptcha_ChallengeRateLimited(t *testing.T) {
	h := newHarnessWith(t, func(d *api.Deps) { d.Captcha = altchaService(t) })
	for i := 0; i < 5; i++ {
		w := h.do(t, http.MethodGet, "/api/v1/auth/captcha", nil, "")
		require.Equal(t, http.StatusOK, w.Code, "request %d: %s", i, w.Body.String())
	}
	w := h.do(t, http.MethodGet, "/api/v1/auth/captcha", nil, "")
	require.Equal(t, http.StatusTooManyRequests, w.Code)

	var out gen.ErrorResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &out))
	require.Equal(t, gen.ErrorCodeRateLimited, out.Code)
}

// freshChallenge fetches and solves one challenge from the HTTP endpoint.
func freshChallenge(t *testing.T, h *harness) map[string]string {
	t.Helper()
	w := h.do(t, http.MethodGet, "/api/v1/auth/captcha", nil, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var out gen.CaptchaChallengeResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &out))
	require.NotNil(t, out.Data)
	require.NotNil(t, out.Data.Challenge)
	return solveAltchaHTTP(t, out.Data.Challenge.Params)
}

func TestCaptcha_DisabledEntrancesUnchanged(t *testing.T) {
	// With the captcha off, the login body has no captcha field and must work
	// exactly as before v0.10.0.
	h := newHarness(t)
	h.seedUser(t, "plain@example.com", "password123")
	w := h.do(t, http.MethodPost, "/api/v1/auth/login", map[string]string{
		"email": "plain@example.com", "password": "password123",
	}, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
}

func TestCaptcha_LoginRequiresProof(t *testing.T) {
	h := newHarnessWith(t, func(d *api.Deps) { d.Captcha = altchaService(t) })
	w := h.do(t, http.MethodPost, "/api/v1/auth/login", map[string]string{
		"email": "nobody@example.com", "password": "password123",
	}, "")
	require.Equal(t, http.StatusBadRequest, w.Code)

	var out gen.ErrorResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &out))
	require.Equal(t, gen.ErrorCodeCaptchaRequired, out.Code)
}

func TestCaptcha_LoginInvalidHidesAccount(t *testing.T) {
	h := newHarnessWith(t, func(d *api.Deps) { d.Captcha = altchaService(t) })
	h.seedUser(t, "known@example.com", "password123")

	body := map[string]any{
		"password": "password123",
		"captcha":  map[string]any{"response": map[string]string{"payload": "not-base64!!"}},
	}
	first := h.do(t, http.MethodPost, "/api/v1/auth/login", mergeBody(body, "known@example.com"), "")
	second := h.do(t, http.MethodPost, "/api/v1/auth/login", mergeBody(body, "unknown@example.com"), "")

	require.Equal(t, http.StatusBadRequest, first.Code)
	require.Equal(t, first.Code, second.Code)
	require.Equal(t, first.Body.String(), second.Body.String(),
		"a failed captcha must not reveal whether the account exists")
}

func TestCaptcha_LoginValidProofProceeds(t *testing.T) {
	h := newHarnessWith(t, func(d *api.Deps) { d.Captcha = altchaService(t) })
	h.seedUser(t, "member@example.com", "password123")

	// Four bad proofs stay below the 5/min IP bucket, and a proof failure must
	// not be booked as a credential failure: the correct password still logs in.
	for i := 0; i < 4; i++ {
		w := h.do(t, http.MethodPost, "/api/v1/auth/login", map[string]any{
			"email":    "member@example.com",
			"password": "password123",
			"captcha":  map[string]any{"response": map[string]string{"payload": "not-base64!!"}},
		}, "")
		require.Equal(t, http.StatusBadRequest, w.Code)
		var out gen.ErrorResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &out))
		require.Equal(t, gen.ErrorCodeCaptchaInvalid, out.Code)
	}

	proof := freshChallenge(t, h)
	ok := h.do(t, http.MethodPost, "/api/v1/auth/login", map[string]any{
		"email":    "member@example.com",
		"password": "password123",
		"captcha":  map[string]any{"response": proof},
	}, "")
	require.Equal(t, http.StatusOK, ok.Code, ok.Body.String())
}

func TestCaptcha_WrongPasswordAfterValidProof(t *testing.T) {
	h := newHarnessWith(t, func(d *api.Deps) { d.Captcha = altchaService(t) })
	h.seedUser(t, "member@example.com", "password123")

	proof := freshChallenge(t, h)
	w := h.do(t, http.MethodPost, "/api/v1/auth/login", map[string]any{
		"email":    "member@example.com",
		"password": "wrong-password",
		"captcha":  map[string]any{"response": proof},
	}, "")
	require.Equal(t, http.StatusUnauthorized, w.Code)

	var out gen.ErrorResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &out))
	require.Equal(t, gen.ErrorCodeUnauthorized, out.Code)
}

func TestCaptcha_CompatLoginUnaffected(t *testing.T) {
	h := newHarnessWith(t, func(d *api.Deps) { d.Captcha = altchaService(t) })
	h.seedUser(t, "client@example.com", "password123")

	// The RustDesk client cannot solve an interactive captcha: its login path
	// must stay outside the gate. Without a membership this answers 403, never
	// a captcha error.
	w := h.do(t, http.MethodPost, "/api/login", map[string]string{
		"username": "client@example.com", "password": "password123", "id": "123456789", "uuid": "uuid-1",
	}, "")
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	require.NotContains(t, w.Body.String(), "captcha")
}

// mergeBody copies the shared login fields and sets the email.
func mergeBody(base map[string]any, email string) map[string]any {
	out := map[string]any{}
	for k, v := range base {
		out[k] = v
	}
	out["email"] = email
	return out
}

// loginWithProof performs the password step with a solved captcha.
func loginWithProof(t *testing.T, h *harness, email, password string) *httptest.ResponseRecorder {
	t.Helper()
	proof := freshChallenge(t, h)
	return h.do(t, http.MethodPost, "/api/v1/auth/login", map[string]any{
		"email":    email,
		"password": password,
		"captcha":  map[string]any{"response": proof},
	}, "")
}

// seedTOTP enables two-factor for an existing user without the HTTP flow.
func seedTOTP(t *testing.T, h *harness, userID uint, at time.Time) string {
	t.Helper()
	svc := auth.NewTOTPService(h.db.DB, "test-secret", func() time.Time { return at })
	secret, _, err := svc.Setup(userID)
	require.NoError(t, err)
	require.NoError(t, svc.Enable(userID, apiTOTPCode(secret, at)))
	return secret
}

func TestCaptcha_TwoFactorRequiresProof(t *testing.T) {
	start := time.Now().UTC().Truncate(30 * time.Second)
	h := newHarnessWith(t, func(d *api.Deps) {
		d.Captcha = altchaService(t)
		d.TOTP = auth.NewTOTPService(d.DB, "test-secret", func() time.Time { return start })
	})
	u := h.seedUser(t, "otp@example.com", "password123")
	secret := seedTOTP(t, h, u.ID, start)

	w := loginWithProof(t, h, "otp@example.com", "password123")
	require.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())
	var challenge struct {
		Code string `json:"code"`
		Data struct {
			ChallengeToken string `json:"challenge_token"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &challenge))
	require.Equal(t, "two_factor_required", challenge.Code)

	w = h.do(t, http.MethodPost, "/api/v1/auth/2fa/verify", map[string]string{
		"challenge_token": challenge.Data.ChallengeToken,
		"code":            apiTOTPCode(secret, start),
	}, "")
	require.Equal(t, http.StatusBadRequest, w.Code)
	var out gen.ErrorResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &out))
	require.Equal(t, gen.ErrorCodeCaptchaRequired, out.Code)
}

func TestCaptcha_TwoFactorInvalidProofKeepsCode(t *testing.T) {
	start := time.Now().UTC().Truncate(30 * time.Second)
	h := newHarnessWith(t, func(d *api.Deps) {
		d.Captcha = altchaService(t)
		d.TOTP = auth.NewTOTPService(d.DB, "test-secret", func() time.Time { return start })
	})
	u := h.seedUser(t, "otp@example.com", "password123")
	secret := seedTOTP(t, h, u.ID, start)
	// Enabling consumed the current step; move to the next one so the login
	// code is not a replay.
	start = start.Add(30 * time.Second)

	w := loginWithProof(t, h, "otp@example.com", "password123")
	require.Equal(t, http.StatusUnauthorized, w.Code)
	var challenge struct {
		Data struct {
			ChallengeToken string `json:"challenge_token"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &challenge))

	// A wrong proof must not consume the TOTP code or book a factor failure:
	// the very same code still works once a valid proof is supplied.
	w = h.do(t, http.MethodPost, "/api/v1/auth/2fa/verify", map[string]any{
		"challenge_token": challenge.Data.ChallengeToken,
		"code":            apiTOTPCode(secret, start),
		"captcha":         map[string]any{"response": map[string]string{"payload": "not-base64!!"}},
	}, "")
	require.Equal(t, http.StatusBadRequest, w.Code)
	var bad gen.ErrorResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &bad))
	require.Equal(t, gen.ErrorCodeCaptchaInvalid, bad.Code)

	w = h.do(t, http.MethodPost, "/api/v1/auth/2fa/verify", map[string]any{
		"challenge_token": challenge.Data.ChallengeToken,
		"code":            apiTOTPCode(secret, start),
		"captcha":         map[string]any{"response": freshChallenge(t, h)},
	}, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
}

// seedInvitationOrg creates an organization with builtin roles and a matching
// invitation for the given email.
func seedInvitationOrg(t *testing.T, h *harness, email string) (int64, string) {
	t.Helper()
	org := model.Organization{Name: "invite-org"}
	require.NoError(t, h.db.DB.Create(&org).Error)
	_ = h.roleID(t, org.ID, "member")
	token := h.newInvitationForTest(t, int64(org.ID), email, "member")
	return int64(org.ID), token
}

func TestCaptcha_InvitationAcceptRequiresProof(t *testing.T) {
	h := newHarnessWith(t, func(d *api.Deps) { d.Captcha = altchaService(t) })
	h.seedUser(t, "invitee@example.com", "password123")
	_, token := seedInvitationOrg(t, h, "invitee@example.com")

	w := h.do(t, http.MethodPost, "/api/v1/invitations/accept", map[string]string{
		"token": token, "password": "password123",
	}, "")
	require.Equal(t, http.StatusBadRequest, w.Code)
	var out gen.ErrorResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &out))
	require.Equal(t, gen.ErrorCodeCaptchaRequired, out.Code)

	// The invitation is untouched: the same token still works with a proof.
	w = h.do(t, http.MethodPost, "/api/v1/invitations/accept", map[string]any{
		"token": token, "password": "password123",
		"captcha": map[string]any{"response": freshChallenge(t, h)},
	}, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
}
