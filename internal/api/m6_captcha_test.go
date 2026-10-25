package api_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	altchalib "github.com/altcha-org/altcha-lib-go"

	"github.com/GogoYang0/rustdesk-control-panel-api/gen"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/api"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/captcha"
)

// altchaService builds a real embedded provider for HTTP-level tests.
func altchaService(t *testing.T) *captcha.Service {
	t.Helper()
	svc, err := captcha.Build(captcha.Options{
		Provider:  "altcha",
		AltchaKey: "test-captcha-key",
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
