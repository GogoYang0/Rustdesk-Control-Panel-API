package api_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/passkey/testauth"
)

func TestPasskeyStepup_ReturnsSingleUseToken(t *testing.T) {
	h, svc, u, jwt := passkeyLoginHarness(t)
	authn := testauth.New(t, passkeyRPID, passkeyOrigin)
	seedPasskey(t, svc, u, authn)

	w := h.do(t, http.MethodPost, "/api/v1/auth/passkey/stepup/begin", nil, jwt)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var begin ceremonyView
	decodeData(t, w, &begin)

	w = h.do(t, http.MethodPost, "/api/v1/auth/passkey/stepup/finish", map[string]any{
		"ceremony_token": begin.CeremonyToken,
		"credential": mustDecode(t, authn.Assertion(t, begin.Options.PublicKey.Challenge, 1,
			passkeyHandle(u.ID))),
	}, jwt)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var view struct {
		StepupToken string `json:"stepup_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	decodeData(t, w, &view)
	require.NotEmpty(t, view.StepupToken)
	require.EqualValues(t, 120, view.ExpiresIn)
}

func TestPasskeyStepup_NoCredentialsConflicts(t *testing.T) {
	h, _, _, jwt := passkeyLoginHarness(t)

	w := h.do(t, http.MethodPost, "/api/v1/auth/passkey/stepup/begin", nil, jwt)
	require.Equal(t, http.StatusConflict, w.Code, w.Body.String())
}

func TestPasskeyStepup_RejectsAssertionFromUnknownKey(t *testing.T) {
	h, svc, u, jwt := passkeyLoginHarness(t)
	authn := testauth.New(t, passkeyRPID, passkeyOrigin)
	seedPasskey(t, svc, u, authn)
	evil := testauth.New(t, passkeyRPID, "https://evil.example.org")

	w := h.do(t, http.MethodPost, "/api/v1/auth/passkey/stepup/begin", nil, jwt)
	require.Equal(t, http.StatusOK, w.Code)
	var begin ceremonyView
	decodeData(t, w, &begin)

	w = h.do(t, http.MethodPost, "/api/v1/auth/passkey/stepup/finish", map[string]any{
		"ceremony_token": begin.CeremonyToken,
		"credential": mustDecode(t, evil.Assertion(t, begin.Options.PublicKey.Challenge, 1,
			passkeyHandle(u.ID))),
	}, jwt)
	require.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())
}
