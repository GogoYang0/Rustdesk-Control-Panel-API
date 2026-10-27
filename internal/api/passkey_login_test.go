package api_test

import (
	"context"
	"encoding/base64"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/api"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/passkey"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/passkey/testauth"
)

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func passkeyLoginHarness(t *testing.T) (*harness, *passkey.Service, model.User, string) {
	t.Helper()

	var svc *passkey.Service
	h := newHarnessWith(t, func(d *api.Deps) {
		d.AuthSecret = "test-secret"
		built, err := passkey.NewService(d.DB, passkey.Config{
			RPID:               passkeyRPID,
			RPDisplayName:      "Panel",
			Origin:             passkeyOrigin,
			CeremonyTTL:        5 * time.Minute,
			CredentialsPerUser: 10,
		}, d.Issuer, nil)
		require.NoError(t, err)
		svc = built
		d.Passkeys = built
	})
	u := h.seedUser(t, "passkey-login-http@example.com", "password123")
	jwt := h.login(t, "passkey-login-http@example.com", "password123")
	return h, svc, u, jwt
}

func seedPasskey(t *testing.T, svc *passkey.Service, u model.User, authn *testauth.Authenticator) {
	t.Helper()

	ctx := context.Background()
	token, options, err := svc.BeginRegistration(ctx, u)
	require.NoError(t, err)
	body := authn.Attestation(t, options.Response.Challenge.String(), passkeyHandle(u.ID))
	_, err = svc.FinishRegistration(ctx, u, token, body, "Phone")
	require.NoError(t, err)
}

func beginLoginHTTP(t *testing.T, h *harness, body any) ceremonyView {
	t.Helper()

	w := h.do(t, http.MethodPost, "/api/v1/auth/passkey/login/begin", body, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var view ceremonyView
	decodeData(t, w, &view)
	require.NotEmpty(t, view.CeremonyToken)
	require.NotEmpty(t, view.Options.PublicKey.Challenge)
	return view
}

func finishLoginHTTP(t *testing.T, h *harness, begin ceremonyView, assertion []byte) *struct {
	Code int
	Body string
} {
	t.Helper()

	w := h.do(t, http.MethodPost, "/api/v1/auth/passkey/login/finish", map[string]any{
		"ceremony_token": begin.CeremonyToken,
		"credential":     mustDecode(t, assertion),
	}, "")
	return &struct {
		Code int
		Body string
	}{Code: w.Code, Body: w.Body.String()}
}

func TestPasskeyLogin_Usernameless(t *testing.T) {
	h, svc, u, _ := passkeyLoginHarness(t)
	authn := testauth.New(t, passkeyRPID, passkeyOrigin)
	seedPasskey(t, svc, u, authn)

	begin := beginLoginHTTP(t, h, nil)
	w := h.do(t, http.MethodPost, "/api/v1/auth/passkey/login/finish", map[string]any{
		"ceremony_token": begin.CeremonyToken,
		"credential": mustDecode(t, authn.Assertion(t, begin.Options.PublicKey.Challenge, 1,
			passkeyHandle(u.ID))),
	}, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var tokens struct {
		AccessToken string `json:"access_token"`
	}
	decodeData(t, w, &tokens)
	require.NotEmpty(t, tokens.AccessToken)

	// The issued token is a normal management token.
	w = h.do(t, http.MethodGet, "/api/v1/orgs", nil, tokens.AccessToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
}

func TestPasskeyLogin_EmailHint(t *testing.T) {
	h, svc, u, _ := passkeyLoginHarness(t)
	authn := testauth.New(t, passkeyRPID, passkeyOrigin)
	seedPasskey(t, svc, u, authn)

	w0 := h.do(t, http.MethodPost, "/api/v1/auth/passkey/login/begin", map[string]any{"email": u.Email}, "")
	require.Equal(t, http.StatusOK, w0.Code, w0.Body.String())
	var narrowed struct {
		CeremonyToken string `json:"ceremony_token"`
		Options       struct {
			PublicKey struct {
				Challenge        string `json:"challenge"`
				AllowCredentials []struct {
					Id string `json:"id"`
				} `json:"allowCredentials"`
			} `json:"publicKey"`
		} `json:"options"`
	}
	decodeData(t, w0, &narrowed)
	// D16: the hint must actually narrow the list to this account's credential.
	require.Len(t, narrowed.Options.PublicKey.AllowCredentials, 1)
	require.Equal(t, b64url(authn.CredentialID()), narrowed.Options.PublicKey.AllowCredentials[0].Id)
	begin := ceremonyView{CeremonyToken: narrowed.CeremonyToken}
	begin.Options.PublicKey.Challenge = narrowed.Options.PublicKey.Challenge

	w := h.do(t, http.MethodPost, "/api/v1/auth/passkey/login/finish", map[string]any{
		"ceremony_token": begin.CeremonyToken,
		"credential": mustDecode(t, authn.Assertion(t, begin.Options.PublicKey.Challenge, 1,
			passkeyHandle(u.ID))),
	}, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
}

func TestPasskeyLogin_UnknownEmailStillBegins(t *testing.T) {
	h, _, _, _ := passkeyLoginHarness(t)

	w := h.do(t, http.MethodPost, "/api/v1/auth/passkey/login/begin", map[string]any{
		"email": "nobody@example.com",
	}, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var view struct {
		CeremonyToken string `json:"ceremony_token"`
		Options       struct {
			PublicKey struct {
				AllowCredentials []any `json:"allowCredentials"`
			} `json:"publicKey"`
		} `json:"options"`
	}
	decodeData(t, w, &view)
	require.NotEmpty(t, view.CeremonyToken)
	require.Empty(t, view.Options.PublicKey.AllowCredentials)
}

func TestPasskeyLogin_ChallengeTokenSecondFactor(t *testing.T) {
	h, svc, u, _ := passkeyLoginHarness(t)
	authn := testauth.New(t, passkeyRPID, passkeyOrigin)
	seedPasskey(t, svc, u, authn)

	challenge, err := h.issuer.IssueChallenge(u.ID, time.Minute)
	require.NoError(t, err)

	begin := beginLoginHTTP(t, h, map[string]any{"challenge_token": challenge})
	w := h.do(t, http.MethodPost, "/api/v1/auth/passkey/login/finish", map[string]any{
		"ceremony_token": begin.CeremonyToken,
		"credential": mustDecode(t, authn.Assertion(t, begin.Options.PublicKey.Challenge, 1,
			passkeyHandle(u.ID))),
	}, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
}

func TestPasskeyLogin_ChallengeTokenWithoutPasskeyConflicts(t *testing.T) {
	h, _, u, _ := passkeyLoginHarness(t)

	challenge, err := h.issuer.IssueChallenge(u.ID, time.Minute)
	require.NoError(t, err)

	w := h.do(t, http.MethodPost, "/api/v1/auth/passkey/login/begin", map[string]any{
		"challenge_token": challenge,
	}, "")
	require.Equal(t, http.StatusConflict, w.Code, w.Body.String())
}

func TestPasskeyLogin_ReplayRejected(t *testing.T) {
	h, svc, u, _ := passkeyLoginHarness(t)
	authn := testauth.New(t, passkeyRPID, passkeyOrigin)
	seedPasskey(t, svc, u, authn)

	begin := beginLoginHTTP(t, h, nil)
	assertion := authn.Assertion(t, begin.Options.PublicKey.Challenge, 1, passkeyHandle(u.ID))

	first := finishLoginHTTP(t, h, begin, assertion)
	require.Equal(t, http.StatusOK, first.Code, first.Body)

	second := finishLoginHTTP(t, h, begin, assertion)
	require.Equal(t, http.StatusUnauthorized, second.Code, second.Body)
}

func TestPasskeyLogin_DisabledReturns503(t *testing.T) {
	h := newHarness(t)

	w := h.do(t, http.MethodPost, "/api/v1/auth/passkey/login/begin", nil, "")
	require.Equal(t, http.StatusServiceUnavailable, w.Code, w.Body.String())
}

func TestPasskeyLogin_MutuallyExclusiveInputs(t *testing.T) {
	h, _, u, _ := passkeyLoginHarness(t)

	challenge, err := h.issuer.IssueChallenge(u.ID, time.Minute)
	require.NoError(t, err)

	w := h.do(t, http.MethodPost, "/api/v1/auth/passkey/login/begin", map[string]any{
		"challenge_token": challenge,
		"email":           u.Email,
	}, "")
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
}
