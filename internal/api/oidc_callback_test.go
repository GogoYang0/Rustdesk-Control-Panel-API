package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/api"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/auth/oidctest"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/oidc"
)

// oidcHarness wires the OIDC service (pointed at a fake IdP) into the API.
func oidcHarness(t *testing.T, requireLocalSecondFactor bool) (*harness, *oidctest.Server) {
	t.Helper()

	fake := oidctest.New(t, "panel-client")
	h := newHarnessWith(t, func(d *api.Deps) {
		d.OIDC = oidc.NewService(d.DB, oidc.Config{
			ProviderName: "Test IdP",
			Issuer:       fake.Issuer,
			ClientID:     "panel-client",
			ClientSecret: "s3cret-value",
			Scopes:       []string{"openid", "profile", "email"},
			ClockSkew:    time.Minute,
			StateTTL:     10 * time.Minute,
			CallbackURL:  testCallbackURL,
			Now:          time.Now,
		}, zap.NewNop())
		d.RequireLocalSecondFactor = requireLocalSecondFactor
		d.WebBaseURL = "https://panel.example.com"
		// TOTP secrets are encrypted with a key derived from this value.
		d.AuthSecret = "oidc-test-secret-32-bytes-long!!"
	})
	return h, fake
}

func oidcBegin(t *testing.T, h *harness) (state, nonce string) {
	t.Helper()

	w := h.do(t, http.MethodPost, "/api/v1/auth/oidc/start", map[string]string{"redirect_path": "/devices"}, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var start struct {
		AuthorizationURL string `json:"authorization_url"`
		State            string `json:"state"`
	}
	decodeData(t, w, &start)
	parsed, err := url.Parse(start.AuthorizationURL)
	require.NoError(t, err)
	return start.State, parsed.Query().Get("nonce")
}

func oidcCallback(t *testing.T, h *harness, query string) *httptest.ResponseRecorder {
	t.Helper()
	return h.do(t, http.MethodGet, "/api/v1/auth/oidc/callback?"+query, nil, "")
}

// locationQuery asserts a 302 and returns the parsed query of its Location.
// It also pins the "no token in the URL" rule for every caller.
func locationQuery(t *testing.T, w *httptest.ResponseRecorder) url.Values {
	t.Helper()

	require.Equal(t, http.StatusFound, w.Code, w.Body.String())
	loc := w.Header().Get("Location")
	require.NotEmpty(t, loc)
	require.NotContains(t, loc, "access_token")
	require.NotContains(t, loc, "refresh_token")
	require.NotContains(t, loc, "id_token")

	parsed, err := url.Parse(loc)
	require.NoError(t, err)
	return parsed.Query()
}

func TestOIDCCallback_IssuesTicketAndExchangeReturnsTokens(t *testing.T) {
	h, fake := oidcHarness(t, false)
	u := h.seedUser(t, "oidc-flow@example.com", "password123")

	state, nonce := oidcBegin(t, h)
	fake.Nonce = nonce
	fake.Sub = "subject-flow"
	fake.Email = u.Email
	fake.EmailVerified = true

	w0 := oidcCallback(t, h, "state="+state+"&code=code-1")
	// The redirect must land on the configured origin and the requested path;
	// anything else would be an open redirect the SPA cannot detect.
	require.Equal(t, http.StatusFound, w0.Code)
	require.True(t, strings.HasPrefix(w0.Header().Get("Location"), "https://panel.example.com/devices?"),
		"Location = %q", w0.Header().Get("Location"))

	q := locationQuery(t, w0)
	ticket := q.Get("ticket")
	require.NotEmpty(t, ticket)
	require.Empty(t, q.Get("error"))

	w := h.do(t, http.MethodPost, "/api/v1/auth/oidc/exchange", map[string]string{"ticket": ticket}, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var tokens struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	decodeData(t, w, &tokens)
	require.NotEmpty(t, tokens.AccessToken)
	require.NotEmpty(t, tokens.RefreshToken)
}

func TestOIDCCallback_TicketIsSingleUse(t *testing.T) {
	h, fake := oidcHarness(t, false)
	u := h.seedUser(t, "oidc-once@example.com", "password123")

	state, nonce := oidcBegin(t, h)
	fake.Nonce = nonce
	fake.Sub = "subject-once"
	fake.Email = u.Email
	fake.EmailVerified = true

	ticket := locationQuery(t, oidcCallback(t, h, "state="+state+"&code=code-1")).Get("ticket")
	require.NotEmpty(t, ticket)

	first := h.do(t, http.MethodPost, "/api/v1/auth/oidc/exchange", map[string]string{"ticket": ticket}, "")
	require.Equal(t, http.StatusOK, first.Code, first.Body.String())

	second := h.do(t, http.MethodPost, "/api/v1/auth/oidc/exchange", map[string]string{"ticket": ticket}, "")
	require.Equal(t, http.StatusUnauthorized, second.Code, second.Body.String())
}

func TestOIDCCallback_StateReplayIsRefused(t *testing.T) {
	h, fake := oidcHarness(t, false)
	u := h.seedUser(t, "oidc-replay@example.com", "password123")

	state, nonce := oidcBegin(t, h)
	fake.Nonce = nonce
	fake.Sub = "subject-replay"
	fake.Email = u.Email
	fake.EmailVerified = true

	locationQuery(t, oidcCallback(t, h, "state="+state+"&code=code-1"))
	q := locationQuery(t, oidcCallback(t, h, "state="+state+"&code=code-1"))
	require.Equal(t, "oidc_failed", q.Get("error"))
}

// TestOIDCCallback_RateLimited pins the guard on the callback: without it an
// unauthenticated caller can hammer the state lookup and drive outbound token
// exchanges against the IdP (the guard covers start and exchange already).
func TestOIDCCallback_RateLimited(t *testing.T) {
	h, _ := oidcHarness(t, false)

	sawLimit := false
	for i := 0; i < 15; i++ {
		w := h.do(t, http.MethodGet, "/api/v1/auth/oidc/callback?state=missing-"+string(rune('a'+i))+"&code=x", nil, "")
		if w.Code == http.StatusTooManyRequests {
			sawLimit = true
			break
		}
		require.Equal(t, http.StatusFound, w.Code, w.Body.String())
	}
	require.True(t, sawLimit, "callback never hit the per-IP limit")
}

func TestOIDCCallback_IdPErrorRedirectsToFixedCode(t *testing.T) {
	h, _ := oidcHarness(t, false)

	// The flow must exist so the handler can honour its redirect_path.
	state, _ := oidcBegin(t, h)
	q := locationQuery(t, oidcCallback(t, h, "state="+state+"&error=access_denied&error_description=user+said+no"))
	require.Equal(t, "oidc_failed", q.Get("error"))
	require.Empty(t, q.Get("ticket"))
}

func TestOIDCCallback_FailureCodes(t *testing.T) {
	cases := []struct {
		name     string
		verified any
		email    string
		seed     bool
		want     string
	}{
		{name: "unverified idp mailbox", verified: false, email: "oidc-shape-bad@example.com", seed: true, want: "email_unverified"},
		{name: "missing email_verified", verified: nil, email: "oidc-shape-missing@example.com", seed: true, want: "email_unverified"},
		{name: "no panel account", verified: true, email: "oidc-ghost@example.com", seed: false, want: "no_account"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, fake := oidcHarness(t, false)
			if tc.seed {
				h.seedUser(t, tc.email, "password123")
			}

			state, nonce := oidcBegin(t, h)
			fake.Nonce = nonce
			fake.Sub = "subject-" + tc.name
			fake.Email = tc.email
			fake.EmailVerified = tc.verified

			q := locationQuery(t, oidcCallback(t, h, "state="+state+"&code=code-1"))
			require.Equal(t, tc.want, q.Get("error"))
		})
	}
}

func TestOIDCExchange_InvalidTicket(t *testing.T) {
	h, _ := oidcHarness(t, false)

	w := h.do(t, http.MethodPost, "/api/v1/auth/oidc/exchange", map[string]string{"ticket": "not-a-ticket"}, "")
	require.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())
}

func TestOIDCExchange_DisabledReturns503(t *testing.T) {
	h := newHarness(t)
	w := h.do(t, http.MethodPost, "/api/v1/auth/oidc/exchange", map[string]string{"ticket": "x"}, "")
	require.Equal(t, http.StatusServiceUnavailable, w.Code, w.Body.String())
}

func TestOIDCExchange_RequiresLocalTOTPWhenEnabled(t *testing.T) {
	h, fake := oidcHarness(t, true)
	u := h.seedUser(t, "oidc-gate@example.com", "password123")

	// The account enables TOTP through the normal flow.
	jwt := h.login(t, u.Email, "password123")
	secret := enableTOTPAPI(t, h, jwt)

	state, nonce := oidcBegin(t, h)
	fake.Nonce = nonce
	fake.Sub = "subject-gate"
	fake.Email = u.Email
	fake.EmailVerified = true
	ticket := locationQuery(t, oidcCallback(t, h, "state="+state+"&code=code-1")).Get("ticket")

	w := h.do(t, http.MethodPost, "/api/v1/auth/oidc/exchange", map[string]string{"ticket": ticket}, "")
	require.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())

	var challenge struct {
		Code string `json:"code"`
		Data struct {
			ChallengeToken string   `json:"challenge_token"`
			Methods        []string `json:"methods"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &challenge))
	require.Equal(t, "two_factor_required", challenge.Code)
	require.NotEmpty(t, challenge.Data.ChallengeToken)
	require.Equal(t, []string{"totp"}, challenge.Data.Methods)

	// The second step still completes: the gate defers, it does not block.
	verify := h.do(t, http.MethodPost, "/api/v1/auth/2fa/verify", map[string]string{
		"challenge_token": challenge.Data.ChallengeToken,
		"code":            apiTOTPCode(secret, time.Now().Add(30*time.Second)),
	}, "")
	require.Equal(t, http.StatusOK, verify.Code, verify.Body.String())
}

func TestOIDCExchange_NoTOTPStillSucceedsWhenGateEnabled(t *testing.T) {
	h, fake := oidcHarness(t, true)
	u := h.seedUser(t, "oidc-gate-nototp@example.com", "password123")

	state, nonce := oidcBegin(t, h)
	fake.Nonce = nonce
	fake.Sub = "subject-gate-nototp"
	fake.Email = u.Email
	fake.EmailVerified = true
	ticket := locationQuery(t, oidcCallback(t, h, "state="+state+"&code=code-1")).Get("ticket")

	w := h.do(t, http.MethodPost, "/api/v1/auth/oidc/exchange", map[string]string{"ticket": ticket}, "")
	require.Equal(t, http.StatusOK, w.Code,
		"an account that never enabled TOTP must not be locked out by the gate: %s", w.Body.String())
}
