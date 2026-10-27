package api_test

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/api"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/ldapauth"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
)

// ldapHarness wires a fake directory into the API. The same harness shape as
// the OIDC tests: the directory is the only difference.
func ldapHarness(t *testing.T, tune func(*api.Deps)) (*harness, *ldapauth.Fake) {
	t.Helper()

	fake := ldapauth.NewFake(map[string]ldapauth.FakeUser{
		"alice":  {Mail: "ldap-alice@example.com", Password: "alicepassword"},
		"nomail": {Mail: "", Password: "nomailpassword"},
	})
	h := newHarnessWith(t, func(d *api.Deps) {
		d.LDAP = fake
		d.LDAPProviderName = "Directory"
		d.LDAPIssuer = "ldap.example.com"
		if tune != nil {
			tune(d)
		}
	})
	return h, fake
}

func ldapLogin(t *testing.T, h *harness, username, password string) *int {
	t.Helper()

	w := h.do(t, http.MethodPost, "/api/v1/auth/ldap/login", map[string]string{
		"username": username, "password": password,
	}, "")
	return &w.Code
}

func TestLdapLogin_HappyPathBindsIdentity(t *testing.T) {
	h, _ := ldapHarness(t, nil)
	u := h.seedUser(t, "ldap-alice@example.com", "password123")

	wFirst := h.do(t, http.MethodPost, "/api/v1/auth/ldap/login", map[string]string{
		"username": "alice", "password": "alicepassword",
	}, "")
	require.Equal(t, http.StatusOK, wFirst.Code, wFirst.Body.String())

	w := h.do(t, http.MethodPost, "/api/v1/auth/ldap/login", map[string]string{
		"username": "alice", "password": "alicepassword",
	}, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var tokens struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	decodeData(t, w, &tokens)
	require.NotEmpty(t, tokens.AccessToken)
	require.NotEmpty(t, tokens.RefreshToken)

	var row model.UserIdentity
	require.NoError(t, h.db.DB.Where("provider = ? AND subject = ?", model.IdentityProviderLDAP, "alice").First(&row).Error)
	require.Equal(t, u.ID, row.UserID)
	require.Equal(t, "ldap.example.com", row.Issuer, "issuer is the lowercased host")
}

func TestLdapLogin_WrongPasswordIs401AndFeedsLockout(t *testing.T) {
	h, _ := ldapHarness(t, nil)
	h.seedUser(t, "ldap-wrong@example.com", "password123")

	for i := 0; i < 5; i++ {
		code := ldapLogin(t, h, "alice", "wrong")
		require.Equal(t, http.StatusUnauthorized, *code)
	}
	// The 6th attempt hits the account+IP failure window, same as /auth/login.
	code := ldapLogin(t, h, "alice", "alicepassword")
	require.Equal(t, http.StatusTooManyRequests, *code)
}

func TestLdapLogin_UnknownDirectoryUserIs401(t *testing.T) {
	h, _ := ldapHarness(t, nil)
	h.seedUser(t, "ldap-anyone@example.com", "password123")

	code := ldapLogin(t, h, "nobody", "whatever")
	require.Equal(t, http.StatusUnauthorized, *code)
}

// TestLdapLogin_EmptyCredentialsNeverTouchTheDirectory pins L1: the classic
// LDAP anonymous-bind bypass is closed before the rate limiter and before any
// connection exists.
func TestLdapLogin_EmptyCredentialsNeverTouchTheDirectory(t *testing.T) {
	h, fake := ldapHarness(t, nil)

	code := ldapLogin(t, h, "alice", "")
	require.Equal(t, http.StatusBadRequest, *code)
	code = ldapLogin(t, h, "", "secret")
	require.Equal(t, http.StatusBadRequest, *code)

	// The refusal must also not spend the per-IP bucket: seven refusals (more
	// than the 5-token burst) followed by a legitimate login that still
	// succeeds is the proof. If the gate ever moved below AllowIP, the sixth
	// refusal would 429 and this test would fail.
	for i := 0; i < 5; i++ {
		code = ldapLogin(t, h, "alice", "")
		require.Equal(t, http.StatusBadRequest, *code)
	}
	require.Zero(t, fake.DialCount(), "empty credentials must not reach the directory")

	h.seedUser(t, "ldap-alice@example.com", "password123")
	code = ldapLogin(t, h, "alice", "alicepassword")
	require.Equal(t, http.StatusOK, *code,
		"empty-credential refusals must not consume the rate-limit budget")
}

func TestLdapLogin_AmbiguousSearchIs401(t *testing.T) {
	h, fake := ldapHarness(t, nil)
	h.seedUser(t, "ldap-ambig@example.com", "password123")
	fake.Ambiguous = true

	code := ldapLogin(t, h, "alice", "alicepassword")
	require.Equal(t, http.StatusUnauthorized, *code)
}

func TestLdapLogin_MissingMailIs403(t *testing.T) {
	h, _ := ldapHarness(t, nil)

	code := ldapLogin(t, h, "nomail", "nomailpassword")
	require.Equal(t, http.StatusForbidden, *code)
}

func TestLdapLogin_NoPanelAccountIs403(t *testing.T) {
	h, _ := ldapHarness(t, nil)
	// Directory knows alice; the panel has no such mailbox (no JIT).

	code := ldapLogin(t, h, "alice", "alicepassword")
	require.Equal(t, http.StatusForbidden, *code)
}

func TestLdapLogin_DirectoryUnavailableIs503(t *testing.T) {
	h, fake := ldapHarness(t, nil)
	h.seedUser(t, "ldap-down@example.com", "password123")
	fake.Unavailable = true

	code := ldapLogin(t, h, "alice", "alicepassword")
	require.Equal(t, http.StatusServiceUnavailable, *code)
}

func TestLdapLogin_DisabledReturns503(t *testing.T) {
	h := newHarness(t)
	w := h.do(t, http.MethodPost, "/api/v1/auth/ldap/login", map[string]string{
		"username": "alice", "password": "secret",
	}, "")
	require.Equal(t, http.StatusServiceUnavailable, w.Code, w.Body.String())
}

func TestLdapLogin_RequiresLocalTOTPWhenEnabled(t *testing.T) {
	h, fake := ldapHarness(t, func(d *api.Deps) {
		d.RequireLocalSecondFactor = true
		d.AuthSecret = "oidc-test-secret-32-bytes-long!!"
	})
	u := h.seedUser(t, "ldap-gate@example.com", "password123")
	fake.Users["gate"] = ldapauth.FakeUser{Mail: u.Email, Password: "gatepassword"}

	jwt := h.login(t, u.Email, "password123")
	secret := enableTOTPAPI(t, h, jwt)

	w := h.do(t, http.MethodPost, "/api/v1/auth/ldap/login", map[string]string{
		"username": "gate", "password": "gatepassword",
	}, "")
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
	require.Equal(t, []string{"totp"}, challenge.Data.Methods)

	verify := h.do(t, http.MethodPost, "/api/v1/auth/2fa/verify", map[string]string{
		"challenge_token": challenge.Data.ChallengeToken,
		"code":            apiTOTPCode(secret, time.Now().Add(30*time.Second)),
	}, "")
	require.Equal(t, http.StatusOK, verify.Code, verify.Body.String())
}

func TestLdapLogin_NoTOTPStillSucceedsWhenGateEnabled(t *testing.T) {
	h, fake := ldapHarness(t, func(d *api.Deps) {
		d.RequireLocalSecondFactor = true
	})
	u := h.seedUser(t, "ldap-gate2@example.com", "password123")
	fake.Users["gate2"] = ldapauth.FakeUser{Mail: u.Email, Password: "gatepassword"}

	w := h.do(t, http.MethodPost, "/api/v1/auth/ldap/login", map[string]string{
		"username": "gate2", "password": "gatepassword",
	}, "")
	require.Equal(t, http.StatusOK, w.Code,
		"an account that never enabled TOTP must not be locked out by the gate: %s", w.Body.String())
}

func TestAuthProviders_LDAPEnabled(t *testing.T) {
	h, _ := ldapHarness(t, nil)

	w := h.do(t, http.MethodGet, "/api/v1/auth/providers", nil, "")
	require.Equal(t, http.StatusOK, w.Code)
	var view struct {
		Ldap struct {
			Enabled bool   `json:"enabled"`
			Name    string `json:"name"`
		} `json:"ldap"`
	}
	decodeData(t, w, &view)
	require.True(t, view.Ldap.Enabled)
	require.Equal(t, "Directory", view.Ldap.Name)
}

// TestLdapLogin_CaseVariantSubjectDoesNotConflict pins the subject
// normalization: directories match uid/sAMAccountName case-insensitively, so
// "Alice" and "alice" are the same directory identity and must bind to the
// same subject — a case variant must never look like a second human claiming
// an already-linked account (409).
func TestLdapLogin_CaseVariantSubjectDoesNotConflict(t *testing.T) {
	h, _ := ldapHarness(t, nil)
	h.seedUser(t, "ldap-alice@example.com", "password123")

	w := h.do(t, http.MethodPost, "/api/v1/auth/ldap/login", map[string]string{
		"username": "Alice", "password": "alicepassword",
	}, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	w = h.do(t, http.MethodPost, "/api/v1/auth/ldap/login", map[string]string{
		"username": "ALICE", "password": "alicepassword",
	}, "")
	require.Equal(t, http.StatusOK, w.Code,
		"a case variant of the same directory user must not be a conflict: %s", w.Body.String())

	var row model.UserIdentity
	require.NoError(t, h.db.DB.Where("provider = ?", model.IdentityProviderLDAP).First(&row).Error)
	require.Equal(t, "alice", row.Subject, "the subject is the lowercased username")
}
