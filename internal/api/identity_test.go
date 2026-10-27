package api_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/api"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/oidc"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/passkey"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/passkey/testauth"
)

// identityHarness wires both credential services: unlink accepts either a
// step-up assertion or the account password.
func identityHarness(t *testing.T) (*harness, *passkey.Service) {
	t.Helper()

	var pk *passkey.Service
	h := newHarnessWith(t, func(d *api.Deps) {
		d.AuthSecret = "oidc-test-secret-32-bytes-long!!"
		d.WebBaseURL = "https://panel.example.com"
		d.OIDC = oidc.NewService(d.DB, oidc.Config{
			ProviderName: "Test IdP",
			Issuer:       "https://idp.example.com",
			ClientID:     "panel-client",
			ClientSecret: "s3cret-value",
			Scopes:       []string{"openid", "profile", "email"},
			ClockSkew:    time.Minute,
			StateTTL:     10 * time.Minute,
			CallbackURL:  testCallbackURL,
			Now:          time.Now,
		}, zap.NewNop())
		built, err := passkey.NewService(d.DB, passkey.Config{
			RPID:               passkeyRPID,
			RPDisplayName:      "Panel",
			Origin:             passkeyOrigin,
			CeremonyTTL:        5 * time.Minute,
			CredentialsPerUser: 10,
		}, d.Issuer, nil)
		require.NoError(t, err)
		pk = built
		d.Passkeys = built
	})
	return h, pk
}

func seedOwnIdentity(t *testing.T, h *harness, userID uint, issuer, subject string) model.UserIdentity {
	t.Helper()
	row := model.UserIdentity{
		UserID:   userID,
		Provider: model.IdentityProviderOIDC,
		Issuer:   issuer,
		Subject:  subject,
		Email:    "oidc-" + subject + "@example.com",
		LinkedAt: time.Now(),
	}
	require.NoError(t, h.db.DB.Create(&row).Error)
	return row
}

func TestGetIdentities_ListsOwnBindings(t *testing.T) {
	h, _ := identityHarness(t)
	u := h.seedUser(t, "oidc-identity@example.com", "password123")
	row := seedOwnIdentity(t, h, u.ID, "https://idp.example.com", "subject-identity")
	jwt := h.login(t, u.Email, "password123")

	w := h.do(t, http.MethodGet, "/api/v1/auth/identity", nil, jwt)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var view struct {
		ActiveProvider string `json:"active_provider"`
		Identities     []struct {
			ID          uint    `json:"id"`
			Provider    string  `json:"provider"`
			Issuer      string  `json:"issuer"`
			Subject     string  `json:"subject"`
			Email       string  `json:"email"`
			ConflictAt  *string `json:"conflict_at"`
			LastLoginAt *string `json:"last_login_at"`
		} `json:"identities"`
	}
	decodeData(t, w, &view)
	require.Equal(t, "oidc", view.ActiveProvider)
	require.Len(t, view.Identities, 1)
	got := view.Identities[0]
	require.Equal(t, row.ID, got.ID)
	require.Equal(t, "https://idp.example.com", got.Issuer)
	require.Equal(t, "subject-identity", got.Subject)
	require.Nil(t, got.ConflictAt)
}

func TestUnlinkIdentity_WithPassword(t *testing.T) {
	h, _ := identityHarness(t)
	u := h.seedUser(t, "oidc-unlink-pw@example.com", "password123")
	row := seedOwnIdentity(t, h, u.ID, "https://idp.example.com", "subject-unlink-pw")
	jwt := h.login(t, u.Email, "password123")

	w := h.do(t, http.MethodPost, "/api/v1/auth/identity/unlink", map[string]any{
		"identity_id": row.ID,
		"password":    "password123",
	}, jwt)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var count int64
	require.NoError(t, h.db.DB.Model(&model.UserIdentity{}).Where("id = ?", row.ID).Count(&count).Error)
	require.Zero(t, count)
}

func TestUnlinkIdentity_WithStepup(t *testing.T) {
	h, pk := identityHarness(t)
	u := h.seedUser(t, "oidc-unlink-stepup@example.com", "password123")
	row := seedOwnIdentity(t, h, u.ID, "https://idp.example.com", "subject-unlink-su")
	jwt := h.login(t, u.Email, "password123")

	authn := testauth.New(t, passkeyRPID, passkeyOrigin)
	seedPasskey(t, pk, u, authn)
	token := stepupToken(t, h, jwt, authn, u.ID, 1)

	w := h.do(t, http.MethodPost, "/api/v1/auth/identity/unlink", map[string]any{
		"identity_id":  row.ID,
		"stepup_token": token,
	}, jwt)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
}

func TestUnlinkIdentity_ProofRules(t *testing.T) {
	h, _ := identityHarness(t)
	u := h.seedUser(t, "oidc-unlink-rules@example.com", "password123")
	row := seedOwnIdentity(t, h, u.ID, "https://idp.example.com", "subject-rules")
	jwt := h.login(t, u.Email, "password123")

	// Both proofs at once is a client bug, not an attempt to unlock.
	w := h.do(t, http.MethodPost, "/api/v1/auth/identity/unlink", map[string]any{
		"identity_id":  row.ID,
		"stepup_token": "x",
		"password":     "password123",
	}, jwt)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())

	// No proof at all must not unlock anything either.
	w = h.do(t, http.MethodPost, "/api/v1/auth/identity/unlink", map[string]any{
		"identity_id": row.ID,
	}, jwt)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())

	// A wrong password must be refused and must not consume the row.
	w = h.do(t, http.MethodPost, "/api/v1/auth/identity/unlink", map[string]any{
		"identity_id": row.ID,
		"password":    "wrong-password",
	}, jwt)
	require.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())

	var count int64
	require.NoError(t, h.db.DB.Model(&model.UserIdentity{}).Where("id = ?", row.ID).Count(&count).Error)
	require.EqualValues(t, 1, count, "a failed proof must not delete the binding")
}

func TestUnlinkIdentity_OtherUsersIdentityIs404(t *testing.T) {
	h, _ := identityHarness(t)
	owner := h.seedUser(t, "oidc-owner@example.com", "password123")
	row := seedOwnIdentity(t, h, owner.ID, "https://idp.example.com", "subject-owner")
	other := h.seedUser(t, "oidc-other@example.com", "password123")
	jwt := h.login(t, other.Email, "password123")

	w := h.do(t, http.MethodPost, "/api/v1/auth/identity/unlink", map[string]any{
		"identity_id": row.ID,
		"password":    "password123",
	}, jwt)
	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())
}

func TestUnlinkIdentity_SecondBindingUnlinkAfterPasswordRemoved(t *testing.T) {
	h, _ := identityHarness(t)
	u := h.seedUser(t, "oidc-lastid@example.com", "password123")
	first := seedOwnIdentity(t, h, u.ID, "https://idp.example.com", "subject-lastid-a")
	second := seedOwnIdentity(t, h, u.ID, "https://idp2.example.com", "subject-lastid-b")
	jwt := h.login(t, u.Email, "password123")

	// With a password and two bindings, the first unlink is legitimate.
	w := h.do(t, http.MethodPost, "/api/v1/auth/identity/unlink", map[string]any{
		"identity_id": first.ID,
		"password":    "password123",
	}, jwt)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var count int64
	require.NoError(t, h.db.DB.Model(&model.UserIdentity{}).Where("user_id = ?", u.ID).Count(&count).Error)
	require.EqualValues(t, 1, count)

	// The password is now gone (passkey-only style account): the stale client
	// still sends the old password as proof.
	require.NoError(t, h.db.DB.Model(&model.User{}).Where("id = ?", u.ID).Update("password_hash", "").Error)
	w = h.do(t, http.MethodPost, "/api/v1/auth/identity/unlink", map[string]any{
		"identity_id": second.ID,
		"password":    "password123",
	}, jwt)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())

	require.NoError(t, h.db.DB.Model(&model.UserIdentity{}).Where("id = ?", second.ID).Count(&count).Error)
	require.EqualValues(t, 1, count, "the refused attempt must not delete the last binding")
}
