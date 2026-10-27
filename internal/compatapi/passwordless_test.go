package compatapi_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
)

// TestCompatLogin_PasswordlessAccountRejectsDummyPassword mirrors the admin
// regression: compat keeps a separate dummy hash with its own literal.
func TestCompatLogin_PasswordlessAccountRejectsDummyPassword(t *testing.T) {
	h := newHarness(t)
	u := h.seedUser(t, "compat-passwordless@example.com", "password123", true)
	org := h.seedOrg(t, "compat-passwordless-org")
	h.seedMembership(t, u.ID, org.ID)
	require.NoError(t, h.db.DB.Model(&model.User{}).Where("id = ?", u.ID).Update("password_hash", "").Error)

	w := h.do(t, http.MethodPost, "/api/login", map[string]string{
		"username": "compat-passwordless@example.com",
		"password": "dummy-password-for-compat-timing",
		"id":       "1001",
		"uuid":     "11111111-2222-3333-4444-555555555555",
	}, "")
	require.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())
}
