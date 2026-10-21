package api_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// The compat paths under /api/* must never be reached by the management JWT
// middleware: an unauthenticated client must hit the compat handler (400/200
// body from the compat layer, not the management 401 envelope), and a
// management access token must not open compat session endpoints.
func TestRouter_ManageJWTNotAppliedToCompatPaths(t *testing.T) {
	h := newHarness(t)
	h.seedUser(t, "mgmt@example.com", "password123")

	// No Authorization header: the management middleware would answer 401
	// "authentication required" before the handler; the compat handler is
	// reached instead.
	w := h.do(t, http.MethodPost, "/api/login", map[string]string{
		"username": "mgmt@example.com", "password": "wrong-pass-1",
	}, "")
	require.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), "invalid credentials",
		"the request must reach the compat handler, not the management JWT middleware")

	// The same for the public-shaped compat probes.
	w = h.do(t, http.MethodGet, "/api/login-options", nil, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
}

// A management-family token must not open compat session endpoints: the two
// token families stay separate (ParseCompat rejects typ=access).
func TestRouter_ManagementTokenCannotOpenCompatEndpoints(t *testing.T) {
	h := newHarness(t)
	h.seedUser(t, "fam@example.com", "password123")
	adminToken := h.login(t, "fam@example.com", "password123")

	w := h.do(t, http.MethodPost, "/api/currentUser", nil, adminToken)
	require.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())

	w = h.do(t, http.MethodGet, "/api/peers", nil, adminToken)
	require.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())
}
