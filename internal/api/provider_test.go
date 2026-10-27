package api_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAuthProviders_AllDisabledInWaveFiveBOne(t *testing.T) {
	h := newHarness(t)

	w := h.do(t, http.MethodGet, "/api/v1/auth/providers", nil, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var view struct {
		Oidc struct {
			Enabled bool `json:"enabled"`
		} `json:"oidc"`
		Ldap struct {
			Enabled bool `json:"enabled"`
		} `json:"ldap"`
	}
	decodeData(t, w, &view)
	require.False(t, view.Oidc.Enabled)
	require.False(t, view.Ldap.Enabled)
}
