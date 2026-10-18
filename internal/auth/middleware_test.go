package auth_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/auth"
)

func newRouter(issuer *auth.Issuer) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/me", auth.RequireJWT(issuer), func(c *gin.Context) {
		uid, ok := auth.UserID(c)
		if !ok {
			c.Status(http.StatusInternalServerError)
			return
		}
		c.JSON(http.StatusOK, gin.H{"user_id": uid})
	})
	return r
}

func doGet(t *testing.T, r *gin.Engine, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestRequireJWT_RejectsMissingToken(t *testing.T) {
	r := newRouter(auth.NewIssuer("s", time.Minute, time.Hour))
	require.Equal(t, http.StatusUnauthorized, doGet(t, r, "").Code)
}

func TestRequireJWT_RejectsGarbageToken(t *testing.T) {
	r := newRouter(auth.NewIssuer("s", time.Minute, time.Hour))
	require.Equal(t, http.StatusUnauthorized, doGet(t, r, "not-a-jwt").Code)
}

func TestRequireJWT_AcceptsValidToken(t *testing.T) {
	issuer := auth.NewIssuer("s", time.Minute, time.Hour)
	access, _, err := issuer.Issue(77)
	require.NoError(t, err)

	w := doGet(t, newRouter(issuer), access)
	require.Equal(t, http.StatusOK, w.Code)
	require.Contains(t, w.Body.String(), "77")
}

func TestRequireJWT_AcceptsLowercaseScheme(t *testing.T) {
	issuer := auth.NewIssuer("s", time.Minute, time.Hour)
	access, _, err := issuer.Issue(88)
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)
	r := newRouter(issuer)
	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.Header.Set("Authorization", "bearer "+access)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestRequireJWT_SetsChallengeHeader(t *testing.T) {
	r := newRouter(auth.NewIssuer("s", time.Minute, time.Hour))
	w := doGet(t, r, "")
	require.Equal(t, http.StatusUnauthorized, w.Code)
	require.Contains(t, w.Header().Get("WWW-Authenticate"), "Bearer")
}
