package authz_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/authz"
)

func routerWithRole(role string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/devices", func(c *gin.Context) {
		authz.SetOrgRole(c, role)
	}, authz.RequirePerm(authz.PermDeviceWrite), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
	return r
}

func TestRequirePerm(t *testing.T) {
	for _, c := range []struct {
		role string
		want int
	}{
		{"owner", http.StatusOK},
		{"admin", http.StatusOK},
		{"member", http.StatusForbidden},
		{"", http.StatusForbidden},
	} {
		w := httptest.NewRecorder()
		routerWithRole(c.role).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/devices", nil))
		require.Equal(t, c.want, w.Code, "role %q", c.role)
	}
}
