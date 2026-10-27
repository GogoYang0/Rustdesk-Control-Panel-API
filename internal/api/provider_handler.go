package api

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/GogoYang0/rustdesk-control-panel-api/gen"
)

// ListAuthProviders tells the login page which credential sources exist. In
// 5b-1 the external providers are always off; 5b-2/5b-3 flip these flags.
func (a *AdminAPI) ListAuthProviders(c *gin.Context) {
	c.JSON(http.StatusOK, gen.AuthProvidersResponse{
		Code:    gen.ErrorCodeOk,
		Message: "ok",
		Data: gen.AuthProviders{
			Oidc: gen.AuthProviderStatus{Enabled: false},
			Ldap: gen.AuthProviderStatus{Enabled: false},
		},
	})
}
