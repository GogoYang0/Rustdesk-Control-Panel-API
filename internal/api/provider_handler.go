package api

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/GogoYang0/rustdesk-control-panel-api/gen"
)

// ListAuthProviders tells the login page which credential sources exist. In
// 5b-1 the external providers are always off; 5b-2/5b-3 flip these flags.
func (a *AdminAPI) ListAuthProviders(c *gin.Context) {
	status := gen.AuthProviderStatus{Enabled: false}
	if a.oidc != nil {
		name := a.oidc.ProviderName()
		status = gen.AuthProviderStatus{Enabled: true, Name: &name}
	}
	c.JSON(http.StatusOK, gen.AuthProvidersResponse{
		Code:    gen.ErrorCodeOk,
		Message: "ok",
		// LDAP has no implementation in this build; config validation refuses
		// to start with ldap.enabled, so false is the only truthful answer.
		Data: gen.AuthProviders{Oidc: status, Ldap: gen.AuthProviderStatus{Enabled: false}},
	})
}
