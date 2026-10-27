package api

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/GogoYang0/rustdesk-control-panel-api/gen"
)

// ListAuthProviders tells the login page which credential sources exist.
func (a *AdminAPI) ListAuthProviders(c *gin.Context) {
	oidcStatus := gen.AuthProviderStatus{Enabled: false}
	if a.oidc != nil {
		name := a.oidc.ProviderName()
		oidcStatus = gen.AuthProviderStatus{Enabled: true, Name: &name}
	}
	ldapStatus := gen.AuthProviderStatus{Enabled: false}
	if a.ldap != nil {
		name := a.ldapName
		ldapStatus = gen.AuthProviderStatus{Enabled: true, Name: &name}
	}
	c.JSON(http.StatusOK, gen.AuthProvidersResponse{
		Code:    gen.ErrorCodeOk,
		Message: "ok",
		Data:    gen.AuthProviders{Oidc: oidcStatus, Ldap: ldapStatus},
	})
}
