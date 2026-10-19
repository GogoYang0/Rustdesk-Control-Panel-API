package api

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/GogoYang0/rustdesk-control-panel-api/gen"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/authz"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// contextOrgID is the gin key holding the org id resolved from the path.
const contextOrgID = "api.orgID"

// membershipFor loads the caller's membership for the org in the path.
//
// The lookup itself is cross-tenant (a user may belong to several orgs), so it
// goes through store.WithoutTenantScope; every later query uses the tenant
// scoped handle.
func (a *AdminAPI) membershipFor(c *gin.Context, userID, orgID uint) (*model.Membership, bool) {
	var m model.Membership
	err := store.WithoutTenantScope(a.deps.DB).
		Where("organization_id = ? AND user_id = ?", orgID, userID).
		First(&m).Error
	if err != nil {
		abortError(c, http.StatusForbidden, gen.ErrorCodeForbidden, "not a member of this organization")
		return nil, false
	}
	c.Set(contextOrgID, orgID)
	authz.SetOrgRole(c, m.Role)
	return &m, true
}

// requirePerm resolves the membership and checks the permission.
func (a *AdminAPI) requirePerm(c *gin.Context, userID, orgID uint, perm string) bool {
	m, ok := a.membershipFor(c, userID, orgID)
	if !ok {
		return false
	}
	if !authz.Can(m.Role, perm) {
		abortError(c, http.StatusForbidden, gen.ErrorCodeForbidden, "insufficient permissions")
		return false
	}
	return true
}

// GetHealthz reports process liveness without authentication.
func (a *AdminAPI) GetHealthz(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": string(gen.GetHealthz200JSONResponseBodyStatusOk)})
}
