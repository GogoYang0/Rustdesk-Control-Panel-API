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

// membershipFor loads the caller's membership for the org in the path and
// resolves its effective role. A missing membership or an unresolvable role
// fails closed with 403.
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
	if m.Disabled {
		// A disabled membership keeps its row (history stays attributable) but
		// grants nothing: every management path fails closed here.
		abortError(c, http.StatusForbidden, gen.ErrorCodeForbidden, "membership is disabled")
		return nil, false
	}
	role, err := a.deps.Roles.Resolve(orgID, m)
	if err != nil {
		// A membership without a resolvable role cannot be authorized; fail
		// closed instead of guessing a role from the legacy string.
		abortError(c, http.StatusForbidden, gen.ErrorCodeForbidden, "membership role unavailable")
		return nil, false
	}
	c.Set(contextOrgID, orgID)
	authz.SetOrgRole(c, role.Name)
	authz.SetOrgPermissions(c, role.PermissionList())
	authz.SetOrgAuditScope(c, role.AuditScope)
	return &m, true
}

// requirePerm resolves the membership and checks the permission.
func (a *AdminAPI) requirePerm(c *gin.Context, userID, orgID uint, perm string) bool {
	if _, ok := a.membershipFor(c, userID, orgID); !ok {
		return false
	}
	perms, ok := authz.OrgPermissions(c)
	if !ok || !authz.Has(perms, perm) {
		abortError(c, http.StatusForbidden, gen.ErrorCodeForbidden, "insufficient permissions")
		return false
	}
	return true
}

// GetHealthz reports process liveness without authentication.
func (a *AdminAPI) GetHealthz(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": string(gen.GetHealthz200JSONResponseBodyStatusOk)})
}
