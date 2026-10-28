package api

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	openapi_types "github.com/oapi-codegen/runtime/types"
	"go.uber.org/zap"

	"github.com/GogoYang0/rustdesk-control-panel-api/gen"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/account"
)

// GetMe returns the caller's own profile and the organizations in which the
// caller holds an effective membership. The console calls it once per load,
// before any organization-scoped request, so the response deliberately carries
// nothing that belongs to another user.
func (a *AdminAPI) GetMe(c *gin.Context) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	me, err := a.deps.Me.Me(c.Request.Context(), uid)
	if err != nil {
		if errors.Is(err, account.ErrNotFound) {
			// The token is valid but the account is gone: an access token can
			// outlive a deletion by at most its TTL.
			abortError(c, http.StatusNotFound, gen.ErrorCodeNotFound, "user not found")
			return
		}
		a.deps.Logger.Error("resolve current user failed", zap.Error(err))
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not complete the request")
		return
	}
	c.JSON(http.StatusOK, gen.MeResponse{
		Code:    gen.ErrorCodeOk,
		Message: "ok",
		Data:    meToAPI(me),
	})
}

func meToAPI(me account.Me) gen.Me {
	out := gen.Me{
		User: gen.MeUser{
			Id:            int64(me.User.ID),
			Email:         openapi_types.Email(me.User.Email),
			EmailVerified: me.User.EmailVerified,
			TotpEnabled:   me.User.TOTPEnabled,
			HasPassword:   me.User.HasPassword,
		},
		Orgs: make([]gen.MeOrg, 0, len(me.Orgs)),
	}
	for _, org := range me.Orgs {
		perms := org.Permissions
		if perms == nil {
			perms = []string{}
		}
		out.Orgs = append(out.Orgs, gen.MeOrg{
			Id:          int64(org.ID),
			Name:        org.Name,
			RoleId:      int64(org.RoleID),
			RoleKind:    gen.MeOrgRoleKind(org.RoleKind),
			Permissions: perms,
		})
	}
	return out
}
