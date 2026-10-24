package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/GogoYang0/rustdesk-control-panel-api/gen"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/authz"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/provision"
)

// getProvisioningState maps the service status onto the contract enum. An
// unknown value means the two sides drifted apart and must not be reported as
// a plausible state.
func getProvisioningState(status string) (gen.ProvisioningStatusState, bool) {
	switch status {
	case provision.StatusDisabled:
		return gen.ProvisioningStatusStateDisabled, true
	case provision.StatusPending:
		return gen.ProvisioningStatusStatePending, true
	case model.ServerGroupProvisioning:
		return gen.ProvisioningStatusStateProvisioning, true
	case model.ServerGroupDeployed:
		return gen.ProvisioningStatusStateDeployed, true
	case model.ServerGroupFailed:
		return gen.ProvisioningStatusStateFailed, true
	default:
		return "", false
	}
}

// respondProvisioning writes the standard envelope for a provisioning state.
func (a *AdminAPI) respondProvisioning(c *gin.Context, status int, state provision.State) {
	enum, ok := getProvisioningState(state.Status)
	if !ok {
		a.deps.Logger.Error("unknown provisioning state", zap.String("state", state.Status))
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not read provisioning state")
		return
	}
	c.JSON(status, gen.ProvisioningResponse{
		Code:    gen.ErrorCodeOk,
		Message: "ok",
		Data: gen.ProvisioningStatus{
			Enabled: state.Enabled,
			State:   enum,
		},
	})
}

// GetProvisioning reports the organization's provisioning switch and
// deployment status. Infrastructure control belongs to the owner.
func (a *AdminAPI) GetProvisioning(c *gin.Context, orgId int64) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	if orgId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid organization id")
		return
	}
	if !a.requirePerm(c, uid, uint(orgId), authz.PermOrgAdmin) {
		return
	}
	if a.deps.Provisioning == nil {
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "provisioning unavailable")
		return
	}

	state, err := a.deps.Provisioning.State(c.Request.Context(), uint(orgId))
	if err != nil {
		a.deps.Logger.Error("load provisioning state failed", zap.Uint("org_id", uint(orgId)), zap.Error(err))
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not read provisioning state")
		return
	}
	a.respondProvisioning(c, http.StatusOK, state)
}

// UpdateProvisioning flips the organization's provisioning switch. Disabling is
// synchronous because it must stop the containers first; enabling only records
// the intent and hands the deployment to the bounded queue.
func (a *AdminAPI) UpdateProvisioning(c *gin.Context, orgId int64) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	if orgId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid organization id")
		return
	}
	if !a.requirePerm(c, uid, uint(orgId), authz.PermOrgAdmin) {
		return
	}

	// A pointer distinguishes a missing "enabled" from an explicit false.
	var req struct {
		Enabled *bool `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.Enabled == nil {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "enabled is required")
		return
	}
	if a.deps.Provisioning == nil {
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "provisioning unavailable")
		return
	}

	state, changed, err := a.deps.Provisioning.SetEnabled(
		c.Request.Context(), uint(orgId), uid, *req.Enabled)
	if err != nil {
		a.deps.Logger.Error("update provisioning failed", zap.Uint("org_id", uint(orgId)), zap.Error(err))
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not update provisioning")
		return
	}
	// The service wrote the domain audit row inside the mutation transaction;
	// an idempotent request has none and keeps the middleware fallback.
	if changed {
		c.Set(contextAuditRecorded, true)
	}

	// Only a fresh enable needs a nudge: a deployed or failed row is left alone
	// (the failed path is an existing manual-recovery rule), and a no-op must
	// not flood the queue. A full queue is recoverable: the reconciler sees the
	// organization without a server group and enqueues it again.
	if changed && state.Enabled && state.Status == provision.StatusPending && a.deps.ProvisionQueue != nil {
		if qerr := a.deps.ProvisionQueue.Enqueue(uint(orgId)); qerr != nil {
			a.deps.Logger.Warn("provisioning enqueue failed; the reconciler will retry",
				zap.Uint("org_id", uint(orgId)), zap.Error(qerr))
		}
	}
	if changed && state.Enabled && state.Status == model.ServerGroupFailed {
		a.deps.Logger.Warn("provisioning enabled but the deployment is failed; manual recovery is required",
			zap.Uint("org_id", uint(orgId)))
	}

	a.respondProvisioning(c, http.StatusOK, state)
}
