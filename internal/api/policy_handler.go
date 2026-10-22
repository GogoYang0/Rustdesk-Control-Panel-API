package api

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/GogoYang0/rustdesk-control-panel-api/gen"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/authz"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/session"
)

// policyPresence mirrors the request body with pointer fields.
//
// The generated type uses plain bools, which cannot tell "omitted" from `false`.
// Reading presence from the raw payload is what keeps an omitted
// enabled/require_approval a 400 instead of a silent policy disable.
type policyPresence struct {
	Name                  *string `json:"name"`
	Enabled               *bool   `json:"enabled"`
	RequireApproval       *bool   `json:"require_approval"`
	MaxConcurrentSessions *int64  `json:"max_concurrent_sessions"`
	MaxSessionMinutes     *int64  `json:"max_session_minutes"`
	AllowedStartMinute    *int64  `json:"allowed_start_minute"`
	AllowedEndMinute      *int64  `json:"allowed_end_minute"`
}

func (p policyPresence) toInput() session.PolicyInput {
	in := session.PolicyInput{
		Enabled:               p.Enabled,
		RequireApproval:       p.RequireApproval,
		MaxConcurrentSessions: p.MaxConcurrentSessions,
		MaxSessionMinutes:     p.MaxSessionMinutes,
		AllowedStartMinute:    p.AllowedStartMinute,
		AllowedEndMinute:      p.AllowedEndMinute,
	}
	if p.Name != nil {
		in.Name = *p.Name
	}
	return in
}

// writePolicyError maps policy domain errors onto the contract's status codes.
func (a *AdminAPI) writePolicyError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, session.ErrInvalidInput):
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, err.Error())
	case errors.Is(err, session.ErrDuplicatePolicy):
		abortError(c, http.StatusConflict, gen.ErrorCodeConflict, err.Error())
	case errors.Is(err, session.ErrPolicyNotFound):
		abortError(c, http.StatusNotFound, gen.ErrorCodeNotFound, err.Error())
	default:
		a.deps.Logger.Error("policy operation failed", zap.Error(err))
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not complete the policy operation")
	}
}

// ListPolicies returns the organization's policies. Reading is a member-level
// capability: the effective policy decides what a member can do, so members are
// allowed to see it.
func (a *AdminAPI) ListPolicies(c *gin.Context, orgId int64) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	if orgId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid organization id")
		return
	}
	if _, ok := a.membershipFor(c, uid, uint(orgId)); !ok {
		return
	}

	policies, err := a.tickets.ListPolicies(c.Request.Context(), uint(orgId))
	if err != nil {
		a.writePolicyError(c, err)
		return
	}
	// Polled read: the request-level audit fallback would add a row per poll,
	// which is exactly the noise #19 removed.
	c.Set(contextAuditRecorded, true)
	c.JSON(http.StatusOK, gen.PolicyListResponse{
		Code:    gen.ErrorCodeOk,
		Message: "ok",
		Data:    policiesToAPI(policies),
	})
}

// CreatePolicy writes a new policy. Only owners and admins may: a policy decides
// whether connections are allowed at all.
func (a *AdminAPI) CreatePolicy(c *gin.Context, orgId int64) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	if orgId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid organization id")
		return
	}
	if !a.requirePerm(c, uid, uint(orgId), authz.PermPolicyWrite) {
		return
	}

	var body policyPresence
	if err := c.ShouldBindJSON(&body); err != nil {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid request body")
		return
	}

	in := body.toInput()
	in.ActorUserID = uid
	policy, err := a.tickets.CreatePolicy(c.Request.Context(), uint(orgId), in)
	if err != nil {
		a.writePolicyError(c, err)
		return
	}
	c.Set(contextAuditRecorded, true)
	c.JSON(http.StatusCreated, gen.PolicyResponse{
		Code:    gen.ErrorCodeOk,
		Message: "ok",
		Data:    policyToAPI(*policy),
	})
}

// UpdatePolicy replaces a policy wholesale. The same role gate as creation.
func (a *AdminAPI) UpdatePolicy(c *gin.Context, orgId int64, policyId int64) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	if orgId <= 0 || policyId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid id")
		return
	}
	if !a.requirePerm(c, uid, uint(orgId), authz.PermPolicyWrite) {
		return
	}

	var body policyPresence
	if err := c.ShouldBindJSON(&body); err != nil {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid request body")
		return
	}

	in := body.toInput()
	in.ActorUserID = uid
	policy, err := a.tickets.UpdatePolicy(c.Request.Context(), uint(orgId), uint(policyId), in)
	if err != nil {
		a.writePolicyError(c, err)
		return
	}
	c.Set(contextAuditRecorded, true)
	c.JSON(http.StatusOK, gen.PolicyResponse{
		Code:    gen.ErrorCodeOk,
		Message: "ok",
		Data:    policyToAPI(*policy),
	})
}

// DeletePolicy removes a policy. Deleting is not an emergency stop: the remaining
// enabled policies keep applying, and an organization with none is unrestricted
// by design — so the role gate is the same and no extra confirmation is needed.
func (a *AdminAPI) DeletePolicy(c *gin.Context, orgId int64, policyId int64) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	if orgId <= 0 || policyId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid id")
		return
	}
	if !a.requirePerm(c, uid, uint(orgId), authz.PermPolicyWrite) {
		return
	}

	if err := a.tickets.DeletePolicy(c.Request.Context(), uint(orgId), uint(policyId), uid); err != nil {
		a.writePolicyError(c, err)
		return
	}
	c.Set(contextAuditRecorded, true)
	c.JSON(http.StatusOK, gen.OkResponse{Code: gen.ErrorCodeOk, Message: "ok"})
}

func policyToAPI(p model.Policy) gen.Policy {
	return gen.Policy{
		Id:                    int64(p.ID),
		OrganizationId:        int64(p.OrganizationID),
		Name:                  p.Name,
		Enabled:               p.Enabled,
		MaxConcurrentSessions: p.MaxConcurrentSessions,
		MaxSessionMinutes:     p.MaxSessionMinutes,
		AllowedStartMinute:    p.AllowedStartMinute,
		AllowedEndMinute:      p.AllowedEndMinute,
		RequireApproval:       p.RequireApproval,
		CreatedAt:             p.CreatedAt,
		UpdatedAt:             p.UpdatedAt,
	}
}

func policiesToAPI(policies []model.Policy) []gen.Policy {
	out := make([]gen.Policy, 0, len(policies))
	for _, p := range policies {
		out = append(out, policyToAPI(p))
	}
	return out
}
