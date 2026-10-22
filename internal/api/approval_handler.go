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

// ListApprovals returns the organization's approval inbox. Reading is a
// member-level capability: the approval center is read-only for members.
func (a *AdminAPI) ListApprovals(c *gin.Context, orgId int64, params gen.ListApprovalsParams) {
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

	filter := session.ApprovalFilter{}
	if params.Status != nil {
		filter.Status = (*string)(params.Status)
	}
	if params.DeviceId != nil {
		if *params.DeviceId <= 0 {
			abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid device id")
			return
		}
		id := uint(*params.DeviceId)
		filter.DeviceID = &id
	}
	if params.Page != nil {
		filter.Page = *params.Page
	}
	if params.PageSize != nil {
		filter.PageSize = *params.PageSize
	}

	items, total, err := a.tickets.ListApprovals(c.Request.Context(), uint(orgId), filter)
	if err != nil {
		a.writeApprovalError(c, err)
		return
	}
	page, pageSize := filter.NormalisedPagination()
	// The approval center polls this endpoint; the request-level audit
	// fallback would add a row per poll, which is exactly the noise #19 removed.
	c.Set(contextAuditRecorded, true)
	c.JSON(http.StatusOK, gen.ApprovalListResponse{
		Code:    gen.ErrorCodeOk,
		Message: "ok",
		Data: gen.ApprovalPage{
			Items:    approvalsToAPI(items),
			Page:     page,
			PageSize: int64(pageSize),
			Total:    total,
		},
	})
}

// GetApproval returns one approval request. Unlike the list, a single detail
// read is an investigation visit, not a poll, so the request-level audit
// fallback is left on — the same rule the session detail endpoint follows.
func (a *AdminAPI) GetApproval(c *gin.Context, orgId int64, approvalId int64) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	if orgId <= 0 || approvalId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid id")
		return
	}
	if _, ok := a.membershipFor(c, uid, uint(orgId)); !ok {
		return
	}

	approval, err := a.tickets.Approval(c.Request.Context(), uint(orgId), uint(approvalId))
	if err != nil {
		a.writeApprovalError(c, err)
		return
	}
	c.JSON(http.StatusOK, gen.ApprovalResponse{
		Code:    gen.ErrorCodeOk,
		Message: "ok",
		Data:    approvalToAPI(*approval),
	})
}

// CreateApproval submits an approval request. Any member may ask; whether the
// underlying request is later granted is the approver's decision.
func (a *AdminAPI) CreateApproval(c *gin.Context, orgId int64) {
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

	var req gen.ApprovalCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid request body")
		return
	}
	// An unknown kind must be a 400 before anything else happens; the service
	// would reject it too, but gen's own enum is the cheapest check.
	if !req.Kind.Valid() {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "unknown approval kind")
		return
	}

	in := session.ApprovalCreateInput{
		Kind:   string(req.Kind),
		Reason: req.Reason,
	}
	if req.DeviceId != nil {
		if *req.DeviceId <= 0 {
			abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid device id")
			return
		}
		in.DeviceID = uint(*req.DeviceId)
	}
	if req.SessionId != nil {
		if *req.SessionId <= 0 {
			abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid session id")
			return
		}
		id := uint(*req.SessionId)
		in.SessionID = &id
	}

	approval, reused, err := a.tickets.CreateApproval(c.Request.Context(), uint(orgId), uid, in)
	if err != nil {
		a.writeApprovalError(c, err)
		return
	}
	// The service audited the new request itself; a reuse is not a new fact.
	c.Set(contextAuditRecorded, true)
	status := http.StatusCreated
	if reused {
		status = http.StatusOK
	}
	c.JSON(status, gen.ApprovalResponse{
		Code:    gen.ErrorCodeOk,
		Message: "ok",
		Data:    approvalToAPI(*approval),
	})
}

// DecideApproval records an owner/admin decision. Approving issues nothing:
// the contract makes the approval a permission to issue one ticket, consumed
// at issuance — never a ticket in the response.
func (a *AdminAPI) DecideApproval(c *gin.Context, orgId int64, approvalId int64) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	if orgId <= 0 || approvalId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid id")
		return
	}
	if !a.requirePerm(c, uid, uint(orgId), authz.PermApprovalDecide) {
		return
	}

	var req gen.ApprovalDecisionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid request body")
		return
	}
	if req.Decision != gen.Approve && req.Decision != gen.Deny {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "decision must be approve or deny")
		return
	}

	approval, err := a.tickets.DecideApproval(c.Request.Context(), uint(orgId), uint(approvalId), uid,
		string(req.Decision), req.Reason)
	if err != nil {
		a.writeApprovalError(c, err)
		return
	}
	c.Set(contextAuditRecorded, true)
	c.JSON(http.StatusOK, gen.ApprovalResponse{
		Code:    gen.ErrorCodeOk,
		Message: "ok",
		Data:    approvalToAPI(*approval),
	})
}

// writeApprovalError maps approval domain errors onto the contract's status
// codes.
func (a *AdminAPI) writeApprovalError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, session.ErrInvalidInput):
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, err.Error())
	case errors.Is(err, session.ErrApprovalNotFound), errors.Is(err, session.ErrDeviceNotFound):
		abortError(c, http.StatusNotFound, gen.ErrorCodeNotFound, err.Error())
	case errors.Is(err, session.ErrConflict):
		abortError(c, http.StatusConflict, gen.ErrorCodeConflict, err.Error())
	default:
		a.deps.Logger.Error("approval operation failed", zap.Error(err))
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not complete the approval operation")
	}
}

func approvalToAPI(p model.Approval) gen.Approval {
	out := gen.Approval{
		Id:             int64(p.ID),
		OrganizationId: int64(p.OrganizationID),
		DeviceId:       int64(p.DeviceID),
		Kind:           gen.ApprovalKind(p.Kind),
		Status:         gen.ApprovalStatus(p.Status),
		RequestedAt:    p.RequestedAt,
		ExpiresAt:      p.ExpiresAt,
		DecidedAt:      p.DecidedAt,
		Reason:         p.Reason,
	}
	if p.ActorUserID != 0 {
		uid := int64(p.ActorUserID)
		out.ActorUserId = &uid
	}
	if p.SessionID != nil {
		id := int64(*p.SessionID)
		out.SessionId = &id
	}
	if p.DecidedBy != nil {
		id := int64(*p.DecidedBy)
		out.DecidedBy = &id
	}
	if p.TicketID != nil {
		id := int64(*p.TicketID)
		out.TicketId = &id
	}
	return out
}

func approvalsToAPI(items []model.Approval) []gen.Approval {
	out := make([]gen.Approval, 0, len(items))
	for _, p := range items {
		out = append(out, approvalToAPI(p))
	}
	return out
}
