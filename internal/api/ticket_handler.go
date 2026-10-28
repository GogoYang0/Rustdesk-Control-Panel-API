package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/GogoYang0/rustdesk-control-panel-api/gen"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/audit"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/session"
)

// IssueTicket issues a one-shot connection ticket.
//
// Any member may ask: whether the request is granted is a policy decision, not a
// role decision, so this endpoint checks membership only.
func (a *AdminAPI) IssueTicket(c *gin.Context, orgId int64) {
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

	var req gen.TicketCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil || req.DeviceId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "device_id is required")
		return
	}

	// Access control decides whether this member may reach the device at all;
	// it runs before any policy, approval or ticket bookkeeping so no refusal
	// path can leak the device's existence or start an approval flow the member
	// could never redeem.
	allowed, err := a.deps.Access.CanAccess(c.Request.Context(), uint(orgId), uid, uint(req.DeviceId))
	if err != nil {
		a.deps.Logger.Error("ticket access evaluation failed", zap.Error(err))
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not complete the ticket operation")
		return
	}
	if !allowed {
		a.denyTicketAccess(c, uint(orgId), uid, uint(req.DeviceId), "issue", nil)
		return
	}

	ticket, token, err := a.tickets.Issue(c.Request.Context(), session.IssueInput{
		OrganizationID: uint(orgId),
		ActorUserID:    uid,
		DeviceID:       uint(req.DeviceId),
		TTLSeconds:     req.TtlSeconds,
	})
	if err != nil {
		// A policy refusal already wrote its own audit row (the denied session),
		// so the request-level fallback must not add a second one.
		if errors.Is(err, session.ErrOutsideWindow) {
			c.Set(contextAuditRecorded, true)
		}
		a.writeTicketError(c, err)
		return
	}

	// The plaintext token is a one-shot credential: no cache anywhere along the
	// path may keep it.
	c.Header("Cache-Control", "no-store")
	c.Set(contextAuditRecorded, true)
	c.JSON(http.StatusCreated, gen.IssuedTicketResponse{
		Code:    gen.ErrorCodeOk,
		Message: "ok",
		Data: gen.IssuedTicket{
			Ticket: ticketToAPI(ticket),
			Token:  token,
		},
	})
}

// RedeemTicket consumes a ticket and returns the panel session it authorised.
func (a *AdminAPI) RedeemTicket(c *gin.Context, orgId int64, ticketId int64) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	if orgId <= 0 || ticketId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid id")
		return
	}
	if _, ok := a.membershipFor(c, uid, uint(orgId)); !ok {
		return
	}

	var req gen.TicketRedeemRequest
	if err := c.ShouldBindJSON(&req); err != nil || req.Token == "" {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "token is required")
		return
	}

	// Validate the secret and the terminal states without consuming anything
	// before any access-dependent response: a wrong token must answer the same
	// 409 for every device, otherwise it could probe whether the device is
	// disabled (CWE-203). The atomic redemption repeats the check inside its
	// transaction, so the ticket stays one-shot.
	ticket, err := a.tickets.ValidateRedeem(c.Request.Context(), uint(orgId), uint(ticketId), req.Token)
	if err != nil {
		a.writeTicketError(c, err)
		return
	}
	// The admission decision is judged against the redeemer (D9): a member
	// whose rules were tightened after issuance cannot consume an old ticket.
	allowed, err := a.deps.Access.CanAccess(c.Request.Context(), uint(orgId), uid, ticket.DeviceID)
	if err != nil {
		a.deps.Logger.Error("ticket access evaluation failed", zap.Error(err))
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not complete the ticket operation")
		return
	}
	if !allowed {
		// A device an administrator stopped keeps the documented 409 conflict
		// from before access control existed (the ticket stays unused). The
		// message is the opaque conflict text so the response does not echo the
		// device state; only the code difference is unavoidable while the M4
		// contract stands. Every other access refusal is the opaque 404.
		stopped, derr := a.deps.Access.DeviceDisabled(c.Request.Context(), uint(orgId), ticket.DeviceID)
		if derr != nil {
			a.deps.Logger.Error("ticket access evaluation failed", zap.Error(derr))
			abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not complete the ticket operation")
			return
		}
		if stopped {
			a.recordTicketAccessDenied(c, uint(orgId), uid, ticket.DeviceID, "device_disabled",
				"redeem", map[string]any{"ticket_id": ticketId})
			abortError(c, http.StatusConflict, gen.ErrorCodeConflict, session.ErrConflict.Error())
			return
		}
		a.denyTicketAccess(c, uint(orgId), uid, ticket.DeviceID, "redeem",
			map[string]any{"ticket_id": ticketId})
		return
	}

	sess, err := a.tickets.Redeem(c.Request.Context(), uint(orgId), uid, uint(ticketId), req.Token)
	if err != nil {
		// The in-transaction re-check refused. The ticket is untouched and no
		// session exists, so this is the same opaque 404 — and the same denial
		// row — as the pre-check above.
		if errors.Is(err, session.ErrAccessDenied) {
			a.denyTicketAccess(c, uint(orgId), uid, ticket.DeviceID, "redeem",
				map[string]any{"ticket_id": ticketId})
			return
		}
		a.writeTicketError(c, err)
		return
	}

	c.Set(contextAuditRecorded, true)
	c.JSON(http.StatusCreated, gen.SessionResponse{
		Code:    gen.ErrorCodeOk,
		Message: "ok",
		Data:    sessionToAPI(*sess),
	})
}

// GetTicket returns the bookkeeping view of one ticket. The plaintext token is
// never part of it: only the digest was ever stored.
func (a *AdminAPI) GetTicket(c *gin.Context, orgId int64, ticketId int64) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	if orgId <= 0 || ticketId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid id")
		return
	}
	if _, ok := a.membershipFor(c, uid, uint(orgId)); !ok {
		return
	}

	ticket, err := a.tickets.Ticket(c.Request.Context(), uint(orgId), uint(ticketId))
	if err != nil {
		a.writeTicketError(c, err)
		return
	}
	c.JSON(http.StatusOK, gen.TicketResponse{
		Code:    gen.ErrorCodeOk,
		Message: "ok",
		Data:    ticketToAPI(*ticket),
	})
}

// denyTicketAccess records the refusal and answers the opaque 404. It
// deliberately does not reuse the session service's recordDenied: that path
// writes a denied session with end_reason policy_denied and raises an
// outside_window alert, while an access refusal is a different cause the
// contract has no enum for. The 404 (instead of 403) keeps the device's
// existence hidden from a member without a rule.
func (a *AdminAPI) denyTicketAccess(c *gin.Context, orgID, userID, deviceID uint, stage string, extra map[string]any) {
	a.recordTicketAccessDenied(c, orgID, userID, deviceID, "access_control", stage, extra)
	abortError(c, http.StatusNotFound, gen.ErrorCodeNotFound, session.ErrDeviceNotFound.Error())
}

// recordTicketAccessDenied writes one denial row and, only when it committed,
// marks the context so the middleware does not add its generic fallback row. A
// failed record leaves the marker unset: the refusal still stands (denying is
// the safe side), and the fallback row is the only remaining trace.
func (a *AdminAPI) recordTicketAccessDenied(c *gin.Context, orgID, userID, deviceID uint, reason, stage string, extra map[string]any) {
	detail := map[string]any{
		"reason":    reason,
		"stage":     stage,
		"device_id": deviceID,
	}
	for key, value := range extra {
		detail[key] = value
	}
	entry := audit.Entry{
		OrganizationID: orgID,
		ActorUserID:    userID,
		Action:         "session.ticket.denied",
		TargetType:     "device",
		TargetID:       fmt.Sprint(deviceID),
		Detail:         detail,
	}
	if err := a.deps.Auditor.Record(c.Request.Context(), entry); err != nil {
		a.deps.Logger.Error("audit record failed",
			zap.String("action", entry.Action), zap.Error(err))
		return
	}
	c.Set(contextAuditRecorded, true)
}

// writeTicketError maps domain errors onto the contract's status codes.
//
// Every redeemable-state failure is a 409 so a caller cannot probe (expired?
// already used? revoked?); the reason stays in the message. approval_required is
// its own 409 code carrying data.approval_id, because the client is meant to
// route the user to the inbox and retry.
func (a *AdminAPI) writeTicketError(c *gin.Context, err error) {
	var need *session.ErrApprovalRequired
	switch {
	case errors.As(err, &need):
		data := map[string]interface{}{"approval_id": int64(need.ApprovalID)}
		c.AbortWithStatusJSON(http.StatusConflict, gen.ErrorResponse{
			Code:    gen.ErrorCodeApprovalRequired,
			Message: "approval required before issuing a ticket",
			Data:    &data,
		})
	case errors.Is(err, session.ErrInvalidInput):
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, err.Error())
	case errors.Is(err, session.ErrAccessDenied):
		// Redeem normally turns this into the audited denial; a future caller
		// that maps it here still gets the opaque not-found instead of a 500.
		abortError(c, http.StatusNotFound, gen.ErrorCodeNotFound, session.ErrDeviceNotFound.Error())
	case errors.Is(err, session.ErrDeviceNotFound), errors.Is(err, session.ErrTicketNotFound):
		abortError(c, http.StatusNotFound, gen.ErrorCodeNotFound, err.Error())
	case errors.Is(err, session.ErrDeviceDisabled):
		// The opaque conflict text: the pre-check path answers this state the
		// same way, and the message must not echo the device state (CWE-203).
		abortError(c, http.StatusConflict, gen.ErrorCodeConflict, session.ErrConflict.Error())
	case errors.Is(err, session.ErrOutsideWindow), errors.Is(err, session.ErrConflict):
		abortError(c, http.StatusConflict, gen.ErrorCodeConflict, err.Error())
	default:
		// Unexpected failures stay opaque to the client but not to operators.
		a.deps.Logger.Error("ticket operation failed", zap.Error(err))
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not complete the ticket operation")
	}
}

func ticketToAPI(t model.Ticket) gen.Ticket {
	out := gen.Ticket{
		Id:             int64(t.ID),
		OrganizationId: int64(t.OrganizationID),
		DeviceId:       int64(t.DeviceID),
		ExpiresAt:      t.ExpiresAt,
		CreatedAt:      t.CreatedAt,
		UsedAt:         t.UsedAt,
		RevokedAt:      t.RevokedAt,
	}
	if t.ActorUserID != 0 {
		uid := int64(t.ActorUserID)
		out.ActorUserId = &uid
	}
	if t.ApprovalID != nil {
		id := int64(*t.ApprovalID)
		out.ApprovalId = &id
	}
	if t.PolicySnapshotJSON != "" {
		var snapshot map[string]interface{}
		if err := json.Unmarshal([]byte(t.PolicySnapshotJSON), &snapshot); err == nil {
			out.PolicySnapshot = &snapshot
		}
	}
	if t.ControlRoleID != nil {
		id := int64(*t.ControlRoleID)
		out.ControlRoleId = &id
	}
	out.ControlPermissions = int64(t.ControlPermissions)
	return out
}

func sessionToAPI(s model.Session) gen.Session {
	out := gen.Session{
		Id:             int64(s.ID),
		OrganizationId: int64(s.OrganizationID),
		DeviceId:       int64(s.DeviceID),
		Origin:         gen.SessionOrigin(s.Origin),
		Status:         gen.SessionStatus(s.Status),
		StartedAt:      s.StartedAt,
		EndedAt:        s.EndedAt,
		EndReason:      s.EndReason,
		LastActivityAt: s.LastActivityAt,

		ControlPermissions: int64(s.ControlPermissions),
	}
	if s.ActorUserID != nil {
		uid := int64(*s.ActorUserID)
		out.ActorUserId = &uid
	}
	if s.TicketID != nil {
		id := int64(*s.TicketID)
		out.TicketId = &id
	}
	if s.PolicyID != nil {
		id := int64(*s.PolicyID)
		out.PolicyId = &id
	}
	if s.RustdeskID != "" {
		rid := s.RustdeskID
		out.RustdeskId = &rid
	}
	revision := int64(s.Revision)
	out.Revision = &revision
	return out
}
