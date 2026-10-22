package api

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/GogoYang0/rustdesk-control-panel-api/gen"
)

// This file holds the placeholder handlers for the session-governance endpoints
// introduced with contract v0.4.0. The contract is the source of truth for the
// series (C1), so it lands together with the generated types before the
// implementations do; the handlers below keep gen.ServerInterface satisfied
// until the owning M3 tasks replace them:
//
//   - tickets: issueTicket / getTicket / redeemTicket (T4)
//   - policies and session records: list/CRUD (T5)
//   - approvals: list/get/create/decide (T6)
//   - alerts: list (T7)
//
// They answer 501 so a client generated from the contract fails loudly instead
// of assuming the feature exists. Shipping this state is safe only because the
// endpoints are new: no existing behaviour changes.
//
// The placeholder still resolves the caller's membership before answering. The
// tenant boundary is the one property that must never silently regress, and
// pinning it here means a handler that forgets its permission check fails a
// test that already exists. Per-operation permissions (read for members, write
// for owner/admin) are added by the task that implements each handler.

// notImplemented aborts with 501 and the standard error envelope.
func notImplemented(c *gin.Context, feature string) {
	abortError(c, http.StatusNotImplemented, gen.ErrorCodeInternal,
		"not implemented yet: "+feature)
}

// stubMembership enforces the shared tenant boundary for a placeholder handler,
// then answers 501. Every path terminates: the caller never continues.
func (a *AdminAPI) stubMembership(c *gin.Context, orgID int64, feature string) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	if orgID <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid organization id")
		return
	}
	if _, ok := a.membershipFor(c, uid, uint(orgID)); !ok {
		return
	}
	notImplemented(c, feature)
}

// ListSessions implements gen.ServerInterface (stub, T5).
func (a *AdminAPI) ListSessions(c *gin.Context, orgId int64, params gen.ListSessionsParams) {
	a.stubMembership(c, orgId, "session records")
}

// GetSession implements gen.ServerInterface (stub, T5).
func (a *AdminAPI) GetSession(c *gin.Context, orgId int64, sessionId int64) {
	a.stubMembership(c, orgId, "session records")
}

// ListPolicies implements gen.ServerInterface (stub, T5).
func (a *AdminAPI) ListPolicies(c *gin.Context, orgId int64) {
	a.stubMembership(c, orgId, "connection policies")
}

// CreatePolicy implements gen.ServerInterface (stub, T5).
func (a *AdminAPI) CreatePolicy(c *gin.Context, orgId int64) {
	a.stubMembership(c, orgId, "connection policies")
}

// UpdatePolicy implements gen.ServerInterface (stub, T5).
func (a *AdminAPI) UpdatePolicy(c *gin.Context, orgId int64, policyId int64) {
	a.stubMembership(c, orgId, "connection policies")
}

// DeletePolicy implements gen.ServerInterface (stub, T5).
func (a *AdminAPI) DeletePolicy(c *gin.Context, orgId int64, policyId int64) {
	a.stubMembership(c, orgId, "connection policies")
}

// ListApprovals implements gen.ServerInterface (stub, T6).
func (a *AdminAPI) ListApprovals(c *gin.Context, orgId int64, params gen.ListApprovalsParams) {
	a.stubMembership(c, orgId, "approvals")
}

// GetApproval implements gen.ServerInterface (stub, T6).
func (a *AdminAPI) GetApproval(c *gin.Context, orgId int64, approvalId int64) {
	a.stubMembership(c, orgId, "approvals")
}

// CreateApproval implements gen.ServerInterface (stub, T6).
func (a *AdminAPI) CreateApproval(c *gin.Context, orgId int64) {
	a.stubMembership(c, orgId, "approvals")
}

// DecideApproval implements gen.ServerInterface (stub, T6).
func (a *AdminAPI) DecideApproval(c *gin.Context, orgId int64, approvalId int64) {
	a.stubMembership(c, orgId, "approvals")
}

// ListAlerts implements gen.ServerInterface (stub, T7).
func (a *AdminAPI) ListAlerts(c *gin.Context, orgId int64, params gen.ListAlertsParams) {
	a.stubMembership(c, orgId, "alerts")
}
