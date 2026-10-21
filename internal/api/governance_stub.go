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
//   - tickets: issueTicket (T4)
//   - policies and session records: list/CRUD (T5)
//   - approvals: list/create/decide (T6)
//   - alerts: list (T7)
//
// They answer 501 so a client generated from the contract fails loudly instead
// of assuming the feature exists. Shipping this state is safe only because the
// endpoints are new: no existing behaviour changes.

// notImplemented aborts with 501 and the standard error envelope.
func notImplemented(c *gin.Context, feature string) {
	abortError(c, http.StatusNotImplemented, gen.ErrorCodeInternal,
		"not implemented yet: "+feature+" ships with the M3 session-governance tasks")
}

// ListSessions implements gen.ServerInterface (stub, T5).
func (a *AdminAPI) ListSessions(c *gin.Context, orgId int64, params gen.ListSessionsParams) {
	notImplemented(c, "session records")
}

// GetSession implements gen.ServerInterface (stub, T5).
func (a *AdminAPI) GetSession(c *gin.Context, orgId int64, sessionId int64) {
	notImplemented(c, "session records")
}

// ListPolicies implements gen.ServerInterface (stub, T5).
func (a *AdminAPI) ListPolicies(c *gin.Context, orgId int64) {
	notImplemented(c, "connection policies")
}

// CreatePolicy implements gen.ServerInterface (stub, T5).
func (a *AdminAPI) CreatePolicy(c *gin.Context, orgId int64) {
	notImplemented(c, "connection policies")
}

// UpdatePolicy implements gen.ServerInterface (stub, T5).
func (a *AdminAPI) UpdatePolicy(c *gin.Context, orgId int64, policyId int64) {
	notImplemented(c, "connection policies")
}

// DeletePolicy implements gen.ServerInterface (stub, T5).
func (a *AdminAPI) DeletePolicy(c *gin.Context, orgId int64, policyId int64) {
	notImplemented(c, "connection policies")
}

// ListApprovals implements gen.ServerInterface (stub, T6).
func (a *AdminAPI) ListApprovals(c *gin.Context, orgId int64, params gen.ListApprovalsParams) {
	notImplemented(c, "approvals")
}

// CreateApproval implements gen.ServerInterface (stub, T6).
func (a *AdminAPI) CreateApproval(c *gin.Context, orgId int64) {
	notImplemented(c, "approvals")
}

// DecideApproval implements gen.ServerInterface (stub, T6).
func (a *AdminAPI) DecideApproval(c *gin.Context, orgId int64, approvalId int64) {
	notImplemented(c, "approvals")
}

// IssueTicket implements gen.ServerInterface (stub, T4).
func (a *AdminAPI) IssueTicket(c *gin.Context, orgId int64) {
	notImplemented(c, "connection tickets")
}

// ListAlerts implements gen.ServerInterface (stub, T7).
func (a *AdminAPI) ListAlerts(c *gin.Context, orgId int64, params gen.ListAlertsParams) {
	notImplemented(c, "alerts")
}
