package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/access"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/audit"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// m5AccessService returns a writable access service on the harness database.
func m5AccessService(h *harness) *access.Service {
	return access.NewService(h.db.DB, audit.NewGormAuditor(h.db.DB), nil)
}

// clearAccessRules deletes every access rule of the organization, which both
// tightens a migrated organization (removing the everyone default rule) and
// removes an explicit grant.
func clearAccessRules(t *testing.T, svc *access.Service, orgID int64) {
	t.Helper()
	ctx := context.Background()
	views, err := svc.ListAccessRules(ctx, uint(orgID))
	require.NoError(t, err)
	for _, view := range views {
		require.NoError(t, svc.DeleteAccessRule(ctx, uint(orgID), 1, view.Rule.ID))
	}
}

// grantDeviceToMember creates one user group holding the member and one device
// group holding the device, then the allow rule between them.
func grantDeviceToMember(t *testing.T, svc *access.Service, orgID int64, memberID uint, deviceID uint) {
	t.Helper()
	ctx := context.Background()
	org := uint(orgID)
	group, err := svc.CreateUserGroup(ctx, org, 1, "ticket-team")
	require.NoError(t, err)
	_, _, err = svc.ReplaceUserGroupMembers(ctx, org, 1, group.ID, []uint{memberID})
	require.NoError(t, err)
	target, err := svc.CreateDeviceGroup(ctx, org, 1, "ticket-targets")
	require.NoError(t, err)
	_, _, err = svc.ReplaceDeviceGroupDevices(ctx, org, 1, target.ID, []uint{deviceID})
	require.NoError(t, err)
	_, err = svc.CreateAccessRule(ctx, org, 1, group.ID, model.AccessTargetKindDeviceGroup, target.ID)
	require.NoError(t, err)
}

// auditRowsByAction loads the audit rows of one action.
func auditRowsByAction(t *testing.T, h *harness, action string) []model.AuditLog {
	t.Helper()
	var rows []model.AuditLog
	require.NoError(t, store.WithoutTenantScope(h.db.DB).Model(&model.AuditLog{}).
		Where("action = ?", action).Order("id").Find(&rows).Error)
	return rows
}

func decodeErrorCode(t *testing.T, body []byte) string {
	t.Helper()
	var envelope struct {
		Code string `json:"code"`
	}
	require.NoError(t, json.Unmarshal(body, &envelope))
	return envelope.Code
}

// TestAccess_IssueTicketDeniedByRules pins the issuance gate: a member whose
// groups hold no rule covering the device gets an opaque 404 instead of a
// ticket, and exactly one session.ticket.denied audit row replaces the HTTP
// fallback row.
func TestAccess_IssueTicketDeniedByRules(t *testing.T) {
	h, orgID, _, _, member, _, _, memberToken := m4Org(t)
	svc := m5AccessService(h)
	clearAccessRules(t, svc, orgID)
	dev := seedDevice(t, h, orgID, "200000001")

	w := h.do(t, http.MethodPost, "/api/v1/orgs/"+itoa(orgID)+"/tickets",
		map[string]any{"device_id": dev.ID}, memberToken)
	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())
	require.Equal(t, "not_found", decodeErrorCode(t, w.Body.Bytes()),
		"the refusal must not reveal that the device exists")

	var tickets int64
	require.NoError(t, store.WithoutTenantScope(h.db.DB).Model(&model.Ticket{}).Count(&tickets).Error)
	require.Zero(t, tickets, "a denied issuance must not persist a ticket")

	denied := auditRowsByAction(t, h, "session.ticket.denied")
	require.Len(t, denied, 1, "the refusal must be audited exactly once")
	require.Equal(t, member.ID, denied[0].ActorUserID)
	require.Equal(t, orgID, int64(denied[0].OrganizationID))
	require.Equal(t, "device", denied[0].TargetType)
	require.Equal(t, fmt.Sprint(dev.ID), denied[0].TargetID)
	require.Contains(t, denied[0].Detail, `"reason":"access_control"`)
	require.Contains(t, denied[0].Detail, `"stage":"issue"`)

	var fallback int64
	require.NoError(t, store.WithoutTenantScope(h.db.DB).Model(&model.AuditLog{}).
		Where("action = ?", "POST /api/v1/orgs/:orgId/tickets").Count(&fallback).Error)
	require.Zero(t, fallback, "the domain denial row must replace the http fallback row")

	// The refusal must not manufacture the side effects of a policy denial: no
	// denied session and no outside_window alert.
	var sessions, alerts int64
	require.NoError(t, store.WithoutTenantScope(h.db.DB).Model(&model.Session{}).Count(&sessions).Error)
	require.NoError(t, store.WithoutTenantScope(h.db.DB).Model(&model.Alert{}).Count(&alerts).Error)
	require.Zero(t, sessions)
	require.Zero(t, alerts)
}

// TestAccess_AdminIssuesAnyDevice pins the D7 bypass on the ticket path: an
// admin of a tightened organization can still issue a ticket for an ungrouped
// device.
func TestAccess_AdminIssuesAnyDevice(t *testing.T) {
	h, orgID, _, _, _, _, adminToken, _ := m4Org(t)
	svc := m5AccessService(h)
	clearAccessRules(t, svc, orgID)
	dev := seedDevice(t, h, orgID, "200000002")

	w := h.do(t, http.MethodPost, "/api/v1/orgs/"+itoa(orgID)+"/tickets",
		map[string]any{"device_id": dev.ID}, adminToken)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())

	var issued issuedBody
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &issued))
	require.NotEmpty(t, issued.Data.Token)
}

// TestAccess_RedeemRejectsAfterRuleRemoved pins Review Focus #4: a ticket
// issued while the member had access must be refused at redemption once the
// grant is gone; the refusal is audited and leaves the ticket unused.
func TestAccess_RedeemRejectsAfterRuleRemoved(t *testing.T) {
	h, orgID, _, _, member, _, _, memberToken := m4Org(t)
	svc := m5AccessService(h)
	clearAccessRules(t, svc, orgID)
	dev := seedDevice(t, h, orgID, "200000003")
	grantDeviceToMember(t, svc, orgID, member.ID, dev.ID)

	w := h.do(t, http.MethodPost, "/api/v1/orgs/"+itoa(orgID)+"/tickets",
		map[string]any{"device_id": dev.ID}, memberToken)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var issued issuedBody
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &issued))

	clearAccessRules(t, svc, orgID)

	w = h.do(t, http.MethodPost, ticketPath(orgID, issued.Data.Ticket.Id)+"/redeem",
		map[string]any{"token": issued.Data.Token}, memberToken)
	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())
	require.Equal(t, "not_found", decodeErrorCode(t, w.Body.Bytes()))

	denied := auditRowsByAction(t, h, "session.ticket.denied")
	require.Len(t, denied, 1)
	require.Equal(t, member.ID, denied[0].ActorUserID)
	require.Equal(t, orgID, int64(denied[0].OrganizationID))
	require.Equal(t, "device", denied[0].TargetType)
	require.Equal(t, fmt.Sprint(dev.ID), denied[0].TargetID)
	require.Contains(t, denied[0].Detail, `"reason":"access_control"`)
	require.Contains(t, denied[0].Detail, `"stage":"redeem"`)
	require.Contains(t, denied[0].Detail, fmt.Sprintf(`"ticket_id":%d`, issued.Data.Ticket.Id))

	var fallback int64
	require.NoError(t, store.WithoutTenantScope(h.db.DB).Model(&model.AuditLog{}).
		Where("action = ?", "POST /api/v1/orgs/:orgId/tickets/:ticketId/redeem").Count(&fallback).Error)
	require.Zero(t, fallback, "the domain denial row must replace the http fallback row")

	var sessions int64
	require.NoError(t, store.WithoutTenantScope(h.db.DB).Model(&model.Session{}).Count(&sessions).Error)
	require.Zero(t, sessions, "a refused redemption must not open a session")

	var ticket model.Ticket
	require.NoError(t, store.WithoutTenantScope(h.db.DB).First(&ticket, issued.Data.Ticket.Id).Error)
	require.Nil(t, ticket.UsedAt, "the refused redemption must not consume the ticket")
}

// TestAccess_RedeemJudgedByRedeemer pins D9: redemption is judged against the
// redeemer, not the issuer. The issuer keeps access, a second member without a
// rule cannot redeem the same ticket, and the issuer still can afterwards.
func TestAccess_RedeemJudgedByRedeemer(t *testing.T) {
	h, orgID, _, _, member, _, _, memberToken := m4Org(t)
	svc := m5AccessService(h)
	clearAccessRules(t, svc, orgID)
	dev := seedDevice(t, h, orgID, "200000004")
	grantDeviceToMember(t, svc, orgID, member.ID, dev.ID)
	otherToken := seedOrgMember(t, h, orgID, "m5-ticket-redeemer@example.com")

	w := h.do(t, http.MethodPost, "/api/v1/orgs/"+itoa(orgID)+"/tickets",
		map[string]any{"device_id": dev.ID}, memberToken)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var issued issuedBody
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &issued))

	w = h.do(t, http.MethodPost, ticketPath(orgID, issued.Data.Ticket.Id)+"/redeem",
		map[string]any{"token": issued.Data.Token}, otherToken)
	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())

	w = h.do(t, http.MethodPost, ticketPath(orgID, issued.Data.Ticket.Id)+"/redeem",
		map[string]any{"token": issued.Data.Token}, memberToken)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String(),
		"the refused redeemer must not consume the ticket")
}

// TestAccess_PreApprovalCannotBypassRules pins the design: an approval flow is
// still subject to access rules. With require_approval set, a member without a
// covering rule gets the access 404 (not approval_required) and no approval row
// is created.
func TestAccess_PreApprovalCannotBypassRules(t *testing.T) {
	h, orgID, _, _, _, _, _, memberToken := m4Org(t)
	svc := m5AccessService(h)
	clearAccessRules(t, svc, orgID)
	seedPolicy(t, h, orgID, func(p *model.Policy) {
		p.RequireApproval = true
	})
	dev := seedDevice(t, h, orgID, "200000005")

	w := h.do(t, http.MethodPost, "/api/v1/orgs/"+itoa(orgID)+"/tickets",
		map[string]any{"device_id": dev.ID}, memberToken)
	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())
	require.Equal(t, "not_found", decodeErrorCode(t, w.Body.Bytes()))

	var approvals int64
	require.NoError(t, store.WithoutTenantScope(h.db.DB).Model(&model.Approval{}).Count(&approvals).Error)
	require.Zero(t, approvals, "the access gate must run before the approval flow")
}

// TestAccess_RedeemDisabledDeviceKeepsConflictAndAudits pins the branch that
// preserves the M4 contract: a ticket issued before an administrator stopped
// the device is refused as a 409 with the opaque conflict message, the refusal
// is audited as device_disabled (not access_control), and the ticket is unused.
func TestAccess_RedeemDisabledDeviceKeepsConflictAndAudits(t *testing.T) {
	h, orgID, _, _, member, _, _, memberToken := m4Org(t)
	dev := seedDevice(t, h, orgID, "200000006")

	w := h.do(t, http.MethodPost, "/api/v1/orgs/"+itoa(orgID)+"/tickets",
		map[string]any{"device_id": dev.ID}, memberToken)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var issued issuedBody
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &issued))

	require.NoError(t, store.ScopedByOrg(h.db.DB, uint(orgID)).Model(&model.Device{}).
		Where("id = ?", dev.ID).Update("disabled", true).Error)

	w = h.do(t, http.MethodPost, ticketPath(orgID, issued.Data.Ticket.Id)+"/redeem",
		map[string]any{"token": issued.Data.Token}, memberToken)
	require.Equal(t, http.StatusConflict, w.Code, w.Body.String())
	require.Equal(t, "conflict", decodeErrorCode(t, w.Body.Bytes()))
	require.NotContains(t, w.Body.String(), "disabled", "the refusal must not echo the device state")

	denied := auditRowsByAction(t, h, "session.ticket.denied")
	require.Len(t, denied, 1)
	require.Equal(t, member.ID, denied[0].ActorUserID)
	require.Contains(t, denied[0].Detail, `"reason":"device_disabled"`)
	require.Contains(t, denied[0].Detail, `"stage":"redeem"`)
	require.Contains(t, denied[0].Detail, fmt.Sprintf(`"ticket_id":%d`, issued.Data.Ticket.Id))

	var sessions int64
	require.NoError(t, store.WithoutTenantScope(h.db.DB).Model(&model.Session{}).Count(&sessions).Error)
	require.Zero(t, sessions)

	var ticket model.Ticket
	require.NoError(t, store.WithoutTenantScope(h.db.DB).First(&ticket, issued.Data.Ticket.Id).Error)
	require.Nil(t, ticket.UsedAt, "a refused redemption must not consume the ticket")
}
