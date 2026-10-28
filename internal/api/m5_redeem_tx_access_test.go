package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/api"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/audit"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/session"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// denyAccessTx is the evaluator the session service consults inside the
// redemption transaction. Wiring it lets a test reach the re-check while the
// handler's own pre-check (deps.Access) still allows: the two decisions are
// independent on purpose, and the in-transaction one is the authority.
type denyAccessTx struct{}

func (denyAccessTx) CanAccessTx(*gorm.DB, uint, uint, uint) (bool, error) {
	return false, nil
}

// TestAccess_RedeemTxRecheckDenialMapsToNotFound covers the route the handler
// takes when its own pre-check passed but the redemption refuses: the response
// must be the same opaque 404 as a pre-check denial, audited exactly once, with
// the ticket left unused.
func TestAccess_RedeemTxRecheckDenialMapsToNotFound(t *testing.T) {
	h, orgID, _, _, member, _, _, memberToken := m4OrgWith(t, func(d *api.Deps) {
		d.Tickets = session.NewService(d.DB, audit.NewGormAuditor(d.DB), time.Now).
			WithAccess(denyAccessTx{})
	})
	svc := m5AccessService(h)
	clearAccessRules(t, svc, orgID)
	dev := seedDevice(t, h, orgID, "200000010")
	grantDeviceToMember(t, svc, orgID, member.ID, dev.ID)

	w := h.do(t, http.MethodPost, "/api/v1/orgs/"+itoa(orgID)+"/tickets",
		map[string]any{"device_id": dev.ID}, memberToken)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var issued issuedBody
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &issued))

	w = h.do(t, http.MethodPost, ticketPath(orgID, issued.Data.Ticket.Id)+"/redeem",
		map[string]any{"token": issued.Data.Token}, memberToken)
	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())
	require.Equal(t, "not_found", decodeErrorCode(t, w.Body.Bytes()))

	denied := auditRowsByAction(t, h, "session.ticket.denied")
	require.Len(t, denied, 1, "the in-transaction refusal must be audited exactly once")
	require.Contains(t, denied[0].Detail, `"reason":"access_control"`)
	require.Contains(t, denied[0].Detail, `"stage":"redeem"`)
	require.Contains(t, denied[0].Detail, fmtTicketID(issued.Data.Ticket.Id))

	var fallback int64
	require.NoError(t, store.WithoutTenantScope(h.db.DB).Model(&model.AuditLog{}).
		Where("action = ?", "POST /api/v1/orgs/:orgId/tickets/:ticketId/redeem").Count(&fallback).Error)
	require.Zero(t, fallback, "the domain denial row must replace the http fallback row")

	var stored model.Ticket
	require.NoError(t, store.WithoutTenantScope(h.db.DB).First(&stored, issued.Data.Ticket.Id).Error)
	require.Nil(t, stored.UsedAt, "the refused redemption must not consume the ticket")

	var sessions int64
	require.NoError(t, store.WithoutTenantScope(h.db.DB).Model(&model.Session{}).Count(&sessions).Error)
	require.Zero(t, sessions, "a refused redemption must not open a session")
}

// TestAccess_RedeemServiceRechecksCommittedRules drives Redeem directly with the
// real access service: the handler's pre-check is deliberately skipped, so the
// only thing that can refuse the second redemption is the re-check inside the
// transaction. The first redemption proves the evaluator is not simply always
// denying.
func TestAccess_RedeemServiceRechecksCommittedRules(t *testing.T) {
	h, orgID, _, _, member, _, _, _ := m4Org(t)
	svc := m5AccessService(h)
	clearAccessRules(t, svc, orgID)
	dev := seedDevice(t, h, orgID, "200000011")
	grantDeviceToMember(t, svc, orgID, member.ID, dev.ID)

	tickets := session.NewService(h.db.DB, audit.NewGormAuditor(h.db.DB), time.Now).WithAccess(svc)
	ctx := context.Background()

	allowed, allowedToken, err := tickets.Issue(ctx, session.IssueInput{
		OrganizationID: uint(orgID), ActorUserID: member.ID, DeviceID: dev.ID,
	})
	require.NoError(t, err)
	sess, err := tickets.Redeem(ctx, uint(orgID), member.ID, allowed.ID, allowedToken)
	require.NoError(t, err, "access is still granted, so the re-check must allow")
	require.Equal(t, dev.ID, sess.DeviceID)

	clearAccessRules(t, svc, orgID)

	late, lateToken, err := tickets.Issue(ctx, session.IssueInput{
		OrganizationID: uint(orgID), ActorUserID: member.ID, DeviceID: dev.ID,
	})
	require.NoError(t, err)
	_, err = tickets.Redeem(ctx, uint(orgID), member.ID, late.ID, lateToken)
	require.ErrorIs(t, err, session.ErrAccessDenied,
		"the revocation committed before the redemption, so the in-transaction re-check must refuse")

	var stored model.Ticket
	require.NoError(t, store.WithoutTenantScope(h.db.DB).First(&stored, late.ID).Error)
	require.Nil(t, stored.UsedAt, "the refused redemption must not consume the ticket")
}

func fmtTicketID(id int64) string {
	return `"ticket_id":` + itoa(id)
}
