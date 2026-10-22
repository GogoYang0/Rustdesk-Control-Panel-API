package api_test

import (
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/api"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// fixedNow is the clock every ticket test runs on: window policies are expressed
// in UTC minutes, so an unfixed clock would make them time-of-day dependent.
var fixedNow = time.Date(2026, 10, 22, 10, 0, 0, 0, time.UTC)

func newTicketHarness(t *testing.T) *harness {
	t.Helper()
	return newHarnessWith(t, func(d *api.Deps) {
		d.Now = func() time.Time { return fixedNow }
	})
}

func seedDevice(t *testing.T, h *harness, orgID int64, rustdeskID string) model.Device {
	t.Helper()
	dev := model.Device{OrganizationID: uint(orgID), RustdeskID: rustdeskID, Name: "dev-" + rustdeskID}
	require.NoError(t, h.db.DB.Create(&dev).Error)
	return dev
}

func seedPolicy(t *testing.T, h *harness, orgID int64, mutate func(*model.Policy)) model.Policy {
	t.Helper()
	p := model.Policy{OrganizationID: uint(orgID), Name: "policy", Enabled: true}
	if mutate != nil {
		mutate(&p)
	}
	require.NoError(t, h.db.DB.Create(&p).Error)
	return p
}

func ticketPath(orgID, ticketID int64) string {
	return "/api/v1/orgs/" + strconv.FormatInt(orgID, 10) + "/tickets/" + strconv.FormatInt(ticketID, 10)
}

type issuedBody struct {
	Code string `json:"code"`
	Data struct {
		Ticket struct {
			Id        int64  `json:"id"`
			DeviceId  int64  `json:"device_id"`
			ExpiresAt string `json:"expires_at"`
			UsedAt    string `json:"used_at"`
		} `json:"ticket"`
		Token string `json:"token"`
	} `json:"data"`
}

// The happy path: issue returns the plaintext once, get never returns it, and
// redeem produces the panel session.
func TestTicket_IssueRedeemGet(t *testing.T) {
	h := newTicketHarness(t)
	token, orgID := seedOrgOwner(t, h, "ticket-ok@example.com")
	dev := seedDevice(t, h, orgID, "100000001")

	w := h.do(t, http.MethodPost, "/api/v1/orgs/"+strconv.FormatInt(orgID, 10)+"/tickets",
		map[string]any{"device_id": dev.ID}, token)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())

	var issued issuedBody
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &issued))
	require.Equal(t, "ok", issued.Code)
	require.NotEmpty(t, issued.Data.Token, "the plaintext token is returned once")
	require.Equal(t, dev.ID, uint(issued.Data.Ticket.DeviceId))
	require.Empty(t, issued.Data.Ticket.UsedAt)

	// The bookkeeping view must not leak the token.
	w = h.do(t, http.MethodGet, ticketPath(orgID, issued.Data.Ticket.Id), nil, token)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.NotContains(t, w.Body.String(), issued.Data.Token)
	require.NotContains(t, w.Body.String(), "token")

	w = h.do(t, http.MethodPost, ticketPath(orgID, issued.Data.Ticket.Id)+"/redeem",
		map[string]any{"token": issued.Data.Token}, token)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())

	var redeemed struct {
		Data struct {
			Id       int64  `json:"id"`
			Origin   string `json:"origin"`
			Status   string `json:"status"`
			TicketId int64  `json:"ticket_id"`
			DeviceId int64  `json:"device_id"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &redeemed))
	require.Equal(t, "panel", redeemed.Data.Origin)
	require.Equal(t, "open", redeemed.Data.Status)
	require.Equal(t, issued.Data.Ticket.Id, redeemed.Data.TicketId)
	require.Equal(t, dev.ID, uint(redeemed.Data.DeviceId))

	// Second redemption is a 409 and stays opaque about the reason.
	w = h.do(t, http.MethodPost, ticketPath(orgID, issued.Data.Ticket.Id)+"/redeem",
		map[string]any{"token": issued.Data.Token}, token)
	require.Equal(t, http.StatusConflict, w.Code, w.Body.String())

	var errBody struct {
		Code string `json:"code"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &errBody))
	require.Equal(t, "conflict", errBody.Code)
}

func TestTicket_RequiresMembership(t *testing.T) {
	h := newTicketHarness(t)
	_, orgA := seedOrgOwner(t, h, "ticket-a@example.com")
	outsider, orgB := seedOrgOwner(t, h, "ticket-b@example.com")
	dev := seedDevice(t, h, orgA, "100000002")

	w := h.do(t, http.MethodPost, "/api/v1/orgs/"+strconv.FormatInt(orgA, 10)+"/tickets",
		map[string]any{"device_id": dev.ID}, outsider)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

	// A member of the organization reaches the handler (the device belongs to
	// orgA, so orgB's caller cannot use it even in their own organization).
	_ = orgB
	w = h.do(t, http.MethodGet, ticketPath(orgA, 1), nil, outsider)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
}

func TestTicket_IssueValidatesInput(t *testing.T) {
	h := newTicketHarness(t)
	token, orgID := seedOrgOwner(t, h, "ticket-input@example.com")
	path := "/api/v1/orgs/" + strconv.FormatInt(orgID, 10) + "/tickets"

	w := h.do(t, http.MethodPost, path, map[string]any{}, token)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())

	dev := seedDevice(t, h, orgID, "100000003")
	ttl := int64(5)
	w = h.do(t, http.MethodPost, path, map[string]any{"device_id": dev.ID, "ttl_seconds": ttl}, token)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())

	// A device from another organization is not found, not forbidden: the
	// caller has no way to tell an existing foreign id from a missing one.
	_, otherOrg := seedOrgOwner(t, h, "ticket-other@example.com")
	foreign := seedDevice(t, h, otherOrg, "100000004")
	w = h.do(t, http.MethodPost, path, map[string]any{"device_id": foreign.ID}, token)
	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())
}

// Outside the window issuance is a 409 *and* leaves a denied session row, so the
// refusal is recorded rather than merely answered.
func TestTicket_OutsideWindowIsConflictAndRecorded(t *testing.T) {
	// 03:00 UTC is outside the 09:00-17:00 window below.
	h := newHarnessWith(t, func(d *api.Deps) {
		d.Now = func() time.Time { return time.Date(2026, 10, 22, 3, 0, 0, 0, time.UTC) }
	})
	token, orgID := seedOrgOwner(t, h, "ticket-window@example.com")
	seedPolicy(t, h, orgID, func(p *model.Policy) {
		start, end := int64(540), int64(1020)
		p.AllowedStartMinute, p.AllowedEndMinute = &start, &end
	})
	dev := seedDevice(t, h, orgID, "100000005")

	w := h.do(t, http.MethodPost, "/api/v1/orgs/"+strconv.FormatInt(orgID, 10)+"/tickets",
		map[string]any{"device_id": dev.ID}, token)
	require.Equal(t, http.StatusConflict, w.Code, w.Body.String())

	var denied []model.Session
	require.NoError(t, store.WithoutTenantScope(h.db.DB).Find(&denied).Error)
	require.Len(t, denied, 1)
	require.Equal(t, model.SessionStatusDenied, denied[0].Status)
	require.NotNil(t, denied[0].EndReason)
	require.Equal(t, model.SessionEndPolicyDenied, *denied[0].EndReason)
}

// A policy that demands approval answers 409 approval_required with the id of
// the request the user has to act on — a distinct code, because the client is
// supposed to route to the inbox and retry rather than show a failure.
func TestTicket_ApprovalRequiredCarriesApprovalID(t *testing.T) {
	h := newTicketHarness(t)
	token, orgID := seedOrgOwner(t, h, "ticket-approval@example.com")
	seedPolicy(t, h, orgID, func(p *model.Policy) { p.RequireApproval = true })
	dev := seedDevice(t, h, orgID, "100000006")

	w := h.do(t, http.MethodPost, "/api/v1/orgs/"+strconv.FormatInt(orgID, 10)+"/tickets",
		map[string]any{"device_id": dev.ID}, token)
	require.Equal(t, http.StatusConflict, w.Code, w.Body.String())

	var body struct {
		Code string `json:"code"`
		Data struct {
			ApprovalId int64 `json:"approval_id"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	require.Equal(t, "approval_required", body.Code)
	require.NotZero(t, body.Data.ApprovalId, "the client needs the id to route the user")
}

func TestTicket_GetUnknownIsNotFound(t *testing.T) {
	h := newTicketHarness(t)
	token, orgID := seedOrgOwner(t, h, "ticket-404@example.com")

	w := h.do(t, http.MethodGet, ticketPath(orgID, 9999), nil, token)
	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())
}

// A wrong token is indistinguishable from an expired or used one.
func TestTicket_RedeemWrongTokenIsConflict(t *testing.T) {
	h := newTicketHarness(t)
	token, orgID := seedOrgOwner(t, h, "ticket-wrong@example.com")
	dev := seedDevice(t, h, orgID, "100000007")

	w := h.do(t, http.MethodPost, "/api/v1/orgs/"+strconv.FormatInt(orgID, 10)+"/tickets",
		map[string]any{"device_id": dev.ID}, token)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var issued issuedBody
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &issued))

	w = h.do(t, http.MethodPost, ticketPath(orgID, issued.Data.Ticket.Id)+"/redeem",
		map[string]any{"token": "not-the-token"}, token)
	require.Equal(t, http.StatusConflict, w.Code, w.Body.String())

	// The ticket survives a failed attempt: it is still usable with the real
	// token, which is what "a refused redemption does not burn it" means.
	w = h.do(t, http.MethodPost, ticketPath(orgID, issued.Data.Ticket.Id)+"/redeem",
		map[string]any{"token": issued.Data.Token}, token)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
}
