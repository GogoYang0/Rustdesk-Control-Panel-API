package api_test

import (
	"encoding/json"
	"net/http"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/api"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

func approvalPath(orgID int64) string {
	return "/api/v1/orgs/" + strconv.FormatInt(orgID, 10) + "/approvals"
}

func approvalItemPath(orgID, approvalID int64) string {
	return approvalPath(orgID) + "/" + strconv.FormatInt(approvalID, 10)
}

func approvalDecisionPath(orgID, approvalID int64) string {
	return approvalItemPath(orgID, approvalID) + "/decision"
}

type approvalBody struct {
	Code string `json:"code"`
	Data struct {
		Id          int64   `json:"id"`
		DeviceId    int64   `json:"device_id"`
		Kind        string  `json:"kind"`
		Status      string  `json:"status"`
		SessionId   *int64  `json:"session_id"`
		ActorUserId int64   `json:"actor_user_id"`
		ExpiresAt   string  `json:"expires_at"`
		DecidedBy   *int64  `json:"decided_by"`
		DecidedAt   *string `json:"decided_at"`
		Reason      *string `json:"reason"`
		TicketId    *int64  `json:"ticket_id"`
	} `json:"data"`
}

// seedNativeSession inserts a native open session the ratification tests can
// point at.
func seedNativeSession(t *testing.T, h *harness, orgID, deviceID int64) int64 {
	t.Helper()
	dev := model.Device{}
	// Direct reads in tests bypass the request's tenant context, so they must
	// opt out of the tenant scope explicitly — the plugin fails closed (WHERE
	// 1 = 0) on scoped tables without one.
	require.NoError(t, store.WithoutTenantScope(h.db.DB).First(&dev, deviceID).Error)
	sess := model.Session{
		OrganizationID: uint(orgID),
		DeviceID:       uint(deviceID),
		RustdeskID:     dev.RustdeskID,
		Origin:         model.SessionOriginNative,
		Status:         model.SessionStatusOpen,
		StartedAt:      fixedNow,
	}
	require.NoError(t, store.WithoutTenantScope(h.db.DB).Create(&sess).Error)
	return int64(sess.ID)
}

// seedApproval inserts an approval row directly, so tests can pin statuses the
// API itself cannot produce.
func seedApproval(t *testing.T, h *harness, orgID, deviceID int64, status string) int64 {
	t.Helper()
	row := model.Approval{
		OrganizationID: uint(orgID),
		DeviceID:       uint(deviceID),
		Kind:           model.ApprovalKindPre,
		ActorUserID:    1,
		Status:         status,
		RequestedAt:    fixedNow,
		ExpiresAt:      fixedNow.Add(15 * 60 * 1e9),
	}
	require.NoError(t, store.WithoutTenantScope(h.db.DB).Create(&row).Error)
	return int64(row.ID)
}

// ── permissions ─────────────────────────────────────────────────────────────

// Reading and requesting are member-level; deciding is owner/admin only.
func TestApproval_PermissionMatrix(t *testing.T) {
	h := newTicketHarness(t)
	owner, orgID := seedOrgOwner(t, h, "approval-owner@example.com")
	member := seedOrgMember(t, h, orgID, "approval-member@example.com")
	admin := seedOrgAdmin(t, h, orgID, "approval-admin@example.com")
	dev := seedDevice(t, h, orgID, "100000010")

	// Member may read the (empty) inbox.
	w := h.do(t, http.MethodGet, approvalPath(orgID), nil, member)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	// Member may submit a request.
	w = h.do(t, http.MethodPost, approvalPath(orgID), map[string]any{
		"kind": "pre_approval", "device_id": dev.ID,
	}, member)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())

	// Member may read a single request.
	var created approvalBody
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &created))
	w = h.do(t, http.MethodGet, approvalItemPath(orgID, created.Data.Id), nil, member)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	// Member may not decide.
	w = h.do(t, http.MethodPost, approvalDecisionPath(orgID, created.Data.Id),
		map[string]any{"decision": "approve"}, member)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

	// Admin and owner may decide — each on their own request, since a decision
	// is one-shot.
	for _, tc := range []struct {
		name  string
		token string
	}{
		{"admin", admin},
		{"owner", owner},
	} {
		next := seedApproval(t, h, orgID, int64(dev.ID), model.ApprovalStatusPending)
		w = h.do(t, http.MethodPost, approvalDecisionPath(orgID, next),
			map[string]any{"decision": "approve"}, tc.token)
		require.Equal(t, http.StatusOK, w.Code, tc.name+": "+w.Body.String())
	}
}

// An outsider gets the same 404 as any other organization's resource.
func TestApproval_RequiresMembership(t *testing.T) {
	h := newTicketHarness(t)
	_, orgA := seedOrgOwner(t, h, "approval-a@example.com")
	outsider, orgB := seedOrgOwner(t, h, "approval-b@example.com")
	dev := seedDevice(t, h, orgB, "100000011")

	w := h.do(t, http.MethodPost, approvalPath(orgA), map[string]any{
		"kind": "pre_approval", "device_id": dev.ID,
	}, outsider)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

	w = h.do(t, http.MethodGet, approvalPath(orgA), nil, outsider)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
}

// ── creation ────────────────────────────────────────────────────────────────

// The contract's create validation: the kind decides which id is allowed, and
// anything else is a 400.
func TestApproval_CreateValidation(t *testing.T) {
	h := newTicketHarness(t)
	owner, orgID := seedOrgOwner(t, h, "approval-valid@example.com")
	dev := seedDevice(t, h, orgID, "100000012")

	cases := []struct {
		name string
		body map[string]any
	}{
		{"no kind", map[string]any{"device_id": dev.ID}},
		{"unknown kind", map[string]any{"kind": "magic", "device_id": dev.ID}},
		{"pre without device", map[string]any{"kind": "pre_approval"}},
		{"pre with session", map[string]any{"kind": "pre_approval", "device_id": dev.ID, "session_id": 1}},
		{"ratification without session", map[string]any{"kind": "ratification"}},
		{"ratification with device", map[string]any{"kind": "ratification", "session_id": 1, "device_id": dev.ID}},
		{"neither id", map[string]any{"kind": "ratification"}},
	}
	for _, tc := range cases {
		w := h.do(t, http.MethodPost, approvalPath(orgID), tc.body, owner)
		require.Equal(t, http.StatusBadRequest, w.Code, tc.name+": "+w.Body.String())
	}
}

// A pending pre-approval is reused on retry with a 200; a fresh one is 201.
func TestApproval_CreateReuse(t *testing.T) {
	h := newTicketHarness(t)
	owner, orgID := seedOrgOwner(t, h, "approval-reuse@example.com")
	dev := seedDevice(t, h, orgID, "100000013")

	w := h.do(t, http.MethodPost, approvalPath(orgID), map[string]any{
		"kind": "pre_approval", "device_id": dev.ID, "reason": "need access",
	}, owner)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var first approvalBody
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &first))
	require.Equal(t, "pending", first.Data.Status)
	require.NotNil(t, first.Data.Reason)
	require.Equal(t, "need access", *first.Data.Reason)

	w = h.do(t, http.MethodPost, approvalPath(orgID), map[string]any{
		"kind": "pre_approval", "device_id": dev.ID,
	}, owner)
	require.Equal(t, http.StatusOK, w.Code, "the pending request is reused with 200")
	var second approvalBody
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &second))
	require.Equal(t, first.Data.Id, second.Data.Id, "same row, no duplicate")
}

// A ratification request derives the device from the session and never issues
// a ticket.
func TestApproval_RatificationViaAPI(t *testing.T) {
	h := newTicketHarness(t)
	owner, orgID := seedOrgOwner(t, h, "approval-ratify@example.com")
	admin := seedOrgAdmin(t, h, orgID, "approval-ratify-admin@example.com")
	dev := seedDevice(t, h, orgID, "100000014")
	sessionID := seedNativeSession(t, h, orgID, int64(dev.ID))

	w := h.do(t, http.MethodPost, approvalPath(orgID), map[string]any{
		"kind": "ratification", "session_id": sessionID,
	}, owner)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var created approvalBody
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &created))
	require.Equal(t, "ratification", created.Data.Kind)
	require.NotNil(t, created.Data.SessionId)
	require.Equal(t, sessionID, *created.Data.SessionId)
	require.Equal(t, int64(dev.ID), created.Data.DeviceId, "device derived server-side")
	require.Nil(t, created.Data.TicketId)

	// A second submitter reuses the same request with 200.
	w = h.do(t, http.MethodPost, approvalPath(orgID), map[string]any{
		"kind": "ratification", "session_id": sessionID,
	}, admin)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var reused approvalBody
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &reused))
	require.Equal(t, created.Data.Id, reused.Data.Id)

	// Approving the ratification acknowledges the fact without a ticket.
	w = h.do(t, http.MethodPost, approvalDecisionPath(orgID, created.Data.Id),
		map[string]any{"decision": "approve"}, admin)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var decided approvalBody
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &decided))
	require.Equal(t, "approved", decided.Data.Status)
	require.NotNil(t, decided.Data.DecidedBy)
	require.Nil(t, decided.Data.TicketId, "a ratification never gets a ticket")
}

// A panel-origin session is not ratifiable: 400.
func TestApproval_RatificationRejectsPanelSession(t *testing.T) {
	h := newTicketHarness(t)
	owner, orgID := seedOrgOwner(t, h, "approval-panel@example.com")
	dev := seedDevice(t, h, orgID, "100000015")
	sess := model.Session{
		OrganizationID: uint(orgID),
		DeviceID:       dev.ID,
		RustdeskID:     dev.RustdeskID,
		Origin:         model.SessionOriginPanel,
		Status:         model.SessionStatusOpen,
		StartedAt:      fixedNow,
	}
	require.NoError(t, store.WithoutTenantScope(h.db.DB).Create(&sess).Error)

	w := h.do(t, http.MethodPost, approvalPath(orgID), map[string]any{
		"kind": "ratification", "session_id": sess.ID,
	}, owner)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
}

// ── decisions ───────────────────────────────────────────────────────────────

func TestApproval_DecideFlow(t *testing.T) {
	h := newTicketHarness(t)
	owner, orgID := seedOrgOwner(t, h, "approval-decide@example.com")
	dev := seedDevice(t, h, orgID, "100000016")
	approvalID := seedApproval(t, h, orgID, int64(dev.ID), model.ApprovalStatusPending)

	// Unknown decision value is a 400.
	w := h.do(t, http.MethodPost, approvalDecisionPath(orgID, approvalID),
		map[string]any{"decision": "maybe"}, owner)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())

	// Approve works.
	w = h.do(t, http.MethodPost, approvalDecisionPath(orgID, approvalID),
		map[string]any{"decision": "approve", "reason": "ok for today"}, owner)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var decided approvalBody
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &decided))
	require.Equal(t, "approved", decided.Data.Status)
	require.NotNil(t, decided.Data.DecidedBy)
	require.NotNil(t, decided.Data.DecidedAt)
	require.NotNil(t, decided.Data.Reason)
	require.Equal(t, "ok for today", *decided.Data.Reason)

	// A second decision is a 409.
	w = h.do(t, http.MethodPost, approvalDecisionPath(orgID, approvalID),
		map[string]any{"decision": "deny"}, owner)
	require.Equal(t, http.StatusConflict, w.Code, w.Body.String())
}

// An expired request cannot be approved even before the sweep marks it.
func TestApproval_DecideExpiredConflicts(t *testing.T) {
	h := newTicketHarness(t)
	owner, orgID := seedOrgOwner(t, h, "approval-exp@example.com")
	dev := seedDevice(t, h, orgID, "100000017")
	approvalID := seedApproval(t, h, orgID, int64(dev.ID), model.ApprovalStatusPending)
	require.NoError(t, store.WithoutTenantScope(h.db.DB).Model(&model.Approval{}).
		Where("id = ?", approvalID).
		Update("expires_at", fixedNow.Add(-1)).Error)

	w := h.do(t, http.MethodPost, approvalDecisionPath(orgID, approvalID),
		map[string]any{"decision": "approve"}, owner)
	require.Equal(t, http.StatusConflict, w.Code, w.Body.String())
}

// A decision on another organization's approval is a 404, not a leak.
func TestApproval_DecideCrossTenant(t *testing.T) {
	h := newTicketHarness(t)
	_, orgA := seedOrgOwner(t, h, "approval-xt-a@example.com")
	ownerB, orgB := seedOrgOwner(t, h, "approval-xt-b@example.com")
	devB := seedDevice(t, h, orgB, "100000018")
	approvalID := seedApproval(t, h, orgA, 1, model.ApprovalStatusPending)

	w := h.do(t, http.MethodPost, approvalDecisionPath(orgB, approvalID),
		map[string]any{"decision": "approve"}, ownerB)
	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())

	w = h.do(t, http.MethodGet, approvalItemPath(orgB, approvalID), nil, ownerB)
	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())
	_ = devB
}

// ── listing ─────────────────────────────────────────────────────────────────

func TestApproval_ListFiltersAndOrdering(t *testing.T) {
	h := newTicketHarness(t)
	owner, orgID := seedOrgOwner(t, h, "approval-list@example.com")
	member := seedOrgMember(t, h, orgID, "approval-list-member@example.com")
	dev := seedDevice(t, h, orgID, "100000019")
	other := seedDevice(t, h, orgID, "100000020")

	// Three requests from two actors across two devices: a same-actor
	// same-device repeat would be reused, not created.
	for _, tc := range []struct {
		token string
		dev   model.Device
	}{
		{owner, dev},
		{member, dev},
		{owner, other},
	} {
		w := h.do(t, http.MethodPost, approvalPath(orgID), map[string]any{
			"kind": "pre_approval", "device_id": tc.dev.ID,
		}, tc.token)
		require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	}

	type listBody struct {
		Code string `json:"code"`
		Data struct {
			Items    []approvalBody_Data `json:"items"`
			Page     int                 `json:"page"`
			PageSize int64               `json:"page_size"`
			Total    int64               `json:"total"`
		} `json:"data"`
	}

	// Newest first, page metadata present.
	w := h.do(t, http.MethodGet, approvalPath(orgID), nil, owner)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var list listBody
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &list))
	require.Equal(t, int64(3), list.Data.Total)
	require.Len(t, list.Data.Items, 3)
	require.Greater(t, list.Data.Items[0].Id, list.Data.Items[2].Id, "newest first")

	// Status filter.
	w = h.do(t, http.MethodGet, approvalPath(orgID)+"?status=pending", nil, owner)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &list))
	require.Equal(t, int64(3), list.Data.Total)

	w = h.do(t, http.MethodGet, approvalPath(orgID)+"?status=denied", nil, owner)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &list))
	require.Equal(t, int64(0), list.Data.Total)
	require.Empty(t, list.Data.Items)

	// Device filter.
	w = h.do(t, http.MethodGet, approvalPath(orgID)+"?deviceId="+strconv.FormatInt(int64(other.ID), 10), nil, owner)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &list))
	require.Equal(t, int64(1), list.Data.Total)
	require.Equal(t, int64(other.ID), list.Data.Items[0].DeviceId)

	// An unknown status is a 400, not a 200 with an empty list: the client
	// would otherwise read its own typo as "nothing pending in this state".
	w = h.do(t, http.MethodGet, approvalPath(orgID)+"?status=bogus", nil, owner)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
}

// The inbox is polled: reads add no audit rows, mutations do.
func TestApproval_AuditCounts(t *testing.T) {
	auditor := &countingAuditor{}
	h := newHarnessWith(t, func(d *api.Deps) { d.Auditor = auditor })
	owner, orgID := seedOrgOwner(t, h, "approval-audit@example.com")
	dev := seedDevice(t, h, orgID, "100000021")

	auditor.reset()
	w := h.do(t, http.MethodGet, approvalPath(orgID), nil, owner)
	require.Equal(t, http.StatusOK, w.Code)
	require.Zero(t, auditor.entries, "polled reads stay silent")

	w = h.do(t, http.MethodPost, approvalPath(orgID), map[string]any{
		"kind": "pre_approval", "device_id": dev.ID,
	}, owner)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var created approvalBody
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &created))
	require.Equal(t, 1, auditor.entries, "a new request is audited once")

	// A duplicate submission reuses the row without a second audit entry.
	w = h.do(t, http.MethodPost, approvalPath(orgID), map[string]any{
		"kind": "pre_approval", "device_id": dev.ID,
	}, owner)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Equal(t, 1, auditor.entries, "a reuse is not a new fact")

	// The decision is audited exactly once.
	auditor.reset()
	w = h.do(t, http.MethodPost, approvalDecisionPath(orgID, created.Data.Id),
		map[string]any{"decision": "approve"}, owner)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Equal(t, 1, auditor.entries, "a decision is audited once")
}

// ── helpers ─────────────────────────────────────────────────────────────────

type approvalBody_Data = struct {
	Id          int64   `json:"id"`
	DeviceId    int64   `json:"device_id"`
	Kind        string  `json:"kind"`
	Status      string  `json:"status"`
	SessionId   *int64  `json:"session_id"`
	ActorUserId int64   `json:"actor_user_id"`
	ExpiresAt   string  `json:"expires_at"`
	DecidedBy   *int64  `json:"decided_by"`
	DecidedAt   *string `json:"decided_at"`
	Reason      *string `json:"reason"`
	TicketId    *int64  `json:"ticket_id"`
}

var _ = store.WithoutTenantScope
