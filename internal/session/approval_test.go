package session_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/session"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// ── creation: pre_approval ──────────────────────────────────────────────────

// A pre-approval starts as pending with the contract's fixed 15-minute TTL and
// is audited, because it is a domain mutation an approver must act on.
func TestCreatePreApproval_CreatesPending(t *testing.T) {
	h := newHarness(t)

	approval, reused, err := h.svc.CreateApproval(context.Background(), h.org.ID, 7, session.ApprovalCreateInput{
		Kind:     model.ApprovalKindPre,
		DeviceID: h.device.ID,
	})
	require.NoError(t, err)
	require.False(t, reused, "the first request for a device creates, it does not reuse")

	require.NotZero(t, approval.ID)
	require.Equal(t, h.org.ID, approval.OrganizationID)
	require.Equal(t, h.device.ID, approval.DeviceID)
	require.Equal(t, model.ApprovalKindPre, approval.Kind)
	require.Nil(t, approval.SessionID, "a pre-approval is never tied to a session")
	require.Equal(t, uint(7), approval.ActorUserID)
	require.Equal(t, model.ApprovalStatusPending, approval.Status)
	require.Equal(t, h.now.Add(15*time.Minute).UTC(), approval.ExpiresAt.UTC(), "the contract fixes the TTL at 15 minutes")
	require.Nil(t, approval.DecidedBy)
	require.Nil(t, approval.TicketID, "no ticket exists before issuance consumes the approval")

	require.Contains(t, h.recorder.actions(), "session.approval.request")
}

// Retrying the same actor+device while the request is still pending must reuse
// the existing row: a retry loop between "approval required" and this endpoint
// must not fill the approval inbox with duplicates.
func TestCreatePreApproval_ReusesPending(t *testing.T) {
	h := newHarness(t)

	first, _, err := h.svc.CreateApproval(context.Background(), h.org.ID, 7, session.ApprovalCreateInput{
		Kind:     model.ApprovalKindPre,
		DeviceID: h.device.ID,
	})
	require.NoError(t, err)

	second, reused, err := h.svc.CreateApproval(context.Background(), h.org.ID, 7, session.ApprovalCreateInput{
		Kind:     model.ApprovalKindPre,
		DeviceID: h.device.ID,
	})
	require.NoError(t, err)
	require.True(t, reused)
	require.Equal(t, first.ID, second.ID, "the pending request is reused, not duplicated")
}

// An expired pending row cannot be approved by anyone, so reusing it would hand
// back a dead id and loop the client forever. A new request is created instead.
func TestCreatePreApproval_ExpiredPendingIsNotReused(t *testing.T) {
	h := newHarness(t)

	first, _, err := h.svc.CreateApproval(context.Background(), h.org.ID, 7, session.ApprovalCreateInput{
		Kind:     model.ApprovalKindPre,
		DeviceID: h.device.ID,
	})
	require.NoError(t, err)

	h.setClock(h.now.Add(16 * time.Minute))
	second, reused, err := h.svc.CreateApproval(context.Background(), h.org.ID, 7, session.ApprovalCreateInput{
		Kind:     model.ApprovalKindPre,
		DeviceID: h.device.ID,
	})
	require.NoError(t, err)
	require.False(t, reused, "the expired request is dead; a fresh one is created")
	require.NotEqual(t, first.ID, second.ID)
}

// A different actor's pending request is not this actor's: approvals are
// per-actor permissions, so sharing one pending row would let one approval
// cover two members.
func TestCreatePreApproval_AnotherActorGetsItsOwnRequest(t *testing.T) {
	h := newHarness(t)

	first, _, err := h.svc.CreateApproval(context.Background(), h.org.ID, 7, session.ApprovalCreateInput{
		Kind:     model.ApprovalKindPre,
		DeviceID: h.device.ID,
	})
	require.NoError(t, err)

	second, reused, err := h.svc.CreateApproval(context.Background(), h.org.ID, 8, session.ApprovalCreateInput{
		Kind:     model.ApprovalKindPre,
		DeviceID: h.device.ID,
	})
	require.NoError(t, err)
	require.False(t, reused)
	require.NotEqual(t, first.ID, second.ID)
}

// The request body must match the kind exactly: both ids, neither id, or an id
// that contradicts the kind are all invalid requests.
func TestCreatePreApproval_FieldMismatchIsRejected(t *testing.T) {
	h := newHarness(t)

	_, _, err := h.svc.CreateApproval(context.Background(), h.org.ID, 7, session.ApprovalCreateInput{
		Kind: model.ApprovalKindPre,
	})
	require.ErrorIs(t, err, session.ErrInvalidInput, "device_id is required for a pre-approval")

	sessionID := h.newNativeSession(t)
	_, _, err = h.svc.CreateApproval(context.Background(), h.org.ID, 7, session.ApprovalCreateInput{
		Kind:      model.ApprovalKindPre,
		DeviceID:  h.device.ID,
		SessionID: &sessionID,
	})
	require.ErrorIs(t, err, session.ErrInvalidInput, "a pre-approval must not carry session_id")
}

// ── creation: ratification ──────────────────────────────────────────────────

// A ratification derives its device from the session server-side and never
// trusts a client-supplied device id.
func TestCreateRatification_DerivesDeviceFromSession(t *testing.T) {
	h := newHarness(t)
	sessionID := h.newNativeSession(t)

	approval, reused, err := h.svc.CreateApproval(context.Background(), h.org.ID, 7, session.ApprovalCreateInput{
		Kind:      model.ApprovalKindRatification,
		SessionID: &sessionID,
	})
	require.NoError(t, err)
	require.False(t, reused)

	require.Equal(t, model.ApprovalKindRatification, approval.Kind)
	require.NotNil(t, approval.SessionID)
	require.Equal(t, sessionID, *approval.SessionID)
	require.Equal(t, h.device.ID, approval.DeviceID, "device_id comes from the session row")
	require.Equal(t, model.ApprovalStatusPending, approval.Status)
	require.Equal(t, h.now.Add(15*time.Minute).UTC(), approval.ExpiresAt.UTC())
	require.Contains(t, h.recorder.actions(), "session.approval.request")
}

// Only native sessions can be ratified: panel sessions are already governed by
// policy, so "acknowledging" one would be a no-op that muddies the audit trail.
func TestCreateRatification_PanelOriginIsRejected(t *testing.T) {
	h := newHarness(t)
	now := h.now
	sess := model.Session{
		OrganizationID: h.org.ID,
		DeviceID:       h.device.ID,
		RustdeskID:     h.device.RustdeskID,
		Origin:         model.SessionOriginPanel,
		Status:         model.SessionStatusOpen,
		StartedAt:      now,
	}
	require.NoError(t, h.db.Create(&sess).Error)
	sid := sess.ID

	_, _, err := h.svc.CreateApproval(context.Background(), h.org.ID, 7, session.ApprovalCreateInput{
		Kind:      model.ApprovalKindRatification,
		SessionID: &sid,
	})
	require.ErrorIs(t, err, session.ErrInvalidInput, "panel sessions are not ratifiable")
}

// A session from another organization is rejected with the same invalid-input
// error: answering 404 would let a caller probe which session ids exist.
func TestCreateRatification_ForeignSessionIsRejected(t *testing.T) {
	h := newHarness(t)
	foreignID := h.newForeignSession(t)

	_, _, err := h.svc.CreateApproval(context.Background(), h.org.ID, 7, session.ApprovalCreateInput{
		Kind:      model.ApprovalKindRatification,
		SessionID: &foreignID,
	})
	require.ErrorIs(t, err, session.ErrInvalidInput, "the same 400 for missing and foreign sessions")
}

// The same session must not produce multiple open requests: two approvers
// clicking the same native-session alert would otherwise create two pending
// rows for the same fact.
func TestCreateRatification_ReusesPendingAndApproved(t *testing.T) {
	h := newHarness(t)
	sessionID := h.newNativeSession(t)

	first, _, err := h.svc.CreateApproval(context.Background(), h.org.ID, 7, session.ApprovalCreateInput{
		Kind:      model.ApprovalKindRatification,
		SessionID: &sessionID,
	})
	require.NoError(t, err)

	// A second submitter, before any decision: reused.
	second, reused, err := h.svc.CreateApproval(context.Background(), h.org.ID, 8, session.ApprovalCreateInput{
		Kind:      model.ApprovalKindRatification,
		SessionID: &sessionID,
	})
	require.NoError(t, err)
	require.True(t, reused, "the pending ratification is reused across submitters")
	require.Equal(t, first.ID, second.ID)

	// After approval, a third click still reuses: the session is acknowledged.
	_, err = h.svc.DecideApproval(context.Background(), h.org.ID, first.ID, 99, session.DecisionApprove, nil)
	require.NoError(t, err)

	third, reused, err := h.svc.CreateApproval(context.Background(), h.org.ID, 9, session.ApprovalCreateInput{
		Kind:      model.ApprovalKindRatification,
		SessionID: &sessionID,
	})
	require.NoError(t, err)
	require.True(t, reused, "the approved ratification is reused: the session is already acknowledged")
	require.Equal(t, first.ID, third.ID)
}

// A session_id is mandatory for a ratification and a device_id is not accepted.
func TestCreateRatification_FieldMismatchIsRejected(t *testing.T) {
	h := newHarness(t)

	_, _, err := h.svc.CreateApproval(context.Background(), h.org.ID, 7, session.ApprovalCreateInput{
		Kind: model.ApprovalKindRatification,
	})
	require.ErrorIs(t, err, session.ErrInvalidInput, "session_id is required for a ratification")

	_, _, err = h.svc.CreateApproval(context.Background(), h.org.ID, 7, session.ApprovalCreateInput{
		Kind:     model.ApprovalKindRatification,
		DeviceID: h.device.ID,
	})
	require.ErrorIs(t, err, session.ErrInvalidInput, "device_id must be derived, not supplied")
}

// An unknown kind is a programming or client error, rejected up front.
func TestCreateApproval_UnknownKindIsRejected(t *testing.T) {
	h := newHarness(t)

	_, _, err := h.svc.CreateApproval(context.Background(), h.org.ID, 7, session.ApprovalCreateInput{
		Kind:     "magic",
		DeviceID: h.device.ID,
	})
	require.ErrorIs(t, err, session.ErrInvalidInput)
}

// A pre-approval for a device that does not exist in this organization is a
// 404: the request could never be consumed and would pollute the inbox.
func TestCreatePreApproval_UnknownDeviceIsNotFound(t *testing.T) {
	h := newHarness(t)

	_, _, err := h.svc.CreateApproval(context.Background(), h.org.ID, 7, session.ApprovalCreateInput{
		Kind:     model.ApprovalKindPre,
		DeviceID: 9999,
	})
	require.ErrorIs(t, err, session.ErrDeviceNotFound)
}

// An expired pending ratification is dead just like a pre-approval's: reusing
// it would hand back an id the decision endpoint refuses with 409.
func TestCreateRatification_ExpiredPendingIsNotReused(t *testing.T) {
	h := newHarness(t)
	sessionID := h.newNativeSession(t)

	first, _, err := h.svc.CreateApproval(context.Background(), h.org.ID, 7, session.ApprovalCreateInput{
		Kind:      model.ApprovalKindRatification,
		SessionID: &sessionID,
	})
	require.NoError(t, err)

	h.setClock(h.now.Add(16 * time.Minute))
	second, reused, err := h.svc.CreateApproval(context.Background(), h.org.ID, 8, session.ApprovalCreateInput{
		Kind:      model.ApprovalKindRatification,
		SessionID: &sessionID,
	})
	require.NoError(t, err)
	require.False(t, reused, "the expired request is dead; a fresh one is created")
	require.NotEqual(t, first.ID, second.ID)
}

// A reason longer than the contract's 500 characters is refused.
func TestCreateApproval_ReasonTooLongIsRejected(t *testing.T) {
	h := newHarness(t)
	long := ""
	for i := 0; i < 501; i++ {
		long += "a"
	}

	_, _, err := h.svc.CreateApproval(context.Background(), h.org.ID, 7, session.ApprovalCreateInput{
		Kind:     model.ApprovalKindPre,
		DeviceID: h.device.ID,
		Reason:   &long,
	})
	require.ErrorIs(t, err, session.ErrInvalidInput)
}

// ── decisions ───────────────────────────────────────────────────────────────

// Approving flips the status and records who decided, but issues nothing: the
// contract says approval is a permission to issue, not an issuance.
func TestDecideApproval_Approve(t *testing.T) {
	h := newHarness(t)
	approval, _, err := h.svc.CreateApproval(context.Background(), h.org.ID, 7, session.ApprovalCreateInput{
		Kind:     model.ApprovalKindPre,
		DeviceID: h.device.ID,
	})
	require.NoError(t, err)

	decided, err := h.svc.DecideApproval(context.Background(), h.org.ID, approval.ID, 99, session.DecisionApprove, nil)
	require.NoError(t, err)
	require.Equal(t, model.ApprovalStatusApproved, decided.Status)
	require.NotNil(t, decided.DecidedBy)
	require.Equal(t, uint(99), *decided.DecidedBy)
	require.NotNil(t, decided.DecidedAt)
	require.Nil(t, decided.TicketID, "approving never issues a ticket")
	require.Contains(t, h.recorder.actions(), "session.approval.decide")
}

// Denying records the decision and its reason.
func TestDecideApproval_Deny(t *testing.T) {
	h := newHarness(t)
	approval, _, err := h.svc.CreateApproval(context.Background(), h.org.ID, 7, session.ApprovalCreateInput{
		Kind:     model.ApprovalKindPre,
		DeviceID: h.device.ID,
	})
	require.NoError(t, err)
	denyReason := "not right now"

	decided, err := h.svc.DecideApproval(context.Background(), h.org.ID, approval.ID, 99, session.DecisionDeny, &denyReason)
	require.NoError(t, err)
	require.Equal(t, model.ApprovalStatusDenied, decided.Status)
	require.NotNil(t, decided.DecidedBy)
	require.NotNil(t, decided.DecidedAt)
	require.Contains(t, h.recorder.actions(), "session.approval.decide")
}

// Only pending requests can be decided: a second decision must hit 409.
func TestDecideApproval_SecondDecisionConflicts(t *testing.T) {
	h := newHarness(t)
	approval, _, err := h.svc.CreateApproval(context.Background(), h.org.ID, 7, session.ApprovalCreateInput{
		Kind:     model.ApprovalKindPre,
		DeviceID: h.device.ID,
	})
	require.NoError(t, err)
	_, err = h.svc.DecideApproval(context.Background(), h.org.ID, approval.ID, 99, session.DecisionApprove, nil)
	require.NoError(t, err)

	_, err = h.svc.DecideApproval(context.Background(), h.org.ID, approval.ID, 100, session.DecisionDeny, nil)
	require.ErrorIs(t, err, session.ErrConflict, "an approved request is final")
}

// An expired-but-not-yet-swept pending request must not be approvable: the
// decision endpoint cannot wait for the background task to catch up.
func TestDecideApproval_ExpiredPendingConflicts(t *testing.T) {
	h := newHarness(t)
	approval, _, err := h.svc.CreateApproval(context.Background(), h.org.ID, 7, session.ApprovalCreateInput{
		Kind:     model.ApprovalKindPre,
		DeviceID: h.device.ID,
	})
	require.NoError(t, err)

	h.setClock(h.now.Add(16 * time.Minute))
	_, err = h.svc.DecideApproval(context.Background(), h.org.ID, approval.ID, 99, session.DecisionApprove, nil)
	require.ErrorIs(t, err, session.ErrConflict, "a stale approval is not actionable")
}

// A ratification approval yields no ticket under any decision: ticket_id stays
// null for its whole life.
func TestDecideApproval_RatificationNeverGetsTicket(t *testing.T) {
	h := newHarness(t)
	sessionID := h.newNativeSession(t)
	approval, _, err := h.svc.CreateApproval(context.Background(), h.org.ID, 7, session.ApprovalCreateInput{
		Kind:      model.ApprovalKindRatification,
		SessionID: &sessionID,
	})
	require.NoError(t, err)

	decided, err := h.svc.DecideApproval(context.Background(), h.org.ID, approval.ID, 99, session.DecisionApprove, nil)
	require.NoError(t, err)
	require.Nil(t, decided.TicketID)

	var stored model.Approval
	require.NoError(t, store.WithoutTenantScope(h.db).First(&stored, approval.ID).Error)
	require.Nil(t, stored.TicketID, "a ratification is an acknowledgement, not an issuance")
}

// An invalid decision value is rejected rather than silently stored.
func TestDecideApproval_InvalidDecisionIsRejected(t *testing.T) {
	h := newHarness(t)
	approval, _, err := h.svc.CreateApproval(context.Background(), h.org.ID, 7, session.ApprovalCreateInput{
		Kind:     model.ApprovalKindPre,
		DeviceID: h.device.ID,
	})
	require.NoError(t, err)

	_, err = h.svc.DecideApproval(context.Background(), h.org.ID, approval.ID, 99, "maybe", nil)
	require.ErrorIs(t, err, session.ErrInvalidInput)
}

// A decision longer than 500 characters is refused.
func TestDecideApproval_ReasonTooLongIsRejected(t *testing.T) {
	h := newHarness(t)
	approval, _, err := h.svc.CreateApproval(context.Background(), h.org.ID, 7, session.ApprovalCreateInput{
		Kind:     model.ApprovalKindPre,
		DeviceID: h.device.ID,
	})
	require.NoError(t, err)
	long := ""
	for i := 0; i < 501; i++ {
		long += "a"
	}

	_, err = h.svc.DecideApproval(context.Background(), h.org.ID, approval.ID, 99, session.DecisionDeny, &long)
	require.ErrorIs(t, err, session.ErrInvalidInput)
}

// An approval from another organization does not exist for this caller: 404,
// not a leak.
func TestApproval_CrossTenantIsNotFound(t *testing.T) {
	h := newHarness(t)
	approval, _, err := h.svc.CreateApproval(context.Background(), h.org.ID, 7, session.ApprovalCreateInput{
		Kind:     model.ApprovalKindPre,
		DeviceID: h.device.ID,
	})
	require.NoError(t, err)

	otherOrg := model.Organization{Name: "other"}
	require.NoError(t, h.db.Create(&otherOrg).Error)

	_, err = h.svc.DecideApproval(context.Background(), otherOrg.ID, approval.ID, 99, session.DecisionApprove, nil)
	require.ErrorIs(t, err, session.ErrApprovalNotFound)

	_, err = h.svc.Approval(context.Background(), otherOrg.ID, approval.ID)
	require.ErrorIs(t, err, session.ErrApprovalNotFound)
}

// ── reads ───────────────────────────────────────────────────────────────────

func TestApproval_Get(t *testing.T) {
	h := newHarness(t)
	approval, _, err := h.svc.CreateApproval(context.Background(), h.org.ID, 7, session.ApprovalCreateInput{
		Kind:     model.ApprovalKindPre,
		DeviceID: h.device.ID,
	})
	require.NoError(t, err)

	got, err := h.svc.Approval(context.Background(), h.org.ID, approval.ID)
	require.NoError(t, err)
	require.Equal(t, approval.ID, got.ID)
}

// The inbox orders by requested_at descending (id descending on ties) so the
// newest request is always first, with a stable order within the same second.
func TestListApprovals_OrdersAndFilters(t *testing.T) {
	h := newHarness(t)

	first, _, err := h.svc.CreateApproval(context.Background(), h.org.ID, 7, session.ApprovalCreateInput{
		Kind:     model.ApprovalKindPre,
		DeviceID: h.device.ID,
	})
	require.NoError(t, err)
	h.setClock(h.now.Add(time.Minute))
	second, _, err := h.svc.CreateApproval(context.Background(), h.org.ID, 8, session.ApprovalCreateInput{
		Kind:     model.ApprovalKindPre,
		DeviceID: h.device.ID,
	})
	require.NoError(t, err)

	// Default order: newest first.
	items, total, err := h.svc.ListApprovals(context.Background(), h.org.ID, session.ApprovalFilter{})
	require.NoError(t, err)
	require.Equal(t, int64(2), total)
	require.Len(t, items, 2)
	require.Equal(t, second.ID, items[0].ID)
	require.Equal(t, first.ID, items[1].ID)

	// Status filter.
	_, total, err = h.svc.ListApprovals(context.Background(), h.org.ID, session.ApprovalFilter{
		Status: ptrString(model.ApprovalStatusPending),
	})
	require.NoError(t, err)
	require.Equal(t, int64(2), total)

	_, err = h.svc.DecideApproval(context.Background(), h.org.ID, first.ID, 99, session.DecisionDeny, nil)
	require.NoError(t, err)

	items, total, err = h.svc.ListApprovals(context.Background(), h.org.ID, session.ApprovalFilter{
		Status: ptrString(model.ApprovalStatusPending),
	})
	require.NoError(t, err)
	require.Equal(t, int64(1), total)
	require.Len(t, items, 1)
	require.Equal(t, second.ID, items[0].ID)

	// Device filter.
	_, total, err = h.svc.ListApprovals(context.Background(), h.org.ID, session.ApprovalFilter{
		DeviceID: &h.device.ID,
	})
	require.NoError(t, err)
	require.Equal(t, int64(2), total)

	other := model.Device{OrganizationID: h.org.ID, RustdeskID: "987654321", Name: "lab"}
	require.NoError(t, h.db.Create(&other).Error)
	otherApproval, _, err := h.svc.CreateApproval(context.Background(), h.org.ID, 7, session.ApprovalCreateInput{
		Kind:     model.ApprovalKindPre,
		DeviceID: other.ID,
	})
	require.NoError(t, err)
	items, _, err = h.svc.ListApprovals(context.Background(), h.org.ID, session.ApprovalFilter{
		DeviceID: &other.ID,
	})
	require.NoError(t, err)
	require.Len(t, items, 1)
	require.Equal(t, otherApproval.ID, items[0].ID)
}

// A listing from another organization is always empty.
func TestListApprovals_CrossTenantIsEmpty(t *testing.T) {
	h := newHarness(t)
	_, _, err := h.svc.CreateApproval(context.Background(), h.org.ID, 7, session.ApprovalCreateInput{
		Kind:     model.ApprovalKindPre,
		DeviceID: h.device.ID,
	})
	require.NoError(t, err)

	otherOrg := model.Organization{Name: "other"}
	require.NoError(t, h.db.Create(&otherOrg).Error)

	items, total, err := h.svc.ListApprovals(context.Background(), otherOrg.ID, session.ApprovalFilter{})
	require.NoError(t, err)
	require.Equal(t, int64(0), total)
	require.Empty(t, items)
}

// ── expiry sweep ────────────────────────────────────────────────────────────

// The background task flips overdue pending rows to expired and touches
// nothing else.
//
// The sweep is deliberately cross-tenant, so on CI's shared PostgreSQL/MySQL
// database the changed count includes rows left over from earlier tests. This
// test therefore starts by clearing the approvals table: every test in this
// package seeds its own rows and reads only its own, and the suite runs
// serially, so the wipe cannot cross a test boundary.
func TestExpirePendingApprovals(t *testing.T) {
	h := newHarness(t)
	require.NoError(t, store.WithoutTenantScope(h.db).
		Where("1 = 1").Delete(&model.Approval{}).Error)

	stale, _, err := h.svc.CreateApproval(context.Background(), h.org.ID, 7, session.ApprovalCreateInput{
		Kind:     model.ApprovalKindPre,
		DeviceID: h.device.ID,
	})
	require.NoError(t, err)
	h.setClock(h.now.Add(10 * time.Minute))
	fresh, _, err := h.svc.CreateApproval(context.Background(), h.org.ID, 8, session.ApprovalCreateInput{
		Kind:     model.ApprovalKindPre,
		DeviceID: h.device.ID,
	})
	require.NoError(t, err)

	// At +10m: the stale request dies at +15m, the fresh one at +25m.
	changed, err := h.svc.ExpirePendingApprovals(context.Background(), h.now.Add(0))
	require.NoError(t, err)
	require.Equal(t, int64(0), changed, "neither request is overdue yet")

	// At +16m: only the stale request is overdue.
	changed, err = h.svc.ExpirePendingApprovals(context.Background(), h.now.Add(6*time.Minute))
	require.NoError(t, err)
	require.Equal(t, int64(1), changed)

	var staleRow, freshRow model.Approval
	require.NoError(t, store.WithoutTenantScope(h.db).First(&staleRow, stale.ID).Error)
	require.NoError(t, store.WithoutTenantScope(h.db).First(&freshRow, fresh.ID).Error)
	require.Equal(t, model.ApprovalStatusExpired, staleRow.Status)
	require.Equal(t, model.ApprovalStatusPending, freshRow.Status, "a live request is untouched")

	// A decided request is never swept, and the sweep is idempotent.
	_, err = h.svc.DecideApproval(context.Background(), h.org.ID, fresh.ID, 99, session.DecisionApprove, nil)
	require.NoError(t, err)
	changed, err = h.svc.ExpirePendingApprovals(context.Background(), h.now.Add(16*time.Minute))
	require.NoError(t, err)
	require.Equal(t, int64(0), changed)

	var decidedRow model.Approval
	require.NoError(t, store.WithoutTenantScope(h.db).First(&decidedRow, fresh.ID).Error)
	require.Equal(t, model.ApprovalStatusApproved, decidedRow.Status)
}

// ── helpers ─────────────────────────────────────────────────────────────────

func ptrString(s string) *string { return &s }

// newNativeSession inserts a native (log-inferred) open session for the
// harness device, the only kind a ratification may reference.
func (h *harness) newNativeSession(t *testing.T) uint {
	t.Helper()
	sess := model.Session{
		OrganizationID: h.org.ID,
		DeviceID:       h.device.ID,
		RustdeskID:     h.device.RustdeskID,
		Origin:         model.SessionOriginNative,
		Status:         model.SessionStatusOpen,
		StartedAt:      h.now,
	}
	require.NoError(t, h.db.Create(&sess).Error)
	return sess.ID
}

// newForeignSession inserts a native session in another organization.
func (h *harness) newForeignSession(t *testing.T) uint {
	t.Helper()
	otherOrg := model.Organization{Name: "foreign-" + time.Now().Format("150405.000000000")}
	require.NoError(t, h.db.Create(&otherOrg).Error)
	dev := model.Device{OrganizationID: otherOrg.ID, RustdeskID: "555555555", Name: "foreign"}
	require.NoError(t, h.db.Create(&dev).Error)
	sess := model.Session{
		OrganizationID: otherOrg.ID,
		DeviceID:       dev.ID,
		RustdeskID:     dev.RustdeskID,
		Origin:         model.SessionOriginNative,
		Status:         model.SessionStatusOpen,
		StartedAt:      h.now,
	}
	require.NoError(t, h.db.Create(&sess).Error)
	return sess.ID
}

// Compile-time guard: the errors below are the handler's mapping surface.
var (
	_ error = session.ErrInvalidInput
	_ error = session.ErrConflict
	_ error = session.ErrApprovalNotFound
	_       = gorm.ErrRecordNotFound
)
