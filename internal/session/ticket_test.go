package session_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/audit"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/config"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/session"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// harnessSeq keeps each harness on its own database; policySeq keeps policy
// names unique inside one test.
var (
	harnessSeq atomic.Int64
	policySeq  atomic.Int64
)

type fakeRecorder struct {
	mu      sync.Mutex
	entries []audit.Entry
	fail    error
}

func (f *fakeRecorder) RecordTx(_ *gorm.DB, e audit.Entry) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return f.fail
	}
	f.entries = append(f.entries, e)
	return nil
}

func (f *fakeRecorder) actions() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.entries))
	for _, e := range f.entries {
		out = append(out, e.Action)
	}
	return out
}

type harness struct {
	svc      *session.Service
	db       *gorm.DB
	recorder *fakeRecorder
	now      time.Time
	org      model.Organization
	device   model.Device
}

// openHarnessStore opens the database a ticket test runs against.
//
// CI's test-db job exports TEST_POSTGRES_DSN / TEST_MYSQL_DSN, and these tests
// must run on those dialects too: the SQLite-only harness is exactly how a
// MySQL-only defect (a no-op UPDATE reports 0 affected rows there) stays green
// locally and breaks in production.
func openHarnessStore(t *testing.T) *store.Store {
	t.Helper()
	switch {
	case os.Getenv("TEST_POSTGRES_DSN") != "":
		s, err := store.Open(config.DatabaseConfig{Driver: "postgres", DSN: os.Getenv("TEST_POSTGRES_DSN")})
		require.NoError(t, err)
		return s
	case os.Getenv("TEST_MYSQL_DSN") != "":
		s, err := store.Open(config.DatabaseConfig{Driver: "mysql", DSN: os.Getenv("TEST_MYSQL_DSN")})
		require.NoError(t, err)
		return s
	}
	// A shared-cache memory database is keyed by name across the process, so a
	// fixed DSN would let one test see another's rows (and hide rollback bugs).
	s, err := store.Open(config.DatabaseConfig{
		Driver: "sqlite",
		DSN:    fmt.Sprintf("file:session_svc_%d?mode=memory&cache=shared", harnessSeq.Add(1)),
	})
	require.NoError(t, err)
	return s
}

func newHarness(t *testing.T) *harness {
	t.Helper()

	s := openHarnessStore(t)
	t.Cleanup(func() { _ = s.Close() })

	require.NoError(t, s.DB.AutoMigrate(
		&model.Organization{}, &model.Device{}, &model.Policy{},
		&model.Ticket{}, &model.Session{}, &model.SessionEvent{},
		&model.Approval{}, &model.Alert{},
		// Control role snapshots need a membership (the assignment) and the
		// role row itself; the user row keeps the fixture realistic.
		&model.User{}, &model.Membership{}, &model.ControlRole{},
	))

	h := &harness{
		db:       s.DB,
		recorder: &fakeRecorder{},
		now:      time.Date(2026, 10, 22, 10, 0, 0, 0, time.UTC),
	}
	h.org = model.Organization{Name: "acme"}
	require.NoError(t, s.DB.Create(&h.org).Error)

	h.device = model.Device{OrganizationID: h.org.ID, RustdeskID: "123456789", Name: "workstation"}
	require.NoError(t, s.DB.Create(&h.device).Error)

	// Redemption re-checks access inside its transaction and fails closed
	// without an evaluator; these tests exercise everything else about the
	// service, so the fixture wires a permissive stand-in. The re-check itself
	// is pinned in ticket_access_test.go.
	h.svc = session.NewService(s.DB, h.recorder, func() time.Time { return h.now }).
		WithAccess(&fakeAccess{allow: true})
	return h
}

// setClock moves time forward without rebuilding the service.
func (h *harness) setClock(t time.Time) { h.now = t }

func (h *harness) addPolicy(t *testing.T, mutate func(*model.Policy)) model.Policy {
	t.Helper()
	// (organization_id, name) is unique, so each policy in a test needs its own.
	p := model.Policy{
		OrganizationID: h.org.ID,
		Name:           "policy-" + fmt.Sprint(policySeq.Add(1)),
		Enabled:        true,
	}
	if mutate != nil {
		mutate(&p)
	}
	require.NoError(t, h.db.Create(&p).Error)
	return p
}

// ── issuance ────────────────────────────────────────────────────────────────

// The default lifetime is 300s and the plaintext token never reaches the
// database: only its digest does.
func TestIssue_DefaultsAndTokenHygiene(t *testing.T) {
	h := newHarness(t)

	ticket, token, err := h.svc.Issue(context.Background(), session.IssueInput{
		OrganizationID: h.org.ID, ActorUserID: 1, DeviceID: h.device.ID,
	})
	require.NoError(t, err)

	require.NotEmpty(t, token, "the plaintext token is returned exactly once")
	require.Equal(t, h.now.Add(300*time.Second), ticket.ExpiresAt.UTC())
	require.NotEqual(t, token, ticket.TokenHash, "the plaintext must not be stored")
	require.Len(t, ticket.TokenHash, 64, "sha256 hex digest")

	var stored model.Ticket
	require.NoError(t, store.WithoutTenantScope(h.db).First(&stored, ticket.ID).Error)
	require.Equal(t, ticket.TokenHash, stored.TokenHash)
	require.Nil(t, stored.UsedAt)
	require.Contains(t, stored.PolicySnapshotJSON, "max_concurrent_sessions", "the snapshot records the effective policy")
}

// The contract bounds the lifetime at 30–900 seconds; anything else is client
// input we must refuse rather than clamp silently.
func TestIssue_RejectsOutOfRangeTTL(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	for _, ttl := range []int64{29, 901} {
		_, _, err := h.svc.Issue(ctx, session.IssueInput{
			OrganizationID: h.org.ID, ActorUserID: 1, DeviceID: h.device.ID, TTLSeconds: &ttl,
		})
		require.ErrorIs(t, err, session.ErrInvalidInput, "ttl %d must be refused", ttl)
	}

	ok := int64(30)
	_, _, err := h.svc.Issue(ctx, session.IssueInput{
		OrganizationID: h.org.ID, ActorUserID: 1, DeviceID: h.device.ID, TTLSeconds: &ok,
	})
	require.NoError(t, err)
}

// A device from another organization is not "forbidden by policy", it simply is
// not there for this organization.
func TestIssue_RejectsForeignDevice(t *testing.T) {
	h := newHarness(t)

	other := model.Organization{Name: "other"}
	require.NoError(t, h.db.Create(&other).Error)
	foreign := model.Device{OrganizationID: other.ID, RustdeskID: "999", Name: "x"}
	require.NoError(t, h.db.Create(&foreign).Error)

	_, _, err := h.svc.Issue(context.Background(), session.IssueInput{
		OrganizationID: h.org.ID, ActorUserID: 1, DeviceID: foreign.ID,
	})
	require.ErrorIs(t, err, session.ErrDeviceNotFound)
}

// Outside the allowed window issuance is refused *and* recorded: a denied
// attempt is exactly what an auditor wants to see, and it must not occupy a
// concurrency slot.
func TestIssue_OutsideWindowRecordsDeniedSession(t *testing.T) {
	h := newHarness(t)
	h.addPolicy(t, func(p *model.Policy) {
		start, end := int64(540), int64(1020) // 09:00-17:00
		p.AllowedStartMinute, p.AllowedEndMinute = &start, &end
	})
	h.setClock(time.Date(2026, 10, 22, 3, 0, 0, 0, time.UTC))

	_, _, err := h.svc.Issue(context.Background(), session.IssueInput{
		OrganizationID: h.org.ID, ActorUserID: 1, DeviceID: h.device.ID,
	})
	require.ErrorIs(t, err, session.ErrOutsideWindow)

	var denied []model.Session
	require.NoError(t, store.WithoutTenantScope(h.db).
		Where("organization_id = ?", h.org.ID).Find(&denied).Error)
	require.Len(t, denied, 1)
	require.Equal(t, model.SessionStatusDenied, denied[0].Status)
	require.Equal(t, model.SessionOriginPanel, denied[0].Origin)
	require.NotNil(t, denied[0].EndReason)
	require.Equal(t, model.SessionEndPolicyDenied, *denied[0].EndReason)
	require.NotNil(t, denied[0].EndedAt, "a denied row is born closed")
	require.Equal(t, denied[0].StartedAt.UTC(), denied[0].EndedAt.UTC())
}

// A policy demanding approval does not fail the request: it opens an approval
// request and returns its id so the client can route the user to the inbox.
func TestIssue_RequiresApprovalAndReusesPending(t *testing.T) {
	h := newHarness(t)
	h.addPolicy(t, func(p *model.Policy) { p.RequireApproval = true })

	_, _, err := h.svc.Issue(context.Background(), session.IssueInput{
		OrganizationID: h.org.ID, ActorUserID: 1, DeviceID: h.device.ID,
	})
	var need *session.ErrApprovalRequired
	require.ErrorAs(t, err, &need)
	require.NotZero(t, need.ApprovalID)

	// Asking again must not open a second approval-centre item.
	_, _, err = h.svc.Issue(context.Background(), session.IssueInput{
		OrganizationID: h.org.ID, ActorUserID: 1, DeviceID: h.device.ID,
	})
	var again *session.ErrApprovalRequired
	require.ErrorAs(t, err, &again)
	require.Equal(t, need.ApprovalID, again.ApprovalID, "the pending approval is reused")

	var approvals []model.Approval
	require.NoError(t, store.WithoutTenantScope(h.db).
		Where("organization_id = ?", h.org.ID).Find(&approvals).Error)
	require.Len(t, approvals, 1)
	require.Equal(t, model.ApprovalKindPre, approvals[0].Kind)
	require.Equal(t, model.ApprovalStatusPending, approvals[0].Status)
}

// Once approved, issuance consumes the approval and records the link on both
// sides: reusing it for a second ticket is what the one-to-one binding forbids.
func TestIssue_ConsumesApprovedApproval(t *testing.T) {
	h := newHarness(t)
	h.addPolicy(t, func(p *model.Policy) { p.RequireApproval = true })

	approval := model.Approval{
		OrganizationID: h.org.ID, DeviceID: h.device.ID, Kind: model.ApprovalKindPre,
		ActorUserID: 1, Status: model.ApprovalStatusApproved,
		RequestedAt: h.now, ExpiresAt: h.now.Add(time.Hour),
	}
	require.NoError(t, h.db.Create(&approval).Error)

	ticket, _, err := h.svc.Issue(context.Background(), session.IssueInput{
		OrganizationID: h.org.ID, ActorUserID: 1, DeviceID: h.device.ID,
	})
	require.NoError(t, err)
	require.NotNil(t, ticket.ApprovalID)
	require.Equal(t, approval.ID, *ticket.ApprovalID)

	var stored model.Approval
	require.NoError(t, store.WithoutTenantScope(h.db).First(&stored, approval.ID).Error)
	require.NotNil(t, stored.TicketID, "issuance back-fills the approval with the ticket it authorised")
	require.Equal(t, ticket.ID, *stored.TicketID)

	// A consumed approval cannot authorise a second ticket.
	_, _, err = h.svc.Issue(context.Background(), session.IssueInput{
		OrganizationID: h.org.ID, ActorUserID: 1, DeviceID: h.device.ID,
	})
	var need *session.ErrApprovalRequired
	require.ErrorAs(t, err, &need, "the second issuance needs a fresh approval")
}

// ── redemption ──────────────────────────────────────────────────────────────

func (h *harness) issue(t *testing.T) (ticketID uint, token string) {
	t.Helper()
	ticket, token, err := h.svc.Issue(context.Background(), session.IssueInput{
		OrganizationID: h.org.ID, ActorUserID: 1, DeviceID: h.device.ID,
	})
	require.NoError(t, err)
	return ticket.ID, token
}

// Redemption is the only creator of open panel sessions, and it must leave the
// ticket unusable.
func TestRedeem_CreatesOpenPanelSessionAndConsumesTicket(t *testing.T) {
	h := newHarness(t)
	ticketID, token := h.issue(t)

	sess, err := h.svc.Redeem(context.Background(), h.org.ID, 1, ticketID, token)
	require.NoError(t, err)

	require.Equal(t, model.SessionStatusOpen, sess.Status)
	require.Equal(t, model.SessionOriginPanel, sess.Origin)
	require.Equal(t, h.device.ID, sess.DeviceID)
	require.Equal(t, h.device.RustdeskID, sess.RustdeskID)
	require.Equal(t, h.now.UTC(), sess.StartedAt.UTC())
	require.NotNil(t, sess.LastActivityAt, "an open session needs an activity clock or the sweeper closes it immediately")
	require.NotNil(t, sess.TicketID)
	require.Equal(t, ticketID, *sess.TicketID)

	var stored model.Ticket
	require.NoError(t, store.WithoutTenantScope(h.db).First(&stored, ticketID).Error)
	require.NotNil(t, stored.UsedAt)
}

// Every failure mode of the ticket itself collapses to one 409 so a caller
// cannot probe which condition failed.
func TestRedeem_RejectsReplaysExpiryAndRevocation(t *testing.T) {
	t.Run("second redemption", func(t *testing.T) {
		h := newHarness(t)
		ticketID, token := h.issue(t)
		_, err := h.svc.Redeem(context.Background(), h.org.ID, 1, ticketID, token)
		require.NoError(t, err)

		_, err = h.svc.Redeem(context.Background(), h.org.ID, 1, ticketID, token)
		require.ErrorIs(t, err, session.ErrConflict)
	})

	t.Run("wrong token", func(t *testing.T) {
		h := newHarness(t)
		ticketID, _ := h.issue(t)

		_, err := h.svc.Redeem(context.Background(), h.org.ID, 1, ticketID, "not-the-token")
		require.ErrorIs(t, err, session.ErrConflict)
	})

	t.Run("expired", func(t *testing.T) {
		h := newHarness(t)
		ticketID, token := h.issue(t)
		h.setClock(h.now.Add(301 * time.Second))

		_, err := h.svc.Redeem(context.Background(), h.org.ID, 1, ticketID, token)
		require.ErrorIs(t, err, session.ErrConflict)
	})

	t.Run("revoked", func(t *testing.T) {
		h := newHarness(t)
		ticketID, token := h.issue(t)
		require.NoError(t, store.WithoutTenantScope(h.db).Model(&model.Ticket{}).
			Where("id = ?", ticketID).
			Update("revoked_at", h.now).Error)

		_, err := h.svc.Redeem(context.Background(), h.org.ID, 1, ticketID, token)
		require.ErrorIs(t, err, session.ErrConflict)
	})

	t.Run("unknown ticket", func(t *testing.T) {
		h := newHarness(t)
		_, err := h.svc.Redeem(context.Background(), h.org.ID, 1, 4242, "x")
		require.ErrorIs(t, err, session.ErrTicketNotFound)
	})
}

// The concurrency gate lives here, not at issuance: issuing never creates a
// session, so a check there could never trip.
func TestRedeem_EnforcesConcurrencyLimit(t *testing.T) {
	h := newHarness(t)
	limit := int64(1)
	h.addPolicy(t, func(p *model.Policy) { p.MaxConcurrentSessions = &limit })

	past := h.now.Add(-time.Minute)
	require.NoError(t, h.db.Create(&model.Session{
		OrganizationID: h.org.ID, DeviceID: h.device.ID, RustdeskID: h.device.RustdeskID,
		Origin: model.SessionOriginPanel, Status: model.SessionStatusOpen,
		StartedAt: past, LastActivityAt: &past,
	}).Error)

	ticketID, token := h.issue(t) // issuance must still succeed

	_, err := h.svc.Redeem(context.Background(), h.org.ID, 1, ticketID, token)
	require.ErrorIs(t, err, session.ErrConflict)

	var stored model.Ticket
	require.NoError(t, store.WithoutTenantScope(h.db).First(&stored, ticketID).Error)
	require.Nil(t, stored.UsedAt, "a refused redemption must not burn the ticket")
}

// Native sessions are record-only: they must not consume the panel quota.
func TestRedeem_NativeSessionsDoNotCount(t *testing.T) {
	h := newHarness(t)
	limit := int64(1)
	h.addPolicy(t, func(p *model.Policy) { p.MaxConcurrentSessions = &limit })

	past := h.now.Add(-time.Minute)
	require.NoError(t, h.db.Create(&model.Session{
		OrganizationID: h.org.ID, DeviceID: h.device.ID, RustdeskID: h.device.RustdeskID,
		Origin: model.SessionOriginNative, Status: model.SessionStatusOpen,
		StartedAt: past, LastActivityAt: &past,
	}).Error)

	ticketID, token := h.issue(t)
	_, err := h.svc.Redeem(context.Background(), h.org.ID, 1, ticketID, token)
	require.NoError(t, err, "native sessions are not part of the panel quota")
}

// The window can close between issuance and redemption, so redemption re-checks
// it rather than trusting the ticket.
func TestRedeem_RechecksWindow(t *testing.T) {
	h := newHarness(t)
	h.addPolicy(t, func(p *model.Policy) {
		start, end := int64(540), int64(1020) // 09:00-17:00
		p.AllowedStartMinute, p.AllowedEndMinute = &start, &end
	})

	ticketID, token := h.issue(t)
	h.setClock(time.Date(2026, 10, 22, 20, 0, 0, 0, time.UTC))

	_, err := h.svc.Redeem(context.Background(), h.org.ID, 1, ticketID, token)
	require.ErrorIs(t, err, session.ErrConflict, "a stale ticket must not bypass a closed window")
}

// Issuing and redeeming are domain mutations: both leave an audit entry, and a
// failing recorder must fail the operation rather than let it through unaudited.
func TestIssueAndRedeem_AreAudited(t *testing.T) {
	h := newHarness(t)

	ticketID, token := h.issue(t)
	_, err := h.svc.Redeem(context.Background(), h.org.ID, 1, ticketID, token)
	require.NoError(t, err)

	require.Len(t, h.recorder.entries, 2, "one entry for issuance, one for redemption")
	for _, e := range h.recorder.entries {
		require.Equal(t, h.org.ID, e.OrganizationID)
		require.Equal(t, uint(1), e.ActorUserID)
	}
	require.Equal(t, "session.ticket.issue", h.recorder.entries[0].Action)
	require.Equal(t, "session.ticket.redeem", h.recorder.entries[1].Action)

	// An audit failure must abort the write: an unaudited session is worse than
	// a refused one.
	broken := newHarness(t)
	broken.recorder.fail = errors.New("audit unavailable")
	_, _, err = broken.svc.Issue(context.Background(), session.IssueInput{
		OrganizationID: broken.org.ID, ActorUserID: 1, DeviceID: broken.device.ID,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "audit unavailable")

	var tickets []model.Ticket
	require.NoError(t, store.WithoutTenantScope(broken.db).
		Where("organization_id = ?", broken.org.ID).Find(&tickets).Error)
	require.Empty(t, tickets, "a failed audit must roll the ticket back")
}

// ── review round: attribution, actor, approval state ────────────────────────

// The contract names the attribution rule: the enabled policy with the smallest
// id. "Exactly one policy" is not the rule — the common case is several
// policies, each owning a different dimension, and that case used to get null.
func TestRedeem_AttributesSmallestEnabledPolicy(t *testing.T) {
	h := newHarness(t)
	first := h.addPolicy(t, nil)
	h.addPolicy(t, nil)
	h.addPolicy(t, nil)

	disabled := model.Policy{OrganizationID: h.org.ID, Name: "off", Enabled: false}
	require.NoError(t, h.db.Create(&disabled).Error)

	ticketID, token := h.issue(t)
	sess, err := h.svc.Redeem(context.Background(), h.org.ID, 1, ticketID, token)
	require.NoError(t, err)

	require.NotNil(t, sess.PolicyID)
	require.Equal(t, first.ID, *sess.PolicyID, "the smallest enabled policy id wins")
}

// A colleague redeeming someone else's token must not appear as the session's
// initiator: the chain policy → ticket → session has to line up, and the
// redeemer is recorded in the audit entry instead.
func TestRedeem_AttributesSessionToIssuer(t *testing.T) {
	h := newHarness(t)

	ticket, token, err := h.svc.Issue(context.Background(), session.IssueInput{
		OrganizationID: h.org.ID, ActorUserID: 7, DeviceID: h.device.ID,
	})
	require.NoError(t, err)

	sess, err := h.svc.Redeem(context.Background(), h.org.ID, 9, ticket.ID, token)
	require.NoError(t, err)

	require.NotNil(t, sess.ActorUserID)
	require.Equal(t, uint(7), *sess.ActorUserID, "the session belongs to the issuer")

	last := h.recorder.entries[len(h.recorder.entries)-1]
	require.Equal(t, "session.ticket.redeem", last.Action)
	require.Equal(t, uint(9), last.ActorUserID, "the redeemer is who performed the redemption")
	require.Equal(t, uint(7), last.Detail["issued_to_user_id"])
	require.Equal(t, uint(9), last.Detail["redeemed_by"])
}

// An approval that expired between approval and use must not authorise a
// ticket: approving something no longer actionable is exactly what the expiry
// is for.
func TestIssue_RejectsExpiredApproval(t *testing.T) {
	h := newHarness(t)
	h.addPolicy(t, func(p *model.Policy) { p.RequireApproval = true })

	approval := model.Approval{
		OrganizationID: h.org.ID, DeviceID: h.device.ID, Kind: model.ApprovalKindPre,
		ActorUserID: 1, Status: model.ApprovalStatusApproved,
		RequestedAt: h.now.Add(-2 * time.Hour),
		ExpiresAt:   h.now.Add(-time.Hour), // approved, but past its window
	}
	require.NoError(t, h.db.Create(&approval).Error)

	_, _, err := h.svc.Issue(context.Background(), session.IssueInput{
		OrganizationID: h.org.ID, ActorUserID: 1, DeviceID: h.device.ID,
	})
	var need *session.ErrApprovalRequired
	require.ErrorAs(t, err, &need, "an expired approval cannot authorise issuance")
}

// Reusing an expired pending row would hand the client a dead id forever: it
// cannot be approved, so every retry returns the same approval_required.
func TestIssue_DoesNotReuseExpiredPendingApproval(t *testing.T) {
	h := newHarness(t)
	h.addPolicy(t, func(p *model.Policy) { p.RequireApproval = true })

	stale := model.Approval{
		OrganizationID: h.org.ID, DeviceID: h.device.ID, Kind: model.ApprovalKindPre,
		ActorUserID: 1, Status: model.ApprovalStatusPending,
		RequestedAt: h.now.Add(-time.Hour),
		ExpiresAt:   h.now.Add(-time.Minute),
	}
	require.NoError(t, h.db.Create(&stale).Error)

	_, _, err := h.svc.Issue(context.Background(), session.IssueInput{
		OrganizationID: h.org.ID, ActorUserID: 1, DeviceID: h.device.ID,
	})
	var need *session.ErrApprovalRequired
	require.ErrorAs(t, err, &need)
	require.NotEqual(t, stale.ID, need.ApprovalID, "an expired pending row is not reused")

	var rows []model.Approval
	require.NoError(t, store.WithoutTenantScope(h.db).Where("organization_id = ?", h.org.ID).Find(&rows).Error)
	require.Len(t, rows, 2, "a fresh pending request is created beside the stale one")
}

// ── review round: concurrency ───────────────────────────────────────────────

// The one-shot guarantee under concurrency: two goroutines redeeming the same
// ticket must produce exactly one session.
//
// Honest scope note: on SQLite the connection pool serialises writers, so this
// proves the conditional claim but not the row lock. The lock is exercised on
// MySQL/PostgreSQL, where CI's test-db job points the same suite at real
// dialects via TEST_MYSQL_DSN / TEST_POSTGRES_DSN.
func TestRedeem_ConcurrentRedeemOfSameTicket(t *testing.T) {
	h := newHarness(t)
	ticketID, token := h.issue(t)

	var okCount, conflictCount int32
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := h.svc.Redeem(context.Background(), h.org.ID, 1, ticketID, token)
			switch {
			case err == nil:
				atomic.AddInt32(&okCount, 1)
			case errors.Is(err, session.ErrConflict):
				atomic.AddInt32(&conflictCount, 1)
			default:
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	wg.Wait()

	require.Equal(t, int32(1), atomic.LoadInt32(&okCount), "exactly one redemption may succeed")
	require.Equal(t, int32(3), atomic.LoadInt32(&conflictCount), "the rest must be refused")

	var sessions []model.Session
	require.NoError(t, store.WithoutTenantScope(h.db).
		Where("organization_id = ? AND origin = ?", h.org.ID, model.SessionOriginPanel).Find(&sessions).Error)
	require.Len(t, sessions, 1)
}

// Two different tickets against a limit of one: this is the interleaving the
// organization row lock exists for ("issue N tickets, redeem them in parallel").
func TestRedeem_ConcurrentRedeemOfDifferentTicketsRespectsLimit(t *testing.T) {
	h := newHarness(t)
	limit := int64(1)
	h.addPolicy(t, func(p *model.Policy) { p.MaxConcurrentSessions = &limit })

	firstID, firstToken := h.issue(t)
	secondID, secondToken := h.issue(t)

	start := make(chan struct{})
	var okCount int32
	var wg sync.WaitGroup
	for _, tc := range []struct {
		id    uint
		token string
	}{{firstID, firstToken}, {secondID, secondToken}} {
		wg.Add(1)
		go func(id uint, token string) {
			defer wg.Done()
			<-start
			if _, err := h.svc.Redeem(context.Background(), h.org.ID, 1, id, token); err == nil {
				atomic.AddInt32(&okCount, 1)
			}
		}(tc.id, tc.token)
	}
	close(start)
	wg.Wait()

	require.Equal(t, int32(1), atomic.LoadInt32(&okCount),
		"a limit of one admits exactly one session, whoever wins the race")
}

// ── review round: audit coverage for the remaining paths ───────────────────

// The denied path writes two rows (session + audit) in one transaction; a failing
// auditor must leave neither behind.
func TestIssue_DeniedAuditFailureRollsBack(t *testing.T) {
	h := newHarness(t)
	h.addPolicy(t, func(p *model.Policy) {
		start, end := int64(540), int64(1020)
		p.AllowedStartMinute, p.AllowedEndMinute = &start, &end
	})
	h.setClock(time.Date(2026, 10, 22, 3, 0, 0, 0, time.UTC))

	h.recorder.fail = errors.New("audit unavailable")
	_, _, err := h.svc.Issue(context.Background(), session.IssueInput{
		OrganizationID: h.org.ID, ActorUserID: 1, DeviceID: h.device.ID,
	})
	require.Error(t, err)

	var sessions []model.Session
	require.NoError(t, store.WithoutTenantScope(h.db).
		Where("organization_id = ?", h.org.ID).Find(&sessions).Error)
	require.Empty(t, sessions, "a failed audit must roll the denied row back too")
}

// Redemption's audit is transactional as well.
func TestRedeem_AuditFailureRollsBack(t *testing.T) {
	h := newHarness(t)
	ticketID, token := h.issue(t)

	h.recorder.fail = errors.New("audit unavailable")
	_, err := h.svc.Redeem(context.Background(), h.org.ID, 1, ticketID, token)
	require.Error(t, err)

	var stored model.Ticket
	require.NoError(t, store.WithoutTenantScope(h.db).First(&stored, ticketID).Error)
	require.Nil(t, stored.UsedAt, "a refused redemption must not burn the ticket")

	var sessions []model.Session
	require.NoError(t, store.WithoutTenantScope(h.db).
		Where("organization_id = ?", h.org.ID).Find(&sessions).Error)
	require.Empty(t, sessions)
}

// A service with no recorder must refuse to write rather than commit an
// unaudited ticket: the audit row is what makes the mutation reconstructable
// afterwards.
func TestIssue_WithoutRecorderFailsClosed(t *testing.T) {
	h := newHarness(t)
	h.svc = session.NewService(h.db, nil, func() time.Time { return h.now })

	_, _, err := h.svc.Issue(context.Background(), session.IssueInput{
		OrganizationID: h.org.ID, ActorUserID: 1, DeviceID: h.device.ID,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "no audit recorder")

	var tickets []model.Ticket
	require.NoError(t, store.WithoutTenantScope(h.db).
		Where("organization_id = ?", h.org.ID).Find(&tickets).Error)
	require.Empty(t, tickets, "no ticket may be committed without an audit entry")
}

// The approval request is itself a domain mutation and is audited.
func TestIssue_ApprovalRequestIsAudited(t *testing.T) {
	h := newHarness(t)
	h.addPolicy(t, func(p *model.Policy) { p.RequireApproval = true })

	_, _, err := h.svc.Issue(context.Background(), session.IssueInput{
		OrganizationID: h.org.ID, ActorUserID: 1, DeviceID: h.device.ID,
	})
	var need *session.ErrApprovalRequired
	require.ErrorAs(t, err, &need)

	require.Contains(t, h.recorder.actions(), "session.approval.request",
		"creating the approval request is an audited mutation")
}
