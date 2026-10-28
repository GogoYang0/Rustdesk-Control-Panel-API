package session_test

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/session"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// fakeAccess stands in for access.Service. The session package must not import
// it (the API layer wires the real evaluator), so these tests pin the service's
// own contract: when the evaluator is consulted and what a refusal means.
type fakeAccess struct {
	allow bool
	err   error
	calls int
}

func (f *fakeAccess) CanAccessTx(_ *gorm.DB, _, _, _ uint) (bool, error) {
	f.calls++
	return f.allow, f.err
}

// grantRowAccess answers from a database row, so the concurrency test can
// revoke access from another connection while the redemption is blocked on the
// organization lock.
type grantRowAccess struct{}

func (grantRowAccess) CanAccessTx(tx *gorm.DB, orgID, _, _ uint) (bool, error) {
	var n int64
	err := store.ScopedByOrg(tx, orgID).Model(&model.Policy{}).
		Where("name = ?", "grant").Count(&n).Error
	return n > 0, err
}

func requireTicketUnused(t *testing.T, h *harness, ticketID uint) {
	t.Helper()
	var stored model.Ticket
	require.NoError(t, store.WithoutTenantScope(h.db).First(&stored, ticketID).Error)
	require.Nil(t, stored.UsedAt, "a refused redemption must not consume the ticket")
}

func requireNoSessions(t *testing.T, h *harness) {
	t.Helper()
	var sessions int64
	require.NoError(t, store.ScopedByOrg(h.db, h.org.ID).Model(&model.Session{}).Count(&sessions).Error)
	require.Zero(t, sessions, "a refused redemption must not open a panel session")
}

// TestRedeem_RequiresAccessEvaluator pins fail-closed wiring: a redemption must
// never run without the in-transaction re-check, because the handler's earlier
// decision is exactly the one this feature exists to re-verify.
func TestRedeem_RequiresAccessEvaluator(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	ticket, token, err := h.svc.Issue(ctx, session.IssueInput{
		OrganizationID: h.org.ID, ActorUserID: 1, DeviceID: h.device.ID,
	})
	require.NoError(t, err)

	unwired := session.NewService(h.db, h.recorder, func() time.Time { return h.now })
	_, err = unwired.Redeem(ctx, h.org.ID, 1, ticket.ID, token)
	require.ErrorIs(t, err, session.ErrAccessUnconfigured)

	requireTicketUnused(t, h, ticket.ID)
	requireNoSessions(t, h)
}

// TestRedeem_AccessRefusalKeepsTicketUnused proves a refusal decided inside the
// transaction is not observable as a consumed ticket: restoring access lets the
// same token redeem.
func TestRedeem_AccessRefusalKeepsTicketUnused(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	ticket, token, err := h.svc.Issue(ctx, session.IssueInput{
		OrganizationID: h.org.ID, ActorUserID: 1, DeviceID: h.device.ID,
	})
	require.NoError(t, err)

	deny := &fakeAccess{}
	_, err = h.svc.WithAccess(deny).Redeem(ctx, h.org.ID, 1, ticket.ID, token)
	require.ErrorIs(t, err, session.ErrAccessDenied)
	require.Equal(t, 1, deny.calls, "the evaluator must run exactly once per redemption")

	requireTicketUnused(t, h, ticket.ID)
	requireNoSessions(t, h)

	allow := &fakeAccess{allow: true}
	sess, err := h.svc.WithAccess(allow).Redeem(ctx, h.org.ID, 1, ticket.ID, token)
	require.NoError(t, err)
	require.Equal(t, h.device.ID, sess.DeviceID)
}

// TestRedeem_AccessEvaluatorErrorAborts keeps a broken evaluation fail-closed:
// the redemption is refused and the ticket stays usable, so the operator sees a
// server error instead of a session nobody authorised.
func TestRedeem_AccessEvaluatorErrorAborts(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	ticket, token, err := h.svc.Issue(ctx, session.IssueInput{
		OrganizationID: h.org.ID, ActorUserID: 1, DeviceID: h.device.ID,
	})
	require.NoError(t, err)

	boom := errors.New("access store unavailable")
	_, err = h.svc.WithAccess(&fakeAccess{allow: true, err: boom}).
		Redeem(ctx, h.org.ID, 1, ticket.ID, token)
	require.ErrorIs(t, err, boom)

	requireTicketUnused(t, h, ticket.ID)
	requireNoSessions(t, h)
}

// TestRedeem_DisabledDeviceOutranksAccessRefusal pins the order inside the
// transaction: the device state is decided first, so the documented 409 for a
// stopped device cannot be rewritten into the opaque 404 of an access refusal.
func TestRedeem_DisabledDeviceOutranksAccessRefusal(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	ticket, token, err := h.svc.Issue(ctx, session.IssueInput{
		OrganizationID: h.org.ID, ActorUserID: 1, DeviceID: h.device.ID,
	})
	require.NoError(t, err)
	require.NoError(t, store.ScopedByOrg(h.db, h.org.ID).Model(&model.Device{}).
		Where("id = ?", h.device.ID).Update("disabled", true).Error)

	deny := &fakeAccess{}
	_, err = h.svc.WithAccess(deny).Redeem(ctx, h.org.ID, 1, ticket.ID, token)
	require.ErrorIs(t, err, session.ErrDeviceDisabled)
	require.Zero(t, deny.calls, "the device check must run before the access re-check")
}

// TestRedeem_SerialisesWithRuleRevocation is the lock-order regression the
// issue asks for: every access mutation takes the organization row lock, and
// redemption holds the same lock, so a revocation committed during a
// redemption must be visible to the re-check instead of arriving "after" it.
//
// SQLite is skipped: its dialect omits SELECT ... FOR UPDATE and serialises
// writers outright, so the interleaving cannot be expressed there — the same
// reason the other locking regressions are gated on a real dialect.
func TestRedeem_SerialisesWithRuleRevocation(t *testing.T) {
	if os.Getenv("TEST_POSTGRES_DSN") == "" && os.Getenv("TEST_MYSQL_DSN") == "" {
		t.Skip("row-lock ordering needs PostgreSQL/MySQL; CI test-db runs this")
	}
	h := newHarness(t)
	ctx := context.Background()
	// A disabled policy is inert for the limits fold, so it only acts as the
	// access marker the evaluator reads.
	require.NoError(t, h.db.Create(&model.Policy{
		OrganizationID: h.org.ID, Name: "grant", Enabled: false,
	}).Error)
	ticket, token, err := h.svc.Issue(ctx, session.IssueInput{
		OrganizationID: h.org.ID, ActorUserID: 1, DeviceID: h.device.ID,
	})
	require.NoError(t, err)
	h.svc.WithAccess(grantRowAccess{})

	tx := h.db.Begin()
	require.NoError(t, tx.Error)
	defer func() { _ = tx.Rollback() }()
	var org model.Organization
	require.NoError(t, tx.Clauses(clause.Locking{Strength: "UPDATE"}).
		Where("id = ?", h.org.ID).First(&org).Error)
	require.NoError(t, store.ScopedByOrg(tx, h.org.ID).
		Where("name = ?", "grant").Delete(&model.Policy{}).Error)

	done := make(chan error, 1)
	go func() {
		_, err := h.svc.Redeem(ctx, h.org.ID, 1, ticket.ID, token)
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("redemption did not wait for the holding transaction: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	require.NoError(t, tx.Commit().Error)

	require.ErrorIs(t, <-done, session.ErrAccessDenied)
	requireTicketUnused(t, h, ticket.ID)
	requireNoSessions(t, h)
}
