package oidc

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/config"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

var flowSeq atomic.Uint64

type testClock struct{ at time.Time }

func (c *testClock) Now() time.Time { return c.at }

func newFlowService(t *testing.T) (*Service, *testClock) {
	t.Helper()

	st, err := store.Open(config.DatabaseConfig{
		Driver: "sqlite",
		DSN:    fmt.Sprintf("file:oidc_flow_%d?mode=memory&cache=shared", flowSeq.Add(1)),
	})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	// Serialise writers: the concurrency case proves the conditional update,
	// not SQLite's locking.
	sqlDB, err := st.DB.DB()
	if err != nil {
		t.Fatalf("sql db: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)

	if err := st.DB.AutoMigrate(&model.User{}, &model.ExternalLoginFlow{}, &model.UserIdentity{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	clock := &testClock{at: time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)}
	return NewService(st.DB, Config{
		ProviderName: "Test IdP",
		StateTTL:     10 * time.Minute,
		Now:          clock.Now,
	}, zap.NewNop()), clock
}

func newFlow(t *testing.T, s *Service, state string) *model.ExternalLoginFlow {
	t.Helper()
	f := &model.ExternalLoginFlow{
		State:        state,
		Provider:     model.IdentityProviderOIDC,
		Nonce:        "nonce-" + state,
		PKCEVerifier: "verifier-" + state,
		RedirectPath: "/devices",
		ExpiresAt:    s.cfg.Now().Add(s.cfg.StateTTL),
	}
	if err := s.createFlow(context.Background(), f); err != nil {
		t.Fatalf("createFlow: %v", err)
	}
	return f
}

func TestConsumeState_OnceOnly(t *testing.T) {
	s, _ := newFlowService(t)
	newFlow(t, s, "state-1")

	if _, err := s.consumeState(context.Background(), "state-1"); err != nil {
		t.Fatalf("first consume: %v", err)
	}
	if _, err := s.consumeState(context.Background(), "state-1"); !errors.Is(err, ErrStateUsed) {
		t.Fatalf("second consume = %v, want ErrStateUsed", err)
	}
}

func TestConsumeState_UnknownIsInvalid(t *testing.T) {
	s, _ := newFlowService(t)
	if _, err := s.consumeState(context.Background(), "nope"); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("consume unknown = %v, want ErrInvalidState", err)
	}
}

// TestConsumeState_ExpiresExactlyAtTTL pins the comparison: a state is dead at
// its expiry instant, and a rejected row must not be burned as "used".
func TestConsumeState_ExpiresExactlyAtTTL(t *testing.T) {
	s, clock := newFlowService(t)
	f := newFlow(t, s, "state-ttl")

	clock.at = f.ExpiresAt

	if _, err := s.consumeState(context.Background(), "state-ttl"); !errors.Is(err, ErrStateExpired) {
		t.Fatalf("consume at expiry = %v, want ErrStateExpired", err)
	}
	var row model.ExternalLoginFlow
	if err := s.db.Where("state = ?", "state-ttl").First(&row).Error; err != nil {
		t.Fatalf("reload: %v", err)
	}
	if row.ConsumedAt != nil {
		t.Fatal("an expired state was marked consumed; a retry inside the window would then fail as 'used'")
	}
}

func TestConsumeState_Concurrent(t *testing.T) {
	s, _ := newFlowService(t)
	newFlow(t, s, "state-race")

	const workers = 20
	var wg sync.WaitGroup
	var wins atomic.Int64
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.consumeState(context.Background(), "state-race"); err == nil {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if got := wins.Load(); got != 1 {
		t.Fatalf("successful consumptions = %d, want exactly 1", got)
	}
}

func TestAttachTicket_RequiresConsumedState(t *testing.T) {
	s, _ := newFlowService(t)
	newFlow(t, s, "state-unconsumed")

	if err := s.attachTicket(context.Background(), "state-unconsumed", "hash-1", 7, time.Minute); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("attach before consume = %v, want ErrInvalidState", err)
	}
}

func TestConsumeTicket_OnceOnly(t *testing.T) {
	s, _ := newFlowService(t)
	newFlow(t, s, "state-ticket")
	if _, err := s.consumeState(context.Background(), "state-ticket"); err != nil {
		t.Fatalf("consume state: %v", err)
	}
	if err := s.attachTicket(context.Background(), "state-ticket", "hash-ticket", 42, time.Minute); err != nil {
		t.Fatalf("attach ticket: %v", err)
	}

	userID, err := s.consumeTicket(context.Background(), "hash-ticket")
	if err != nil {
		t.Fatalf("first ticket consume: %v", err)
	}
	if userID != 42 {
		t.Fatalf("user id = %d, want 42", userID)
	}
	if _, err := s.consumeTicket(context.Background(), "hash-ticket"); !errors.Is(err, ErrInvalidTicket) {
		t.Fatalf("second ticket consume = %v, want ErrInvalidTicket", err)
	}
}

func TestConsumeTicket_ExpiresExactlyAtTTL(t *testing.T) {
	s, clock := newFlowService(t)
	newFlow(t, s, "state-texp")
	if _, err := s.consumeState(context.Background(), "state-texp"); err != nil {
		t.Fatalf("consume state: %v", err)
	}
	if err := s.attachTicket(context.Background(), "state-texp", "hash-exp", 5, time.Minute); err != nil {
		t.Fatalf("attach: %v", err)
	}

	clock.at = clock.at.Add(time.Minute)
	if _, err := s.consumeTicket(context.Background(), "hash-exp"); !errors.Is(err, ErrInvalidTicket) {
		t.Fatalf("ticket at expiry = %v, want ErrInvalidTicket", err)
	}
}

func TestSweep_RemovesOnlyExpiredFlows(t *testing.T) {
	s, clock := newFlowService(t)

	// A state that runs out at 12:10.
	expired := newFlow(t, s, "state-old")

	// A flow whose state is live long enough but whose ticket expires at once.
	newFlow(t, s, "state-ticketed")
	if _, err := s.consumeState(context.Background(), "state-ticketed"); err != nil {
		t.Fatalf("consume: %v", err)
	}
	if err := s.attachTicket(context.Background(), "state-ticketed", "hash-old", 9, time.Second); err != nil {
		t.Fatalf("attach: %v", err)
	}

	// 12:20: the two above are dead, and a fresh flow is live until 12:30.
	clock.at = clock.at.Add(20 * time.Minute)
	live := newFlow(t, s, "state-live")

	removed, err := s.Sweep(context.Background(), clock.at.Add(-5*time.Minute))
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if removed != 2 {
		t.Fatalf("removed = %d, want 2 (expired state + expired ticket)", removed)
	}

	var remaining []string
	if err := s.db.Model(&model.ExternalLoginFlow{}).Pluck("state", &remaining).Error; err != nil {
		t.Fatalf("pluck: %v", err)
	}
	if len(remaining) != 1 || remaining[0] != live.State {
		t.Fatalf("remaining = %v, want only %s", remaining, live.State)
	}
	_ = expired
}
