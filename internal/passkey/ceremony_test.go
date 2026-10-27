package passkey

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/config"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/require"
)

var ceremonySeq atomic.Int64

// testClock lets a test move time forward without sleeping.
type testClock struct{ at time.Time }

func (c *testClock) Now() time.Time { return c.at }

func newCeremonyService(t *testing.T) (*Service, *testClock) {
	t.Helper()

	st, err := store.Open(config.DatabaseConfig{
		Driver: "sqlite",
		DSN:    fmt.Sprintf("file:passkey_ceremony_%d?mode=memory&cache=shared", ceremonySeq.Add(1)),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	// Serialise writers: the concurrency test proves the conditional update,
	// not SQLite's locking behaviour.
	sqlDB, err := st.DB.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)

	require.NoError(t, st.DB.AutoMigrate(&model.WebAuthnCeremony{}))

	clock := &testClock{at: time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)}
	return &Service{
		db:  st.DB,
		now: clock.Now,
		cfg: Config{CeremonyTTL: 5 * time.Minute},
	}, clock
}

func beginTestCeremony(t *testing.T, s *Service, purpose model.CeremonyPurpose) string {
	t.Helper()

	handle, err := s.beginCeremony(context.Background(), purpose, nil, &webauthn.SessionData{
		Challenge: "challenge-value",
		Expires:   s.now().Add(s.cfg.CeremonyTTL),
	})
	require.NoError(t, err)
	return handle
}

func TestConsumeCeremony_SecondCallFails(t *testing.T) {
	s, _ := newCeremonyService(t)
	handle := beginTestCeremony(t, s, model.CeremonyRegister)

	_, _, err := s.consumeCeremony(context.Background(), handle, model.CeremonyRegister)
	require.NoError(t, err)

	_, _, err = s.consumeCeremony(context.Background(), handle, model.CeremonyRegister)
	require.ErrorIs(t, err, ErrCeremonyUsed)
}

func TestConsumeCeremony_Expired(t *testing.T) {
	s, clock := newCeremonyService(t)
	handle := beginTestCeremony(t, s, model.CeremonyLogin)

	clock.at = clock.at.Add(s.cfg.CeremonyTTL + time.Second)

	_, _, err := s.consumeCeremony(context.Background(), handle, model.CeremonyLogin)
	require.ErrorIs(t, err, ErrCeremonyExpired)
}

func TestConsumeCeremony_WrongPurpose(t *testing.T) {
	s, _ := newCeremonyService(t)
	handle := beginTestCeremony(t, s, model.CeremonyRegister)

	_, _, err := s.consumeCeremony(context.Background(), handle, model.CeremonyLogin)
	require.ErrorIs(t, err, ErrCeremonyNotFound)

	// The failed attempt must not have burned the ceremony.
	_, _, err = s.consumeCeremony(context.Background(), handle, model.CeremonyRegister)
	require.NoError(t, err)
}

func TestConsumeCeremony_UnknownHandle(t *testing.T) {
	s, _ := newCeremonyService(t)

	_, _, err := s.consumeCeremony(context.Background(), "does-not-exist", model.CeremonyLogin)
	require.ErrorIs(t, err, ErrCeremonyNotFound)
}

func TestConsumeCeremony_Concurrent(t *testing.T) {
	s, _ := newCeremonyService(t)
	handle := beginTestCeremony(t, s, model.CeremonyLogin)

	const workers = 8
	var success, used atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, err := s.consumeCeremony(context.Background(), handle, model.CeremonyLogin)
			switch {
			case err == nil:
				success.Add(1)
			case errors.Is(err, ErrCeremonyUsed):
				used.Add(1)
			default:
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	wg.Wait()

	require.EqualValues(t, 1, success.Load(), "exactly one consumer may win")
	require.EqualValues(t, workers-1, used.Load())
}

func TestConsumeStepup_SecondCallFails(t *testing.T) {
	s, _ := newCeremonyService(t)
	handle := beginTestCeremony(t, s, model.CeremonyStepup)
	_, _, err := s.consumeCeremony(context.Background(), handle, model.CeremonyStepup)
	require.NoError(t, err)

	require.NoError(t, s.consumeStepup(context.Background(), handle))
	require.ErrorIs(t, s.consumeStepup(context.Background(), handle), ErrStepupUsed)
}

// TestCeremonyRowsAreScopedToTheirPurpose keeps the purpose column honest on
// the storage layer: a register row must remain consumable as register.
func TestCeremonyRowsAreScopedToTheirPurpose(t *testing.T) {
	s, _ := newCeremonyService(t)
	handle := beginTestCeremony(t, s, model.CeremonyStepup)

	var row model.WebAuthnCeremony
	require.NoError(t, s.db.Where("handle = ?", handle).First(&row).Error)
	require.Equal(t, model.CeremonyStepup, row.Purpose)
	require.Nil(t, row.ConsumedAt)

	_, _, err := s.consumeCeremony(context.Background(), handle, model.CeremonyStepup)
	require.NoError(t, err)
	require.NoError(t, s.consumeStepup(context.Background(), handle))
	require.NoError(t, s.db.Where("handle = ?", handle).First(&row).Error)
	require.NotNil(t, row.StepupUsedAt)
}

// TestBeginCeremonyStoresExpiry guards the TTL wiring: an expiry in the past
// would make every ceremony dead on arrival.
func TestBeginCeremonyStoresExpiry(t *testing.T) {
	s, _ := newCeremonyService(t)
	handle := beginTestCeremony(t, s, model.CeremonyRegister)

	var row model.WebAuthnCeremony
	require.NoError(t, s.db.Where("handle = ?", handle).First(&row).Error)
	require.WithinDuration(t, s.now().Add(s.cfg.CeremonyTTL), row.ExpiresAt, time.Second)
}
