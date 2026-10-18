package auth_test

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/auth"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/config"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

func newTestService(t *testing.T) (*auth.Service, func()) {
	t.Helper()
	s, err := store.Open(config.DatabaseConfig{Driver: "sqlite", DSN: "file::memory:?cache=shared"})
	require.NoError(t, err)
	require.NoError(t, s.DB.AutoMigrate(&model.User{}, &model.RefreshToken{}))

	svc := auth.NewService(s.DB, auth.NewIssuer("test-secret", time.Minute, time.Hour), nil)
	return svc, func() { _ = s.Close() }
}

func TestRotateRefresh_ReturnsNewPair(t *testing.T) {
	svc, cleanup := newTestService(t)
	defer cleanup()

	access, refresh, err := svc.IssueTokens(1)
	require.NoError(t, err)

	newAccess, newRefresh, err := svc.RotateRefresh(refresh)
	require.NoError(t, err)
	require.NotEqual(t, access, newAccess)
	require.NotEqual(t, refresh, newRefresh)

	// the new access token must parse
	uid, err := svc.Issuer().ParseAccess(newAccess)
	require.NoError(t, err)
	require.EqualValues(t, 1, uid)
}

func TestRotateRefresh_ReplayRevokesFamily(t *testing.T) {
	svc, cleanup := newTestService(t)
	defer cleanup()

	_, r1, err := svc.IssueTokens(5)
	require.NoError(t, err)

	_, r2, err := svc.RotateRefresh(r1)
	require.NoError(t, err)

	// replaying the old refresh token must fail
	_, _, err = svc.RotateRefresh(r1)
	require.Error(t, err)

	// and every refresh token of the user must be revoked, including the fresh one
	_, _, err = svc.RotateRefresh(r2)
	require.Error(t, err, "replay must revoke the whole token family")
}

func TestRotateRefresh_Expired_Fails(t *testing.T) {
	s, err := store.Open(config.DatabaseConfig{Driver: "sqlite", DSN: "file::memory:?cache=shared"})
	require.NoError(t, err)
	defer func() { _ = s.Close() }()
	require.NoError(t, s.DB.AutoMigrate(&model.User{}, &model.RefreshToken{}))

	svc := auth.NewService(s.DB, auth.NewIssuer("test-secret", time.Minute, -time.Minute), nil)

	_, refresh, err := svc.IssueTokens(3)
	require.NoError(t, err)

	_, _, err = svc.RotateRefresh(refresh)
	require.Error(t, err)
}

func TestRotateRefresh_ConcurrentOnlyOneSucceeds(t *testing.T) {
	svc, cleanup := newTestService(t)
	defer cleanup()

	_, r1, err := svc.IssueTokens(6)
	require.NoError(t, err)

	var wg sync.WaitGroup
	var success, failed int32
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, err := svc.RotateRefresh(r1); err == nil {
				atomic.AddInt32(&success, 1)
			} else {
				atomic.AddInt32(&failed, 1)
			}
		}()
	}
	wg.Wait()

	require.EqualValues(t, 1, success, "exactly one rotation may succeed")
	require.EqualValues(t, 1, failed, "the racing request must be treated as replay")
}
