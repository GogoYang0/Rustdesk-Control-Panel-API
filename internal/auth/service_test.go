package auth_test

import (
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

	// 新 access 可解析
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

	// 重放旧 refresh：必须失败
	_, _, err = svc.RotateRefresh(r1)
	require.Error(t, err)

	// 且该用户全部 refresh 失效（含刚签发的新 token）
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
