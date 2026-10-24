package auth_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/auth"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/config"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

func newTokenStore(t *testing.T) (*store.Store, model.Organization) {
	t.Helper()
	dsn := fmt.Sprintf("file:token_%d?mode=memory&cache=shared", time.Now().UnixNano())
	st, err := store.Open(config.DatabaseConfig{Driver: "sqlite", DSN: dsn})
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	require.NoError(t, st.DB.AutoMigrate(&model.Organization{}, &model.APIToken{}))
	org := model.Organization{Name: "token-org"}
	require.NoError(t, st.DB.Create(&org).Error)
	return st, org
}

func TestToken_RoundTripAndNoPlaintextAtRest(t *testing.T) {
	st, org := newTokenStore(t)
	svc := auth.NewTokenService(st.DB, nil)
	ctx := context.Background()

	plain, row, err := svc.Create(ctx, 7, org.ID, "ci", []string{"device.read"}, time.Hour)
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(plain, auth.TokenPlainPrefix))
	require.Equal(t, plain[:8], row.TokenPrefix)
	require.NotContains(t, row.TokenHash, plain, "the digest must not contain the plaintext")
	require.Len(t, row.TokenHash, 64)

	// The database stores only the digest.
	var stored model.APIToken
	require.NoError(t, store.WithoutTenantScope(st.DB).First(&stored, row.ID).Error)
	require.NotEqual(t, plain, stored.TokenHash)
	require.Equal(t, []string{"device.read"}, stored.PermissionList())

	got, err := svc.Authenticate(ctx, plain)
	require.NoError(t, err)
	require.Equal(t, row.ID, got.ID)
	require.NotNil(t, got.LastUsedAt)

	var refreshed model.APIToken
	require.NoError(t, store.WithoutTenantScope(st.DB).First(&refreshed, row.ID).Error)
	require.NotNil(t, refreshed.LastUsedAt)
}

func TestToken_ExpiredAndRevokedRejected(t *testing.T) {
	st, org := newTokenStore(t)
	svc := auth.NewTokenService(st.DB, nil)
	ctx := context.Background()

	plain, row, err := svc.Create(ctx, 7, org.ID, "short", []string{"device.read"}, time.Hour)
	require.NoError(t, err)
	require.NoError(t, store.WithoutTenantScope(st.DB).Model(&model.APIToken{}).
		Where("id = ?", row.ID).Update("expires_at", time.Now().Add(-time.Minute)).Error)
	_, err = svc.Authenticate(ctx, plain)
	require.ErrorIs(t, err, auth.ErrTokenInactive)

	plain, row, err = svc.Create(ctx, 7, org.ID, "revoked", []string{"device.read"}, time.Hour)
	require.NoError(t, err)
	require.NoError(t, svc.Revoke(ctx, 7, row.ID))
	_, err = svc.Authenticate(ctx, plain)
	require.ErrorIs(t, err, auth.ErrTokenInactive)

	_, err = svc.Authenticate(ctx, "rdt_unknown")
	require.ErrorIs(t, err, auth.ErrTokenNotFound)
	_, err = svc.Authenticate(ctx, "")
	require.ErrorIs(t, err, auth.ErrTokenNotFound)
}

func TestToken_LimitAndOwnership(t *testing.T) {
	st, org := newTokenStore(t)
	svc := auth.NewTokenService(st.DB, nil)
	ctx := context.Background()

	var last *model.APIToken
	for i := 0; i < auth.MaxTokensPerUserOrg; i++ {
		_, row, err := svc.Create(ctx, 7, org.ID, fmt.Sprintf("t-%d", i), []string{"device.read"}, time.Hour)
		require.NoError(t, err)
		last = row
	}
	_, _, err := svc.Create(ctx, 7, org.ID, "over", []string{"device.read"}, time.Hour)
	require.ErrorIs(t, err, auth.ErrTooManyTokens)

	// Revoking frees a slot (revoked counts as inactive).
	require.NoError(t, svc.Revoke(ctx, 7, last.ID))
	_, _, err = svc.Create(ctx, 7, org.ID, "freed", []string{"device.read"}, time.Hour)
	require.NoError(t, err)

	// Another user cannot revoke it.
	require.ErrorIs(t, svc.Revoke(ctx, 8, last.ID), auth.ErrTokenNotFound)

	list, err := svc.List(ctx, 7, org.ID)
	require.NoError(t, err)
	require.Len(t, list, auth.MaxTokensPerUserOrg+1, "revoked tokens stay listed for the owner")
	other, err := svc.List(ctx, 8, org.ID)
	require.NoError(t, err)
	require.Empty(t, other)
}

func TestToken_NameValidation(t *testing.T) {
	st, org := newTokenStore(t)
	svc := auth.NewTokenService(st.DB, nil)
	ctx := context.Background()

	_, _, err := svc.Create(ctx, 7, org.ID, "   ", nil, time.Hour)
	require.ErrorIs(t, err, auth.ErrInvalidTokenInput)
	_, _, err = svc.Create(ctx, 7, org.ID, strings.Repeat("a", 129), nil, time.Hour)
	require.ErrorIs(t, err, auth.ErrInvalidTokenInput)
	_, _, err = svc.Create(ctx, 0, org.ID, "api", nil, time.Hour)
	require.ErrorIs(t, err, auth.ErrInvalidTokenInput)
}
