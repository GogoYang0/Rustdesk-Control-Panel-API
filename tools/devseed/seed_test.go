package main

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/auth"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/config"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

func TestSeed_CreatesLoginAndIsIdempotent(t *testing.T) {
	dsn := fmt.Sprintf("file:devseed_%d?mode=memory&cache=shared", time.Now().UnixNano())
	st, err := store.Open(config.DatabaseConfig{Driver: "sqlite", DSN: dsn})
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	opts := Options{
		OrgName:       "Seed Org",
		AdminEmail:    "seed-owner@example.test",
		AdminPassword: "owner-pass",
		OpsEmail:      "seed-ops@example.test",
		OpsPassword:   "ops-pass",
	}
	first, err := Seed(st.DB, opts)
	require.NoError(t, err)
	second, err := Seed(st.DB, opts)
	require.NoError(t, err)
	require.Equal(t, first.OrgID, second.OrgID)
	require.Equal(t, first.AdminEmail, second.AdminEmail)

	var users, memberships int64
	require.NoError(t, store.WithoutTenantScope(st.DB).Model(&model.User{}).Count(&users).Error)
	require.NoError(t, store.WithoutTenantScope(st.DB).Model(&model.Membership{}).Count(&memberships).Error)
	require.EqualValues(t, 2, users)
	require.EqualValues(t, 2, memberships)

	var events int64
	require.NoError(t, store.WithoutTenantScope(st.DB).Model(&model.LogEvent{}).Count(&events).Error)
	require.EqualValues(t, 4, events, "sample events are replaced, not duplicated")

	var admin model.User
	require.NoError(t, st.DB.Where("email = ?", opts.AdminEmail).First(&admin).Error)
	ok, err := auth.VerifyPassword(admin.PasswordHash, opts.AdminPassword)
	require.NoError(t, err)
	require.True(t, ok)
}
