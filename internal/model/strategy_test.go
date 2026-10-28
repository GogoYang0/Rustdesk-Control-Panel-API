package model_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/config"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

func openStrategyStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(config.DatabaseConfig{
		Driver: "sqlite",
		DSN:    fmt.Sprintf("file:strategy_model_%s?mode=memory&cache=shared", t.Name()),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// TestStrategySchema pins the wave-4 tables and columns: a missing column here
// would silently drop the assignment on save instead of failing a query.
func TestStrategySchema(t *testing.T) {
	s := openStrategyStore(t)
	require.NoError(t, s.DB.AutoMigrate(
		&model.Organization{}, &model.Device{}, &model.DeviceGroup{},
		&model.Membership{}, &model.Strategy{}, &model.DeviceDisconnect{},
		&model.DeviceHeartbeat{},
	))

	m := s.DB.Migrator()
	for _, col := range []struct {
		model any
		name  string
	}{
		{&model.Device{}, "strategy_id"},
		{&model.DeviceGroup{}, "strategy_id"},
		{&model.Membership{}, "strategy_id"},
		{&model.DeviceHeartbeat{}, "conn_ids"},
	} {
		require.True(t, m.HasColumn(col.model, col.name), "%T is missing column %s", col.model, col.name)
	}
	require.True(t, m.HasTable(&model.Strategy{}))
	require.True(t, m.HasTable(&model.DeviceDisconnect{}))
}

// TestStrategyNameUniquePerOrganization keeps the name lookup the CLI and the
// assignment endpoints rely on unambiguous, while letting two tenants share a
// name.
func TestStrategyNameUniquePerOrganization(t *testing.T) {
	s := openStrategyStore(t)
	require.NoError(t, s.DB.AutoMigrate(&model.Organization{}, &model.Strategy{}))

	first := model.Organization{Name: "acme"}
	second := model.Organization{Name: "globex"}
	require.NoError(t, s.DB.Create(&first).Error)
	require.NoError(t, s.DB.Create(&second).Error)

	require.NoError(t, s.DB.Create(&model.Strategy{
		OrganizationID: first.ID, Name: "Locked down", ConfigOptionsJSON: "{}", Version: 1,
	}).Error)
	require.NoError(t, s.DB.Create(&model.Strategy{
		OrganizationID: second.ID, Name: "Locked down", ConfigOptionsJSON: "{}", Version: 1,
	}).Error)
	require.Error(t, s.DB.Create(&model.Strategy{
		OrganizationID: first.ID, Name: "Locked down", ConfigOptionsJSON: "{}", Version: 1,
	}).Error, "the same name twice in one organization must be rejected")
}
