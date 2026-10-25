package access_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/access"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/config"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// accessTestStore opens a private in-memory database carrying every table the
// access domain touches. The DSN is unique per call: the shared-cache in-memory
// database is process-wide, so a fixed name would leak rows across tests.
func accessTestStore(t *testing.T) *store.Store {
	t.Helper()
	dsn := fmt.Sprintf("file:access_%d?mode=memory&cache=shared", time.Now().UnixNano())
	st, err := store.Open(config.DatabaseConfig{Driver: "sqlite", DSN: dsn})
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	require.NoError(t, st.DB.AutoMigrate(
		&model.User{}, &model.Organization{}, &model.Membership{}, &model.Role{},
		&model.Device{}, &model.MigrationMark{},
		&model.UserGroup{}, &model.UserGroupMember{}, &model.DeviceGroup{}, &model.AccessRule{},
	))
	return st
}

// TestAccess_MigrateSeedsEveryone pins the migration contract: every existing
// organization ends up with exactly one reserved everyone group and one
// everyone -> all_devices rule, no explicit member rows (membership is
// implicit), and a second run changes nothing.
func TestAccess_MigrateSeedsEveryone(t *testing.T) {
	st := accessTestStore(t)
	orgA := model.Organization{Name: "alpha"}
	orgB := model.Organization{Name: "beta"}
	require.NoError(t, st.DB.Create(&orgA).Error)
	require.NoError(t, st.DB.Create(&orgB).Error)

	require.NoError(t, access.Migrate(st.DB))
	require.NoError(t, access.Migrate(st.DB))

	for _, org := range []model.Organization{orgA, orgB} {
		var groups []model.UserGroup
		require.NoError(t, store.ScopedByOrg(st.DB, org.ID).
			Where("kind = ?", model.UserGroupKindEveryone).Find(&groups).Error)
		require.Len(t, groups, 1)
		require.Equal(t, "everyone", groups[0].Name)

		var rules []model.AccessRule
		require.NoError(t, store.ScopedByOrg(st.DB, org.ID).Find(&rules).Error)
		require.Len(t, rules, 1)
		require.Equal(t, groups[0].ID, rules[0].SourceGroupID)
		require.Equal(t, model.AccessTargetKindAllDevices, rules[0].TargetKind)
		require.Zero(t, rules[0].TargetGroupID)

		var members int64
		require.NoError(t, store.ScopedByOrg(st.DB, org.ID).
			Model(&model.UserGroupMember{}).Count(&members).Error)
		require.Zero(t, members, "everyone is an implicit user group and stores no member rows")
	}
}
