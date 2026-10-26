package scopetest

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

func TestScopedModels_CoverClientBuildTables(t *testing.T) {
	_, cleanup := newDB(t)
	defer cleanup()
	registered := map[string]bool{}
	for _, m := range store.ScopedModels() {
		if tn, ok := m.(interface{ TableName() string }); ok {
			registered[tn.TableName()] = true
			continue
		}
		s, err := schema.Parse(m, &sync.Map{}, schema.NamingStrategy{})
		require.NoError(t, err)
		registered[s.Table] = true
	}
	for _, table := range []string{"client_build_profiles", "client_builds", "client_build_artifacts"} {
		require.Truef(t, registered[table], "%s must be registered as tenant-scoped", table)
	}
}

func TestClientBuild_TenantIsolation(t *testing.T) {
	db, cleanup := newDB(t)
	defer cleanup()
	require.NoError(t, db.AutoMigrate(
		&model.ClientBuildProfile{}, &model.ClientBuild{}, &model.ClientBuildArtifact{},
	))
	orgA := model.Organization{Name: "cb-iso-a"}
	orgB := model.Organization{Name: "cb-iso-b"}
	require.NoError(t, db.Create(&orgA).Error)
	require.NoError(t, db.Create(&orgB).Error)

	profile := model.ClientBuildProfile{OrganizationID: orgA.ID, Name: "Acme", NameKey: "acme", AppName: "Acme", CreatedBy: 1}
	require.NoError(t, db.Create(&profile).Error)
	build := model.ClientBuild{OrganizationID: orgA.ID, ProfileID: profile.ID, ProfileName: "Acme", AppName: "Acme",
		UpstreamVersion: "1.5.0", ManifestJSON: "{}", PlatformsJSON: "[]",
		Status: model.ClientBuildStatusPending, CreatedBy: 1}
	require.NoError(t, db.Create(&build).Error)
	artifact := model.ClientBuildArtifact{OrganizationID: orgA.ID, BuildID: build.ID, Platform: "linux-x64",
		FileName: "panel-client-1-linux-x64.AppImage", SizeBytes: 1, SHA256: "00",
		StoragePath: "artifacts/1/1/panel-client-1-linux-x64.AppImage"}
	require.NoError(t, db.Create(&artifact).Error)

	for _, m := range []any{&model.ClientBuildProfile{}, &model.ClientBuild{}, &model.ClientBuildArtifact{}} {
		var theirs int64
		require.NoError(t, store.ScopedByOrg(db, orgB.ID).Model(m).Count(&theirs).Error)
		require.Zero(t, theirs)
		var zero int64
		require.NoError(t, store.ScopedByOrg(db, 0).Model(m).Count(&zero).Error)
		require.Zero(t, zero)
	}
}

func TestClientBuildProfile_NameKeyUniquePerOrganization(t *testing.T) {
	db, cleanup := newDB(t)
	defer cleanup()
	require.NoError(t, db.AutoMigrate(&model.ClientBuildProfile{}))

	orgA := model.Organization{Name: "cb-uniq-a"}
	orgB := model.Organization{Name: "cb-uniq-b"}
	require.NoError(t, db.Create(&orgA).Error)
	require.NoError(t, db.Create(&orgB).Error)

	base := model.ClientBuildProfile{OrganizationID: orgA.ID, Name: "Ops", NameKey: "ops", AppName: "Acme", CreatedBy: 1}
	require.NoError(t, db.Create(&base).Error)

	err := db.Create(&model.ClientBuildProfile{
		OrganizationID: orgA.ID, Name: "OPS", NameKey: "ops", AppName: "Acme", CreatedBy: 1,
	}).Error
	require.ErrorIs(t, err, gorm.ErrDuplicatedKey)

	require.NoError(t, db.Create(&model.ClientBuildProfile{
		OrganizationID: orgB.ID, Name: "Ops", NameKey: "ops", AppName: "Acme", CreatedBy: 1,
	}).Error)
}
