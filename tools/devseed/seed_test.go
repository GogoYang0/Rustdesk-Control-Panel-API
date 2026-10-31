package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/auth"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/config"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

func ptrTime(t time.Time) *time.Time { return &t }

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
		AssetDir:      t.TempDir(),
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

	var invitations int64
	require.NoError(t, store.WithoutTenantScope(st.DB).Model(&model.Invitation{}).
		Where("organization_id = ? AND email = ?", first.OrgID, SeedInvitationEmail).
		Count(&invitations).Error)
	require.EqualValues(t, 1, invitations, "sample invitation is replaced, not duplicated")

	var profiles, builds, artifacts int64
	require.NoError(t, store.WithoutTenantScope(st.DB).Model(&model.ClientBuildProfile{}).
		Where("organization_id = ?", first.OrgID).Count(&profiles).Error)
	require.NoError(t, store.WithoutTenantScope(st.DB).Model(&model.ClientBuild{}).
		Where("organization_id = ?", first.OrgID).Count(&builds).Error)
	require.NoError(t, store.WithoutTenantScope(st.DB).Model(&model.ClientBuildArtifact{}).
		Where("organization_id = ?", first.OrgID).Count(&artifacts).Error)
	require.EqualValues(t, 1, profiles, "sample profile is reused")
	require.EqualValues(t, 2, builds, "sample builds are replaced, not duplicated")
	require.EqualValues(t, 2, artifacts, "sample artifacts are replaced, not duplicated")

	var succeeded model.ClientBuild
	require.NoError(t, store.WithoutTenantScope(st.DB).Where("organization_id = ? AND status = ?", first.OrgID,
		model.ClientBuildStatusSucceeded).First(&succeeded).Error)
	var manifest map[string]any
	require.NoError(t, json.Unmarshal([]byte(succeeded.ManifestJSON), &manifest))
	require.EqualValues(t, succeeded.ID, manifest["build_id"])
	require.JSONEq(t, `["windows-x64","linux-x64"]`, succeeded.PlatformsJSON)
	require.EqualValues(t, 2, succeeded.ArtifactCount)

	var artifact model.ClientBuildArtifact
	require.NoError(t, store.WithoutTenantScope(st.DB).Where("build_id = ?", succeeded.ID).First(&artifact).Error)
	data, err := os.ReadFile(filepath.Join(opts.AssetDir, filepath.FromSlash(artifact.StoragePath)))
	require.NoError(t, err)
	require.NotEmpty(t, data)
	require.EqualValues(t, len(data), artifact.SizeBytes)

	// A build created by a user under the seeded profile has no devseed marker
	// and must survive a rerun.
	var seedProfile model.ClientBuildProfile
	require.NoError(t, store.WithoutTenantScope(st.DB).
		Where("organization_id = ? AND name_key = ?", first.OrgID, seedBuildProfileKey).
		First(&seedProfile).Error)
	userBuild := model.ClientBuild{
		OrganizationID: first.OrgID, ProfileID: seedProfile.ID, ProfileName: seedProfile.Name,
		AppName: "User App", UpstreamVersion: "1.5.0",
		ManifestJSON:  `{"schema_version":1,"build_id":999,"app_name":"User App","server":"x","server_key":"y","api_server":"z","upstream_version":"1.5.0","platforms":["windows-x64"]}`,
		PlatformsJSON: `["windows-x64"]`, Status: model.ClientBuildStatusSucceeded, CreatedBy: seedProfile.CreatedBy,
		CreatedAt: time.Now().UTC(), FinishedAt: ptrTime(time.Now().UTC()),
	}
	require.NoError(t, store.WithoutTenantScope(st.DB).Create(&userBuild).Error)
	_, err = Seed(st.DB, opts)
	require.NoError(t, err)
	require.NoError(t, store.WithoutTenantScope(st.DB).Model(&model.ClientBuild{}).
		Where("organization_id = ?", first.OrgID).Count(&builds).Error)
	require.EqualValues(t, 3, builds, "user builds under the seed profile survive")

	var admin model.User
	require.NoError(t, st.DB.Where("email = ?", opts.AdminEmail).First(&admin).Error)
	ok, err := auth.VerifyPassword(admin.PasswordHash, opts.AdminPassword)
	require.NoError(t, err)
	require.True(t, ok)
}
