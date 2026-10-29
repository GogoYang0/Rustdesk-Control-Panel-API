package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

const (
	seedBuildProfileName = "E2E 品牌"
	seedBuildProfileKey  = "__devseed_e2e_brand"
	seedBuildMarker      = `"devseed":"e2e"`
	seedBuildProfileApp  = "E2E Remote"
	seedBuildVersion     = "1.5.0"
	seedBuildServer      = "relay.example.com:21117"
	seedBuildAPI         = "https://panel.example.com"
	seedBuildServerKey   = "dGVzdC1rZXktMDEyMzQ1Njc4OWFiY2RlZmdoaWo="
)

// seedClientBuilds gives the generator e2e a deterministic profile and two
// terminal builds. Reruns only replace rows/files owned by this seed profile.
func seedClientBuilds(db *gorm.DB, orgID, adminID uint, assetDir string) error {
	root, err := filepath.Abs(assetDir)
	if err != nil {
		return fmt.Errorf("devseed: resolve client build asset dir: %w", err)
	}
	profile, err := ensureSeedBuildProfile(db, orgID, adminID)
	if err != nil {
		return err
	}
	scoped := store.ScopedByOrg(db, orgID)
	var oldBuilds []model.ClientBuild
	if err := scoped.Where("profile_id = ? AND manifest_json LIKE ?", profile.ID, "%"+seedBuildMarker+"%").
		Find(&oldBuilds).Error; err != nil {
		return fmt.Errorf("devseed: load sample builds: %w", err)
	}
	oldIDs := make([]uint, 0, len(oldBuilds))
	for _, build := range oldBuilds {
		if err := removeSeedBuildFiles(root, orgID, build.ID); err != nil {
			return err
		}
		oldIDs = append(oldIDs, build.ID)
	}
	if len(oldIDs) > 0 {
		if err := scoped.Where("build_id IN ?", oldIDs).Delete(&model.ClientBuildArtifact{}).Error; err != nil {
			return fmt.Errorf("devseed: clear sample artifacts: %w", err)
		}
		if err := scoped.Where("id IN ?", oldIDs).Delete(&model.ClientBuild{}).Error; err != nil {
			return fmt.Errorf("devseed: clear sample builds: %w", err)
		}
	}

	now := time.Now().UTC()
	succeeded, err := createSeedBuild(db, orgID, adminID, profile, model.ClientBuildStatusSucceeded,
		[]string{model.ClientBuildPlatformWindowsX64, model.ClientBuildPlatformLinuxX64},
		now.Add(-90*time.Minute), now.Add(-30*time.Minute), "", 2)
	if err != nil {
		return err
	}
	for _, platform := range []string{model.ClientBuildPlatformWindowsX64, model.ClientBuildPlatformLinuxX64} {
		content := []byte(fmt.Sprintf("E2E artifact %s\n", platform))
		fileName := fmt.Sprintf("panel-client-%d-%s.zip", succeeded.ID, platform)
		if err := writeSeedArtifact(db, root, orgID, succeeded, platform, fileName, content, now); err != nil {
			return err
		}
	}
	if _, err := createSeedBuild(db, orgID, adminID, profile, model.ClientBuildStatusFailed,
		[]string{model.ClientBuildPlatformAndroidARM64},
		now.Add(-3*time.Hour), now.Add(-2*time.Hour), "E2E sample build failed", 0); err != nil {
		return err
	}
	return nil
}

func ensureSeedBuildProfile(db *gorm.DB, orgID, adminID uint) (*model.ClientBuildProfile, error) {
	key := seedBuildProfileKey
	var row model.ClientBuildProfile
	err := store.ScopedByOrg(db, orgID).Where("name_key = ?", key).First(&row).Error
	now := time.Now().UTC()
	if errors.Is(err, gorm.ErrRecordNotFound) {
		row = model.ClientBuildProfile{
			OrganizationID: orgID,
			Name:           seedBuildProfileName,
			NameKey:        key,
			AppName:        seedBuildProfileApp,
			CreatedBy:      adminID,
			CreatedAt:      now,
			UpdatedAt:      now,
		}
		if err := store.ScopedByOrg(db, orgID).Create(&row).Error; err != nil {
			return nil, fmt.Errorf("devseed: create sample build profile: %w", err)
		}
		return &row, nil
	}
	if err != nil {
		return nil, fmt.Errorf("devseed: load sample build profile: %w", err)
	}
	if row.AppName != seedBuildProfileApp {
		if err := store.ScopedByOrg(db, orgID).Model(&model.ClientBuildProfile{}).
			Where("id = ?", row.ID).Updates(map[string]any{
			"app_name":   seedBuildProfileApp,
			"updated_at": now,
		}).Error; err != nil {
			return nil, fmt.Errorf("devseed: update sample build profile: %w", err)
		}
		row.AppName = seedBuildProfileApp
		row.UpdatedAt = now
	}
	return &row, nil
}

func createSeedBuild(
	db *gorm.DB,
	orgID, adminID uint,
	profile *model.ClientBuildProfile,
	status string,
	platforms []string,
	createdAt, finishedAt time.Time,
	errorMessage string,
	artifactCount int,
) (*model.ClientBuild, error) {
	platformsJSON, err := json.Marshal(platforms)
	if err != nil {
		return nil, fmt.Errorf("devseed: encode sample platforms: %w", err)
	}
	row := model.ClientBuild{
		OrganizationID:  orgID,
		ProfileID:       profile.ID,
		ProfileName:     profile.Name,
		AppName:         profile.AppName,
		UpstreamVersion: seedBuildVersion,
		ManifestJSON:    "{}",
		PlatformsJSON:   string(platformsJSON),
		Status:          status,
		ErrorMessage:    errorMessage,
		ArtifactCount:   artifactCount,
		CreatedBy:       adminID,
		CreatedAt:       createdAt,
		DispatchedAt:    &createdAt,
		FinishedAt:      &finishedAt,
	}
	if err := store.ScopedByOrg(db, orgID).Create(&row).Error; err != nil {
		return nil, fmt.Errorf("devseed: create sample build: %w", err)
	}
	manifest, err := json.Marshal(map[string]any{
		"schema_version":   1,
		"build_id":         row.ID,
		"app_name":         row.AppName,
		"server":           seedBuildServer,
		"server_key":       seedBuildServerKey,
		"api_server":       seedBuildAPI,
		"upstream_version": seedBuildVersion,
		"platforms":        platforms,
		"devseed":          "e2e",
	})
	if err != nil {
		return nil, fmt.Errorf("devseed: encode sample manifest: %w", err)
	}
	row.ManifestJSON = string(manifest)
	if err := store.ScopedByOrg(db, orgID).Model(&model.ClientBuild{}).
		Where("id = ?", row.ID).Update("manifest_json", row.ManifestJSON).Error; err != nil {
		return nil, fmt.Errorf("devseed: store sample manifest: %w", err)
	}
	return &row, nil
}

func writeSeedArtifact(
	db *gorm.DB,
	root string,
	orgID uint,
	build *model.ClientBuild,
	platform, fileName string,
	content []byte,
	createdAt time.Time,
) error {
	dir := filepath.Join(root, "artifacts",
		strconv.FormatUint(uint64(orgID), 10),
		strconv.FormatUint(uint64(build.ID), 10))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("devseed: create sample artifact dir: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, fileName), content, 0o600); err != nil {
		return fmt.Errorf("devseed: write sample artifact: %w", err)
	}
	sum := sha256.Sum256(content)
	artifact := model.ClientBuildArtifact{
		OrganizationID: orgID,
		BuildID:        build.ID,
		Platform:       platform,
		FileName:       fileName,
		SizeBytes:      int64(len(content)),
		SHA256:         hex.EncodeToString(sum[:]),
		StoragePath:    fmt.Sprintf("artifacts/%d/%d/%s", orgID, build.ID, fileName),
		CreatedAt:      createdAt,
	}
	if err := store.ScopedByOrg(db, orgID).Create(&artifact).Error; err != nil {
		return fmt.Errorf("devseed: create sample artifact row: %w", err)
	}
	return nil
}

func seedArtifactFileName(buildID uint, platform string) string {
	ext := ".zip"
	switch platform {
	case model.ClientBuildPlatformLinuxX64:
		ext = ".AppImage"
	case model.ClientBuildPlatformMacOSARM64, model.ClientBuildPlatformMacOSX64:
		ext = ".dmg"
	case model.ClientBuildPlatformAndroidARM64:
		ext = ".apk"
	}
	return fmt.Sprintf("panel-client-%d-%s%s", buildID, platform, ext)
}

func removeSeedBuildFiles(root string, orgID, buildID uint) error {
	if err := os.RemoveAll(filepath.Join(root, "artifacts",
		strconv.FormatUint(uint64(orgID), 10),
		strconv.FormatUint(uint64(buildID), 10))); err != nil {
		return fmt.Errorf("devseed: clear sample artifact files: %w", err)
	}
	bundle := filepath.Join(root, "bundles", fmt.Sprintf("%d.tar.gz", buildID))
	if err := os.Remove(bundle); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("devseed: clear sample bundle: %w", err)
	}
	return nil
}
