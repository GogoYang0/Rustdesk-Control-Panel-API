package clientbuild

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

func (s *Service) Sweep(ctx context.Context) (int64, error) {
	now := s.now()
	var changed int64
	var errs []error

	n, err := s.purgeArtifacts(ctx, now)
	changed += n
	if err != nil {
		errs = append(errs, err)
	}
	n, err = s.purgeBundles(ctx, now)
	changed += n
	if err != nil {
		errs = append(errs, err)
	}
	n, err = s.sweepStaging(now)
	changed += n
	if err != nil {
		errs = append(errs, err)
	}
	n, err = s.sweepOrphanArtifacts(ctx, now)
	changed += n
	if err != nil {
		errs = append(errs, err)
	}
	return changed, errors.Join(errs...)
}

func (s *Service) purgeArtifacts(ctx context.Context, now time.Time) (int64, error) {
	cutoff := now.Add(-s.cfg.ArtifactRetention)
	var builds []model.ClientBuild
	if err := store.WithoutTenantScope(s.db.WithContext(ctx)).Model(&model.ClientBuild{}).
		Where("status IN ? AND finished_at IS NOT NULL AND finished_at < ? AND artifacts_purged_at IS NULL",
			[]string{model.ClientBuildStatusSucceeded, model.ClientBuildStatusFailed, model.ClientBuildStatusCancelled},
			cutoff).
		Find(&builds).Error; err != nil {
		return 0, err
	}
	var changed int64
	var errs []error
	for i := range builds {
		build := &builds[i]
		if err := s.storage.RemoveBuildArtifacts(build.OrganizationID, build.ID); err != nil {
			errs = append(errs, err)
			continue
		}
		err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			if err := store.ScopedByOrg(tx, build.OrganizationID).
				Where("build_id = ?", build.ID).Delete(&model.ClientBuildArtifact{}).Error; err != nil {
				return err
			}
			res := store.ScopedByOrg(tx, build.OrganizationID).Model(&model.ClientBuild{}).
				Where("id = ? AND artifacts_purged_at IS NULL", build.ID).
				Update("artifacts_purged_at", now)
			return res.Error
		})
		if err != nil {
			errs = append(errs, err)
			continue
		}
		changed++
	}
	return changed, errors.Join(errs...)
}

func (s *Service) purgeBundles(ctx context.Context, now time.Time) (int64, error) {
	finishedCutoff := now.Add(-24 * time.Hour)
	createdCutoff := now.Add(-48 * time.Hour)
	var builds []model.ClientBuild
	if err := store.WithoutTenantScope(s.db.WithContext(ctx)).Model(&model.ClientBuild{}).
		Where("(finished_at IS NOT NULL AND finished_at < ?) OR created_at < ?", finishedCutoff, createdCutoff).
		Find(&builds).Error; err != nil {
		return 0, err
	}
	var changed int64
	for i := range builds {
		build := &builds[i]
		if !s.storage.BundleExists(build.ID) {
			continue
		}
		if err := s.storage.RemoveBundle(build.ID); err != nil {
			continue
		}
		changed++
	}
	return changed, nil
}

func (s *Service) sweepStaging(now time.Time) (int64, error) {
	dir := filepath.Join(s.storage.Root(), "staging")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	var changed int64
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if now.Sub(info.ModTime()) <= 2*time.Hour {
			continue
		}
		if err := os.RemoveAll(filepath.Join(dir, entry.Name())); err != nil {
			continue
		}
		changed++
	}
	return changed, nil
}

func (s *Service) sweepOrphanArtifacts(ctx context.Context, now time.Time) (int64, error) {
	root := filepath.Join(s.storage.Root(), "artifacts")
	orgDirs, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	var changed int64
	var errs []error
	for _, orgEntry := range orgDirs {
		if !orgEntry.IsDir() {
			continue
		}
		orgID, err := strconv.ParseUint(orgEntry.Name(), 10, 64)
		if err != nil {
			continue
		}
		buildDirs, err := os.ReadDir(filepath.Join(root, orgEntry.Name()))
		if err != nil {
			continue
		}
		for _, buildEntry := range buildDirs {
			if !buildEntry.IsDir() {
				continue
			}
			buildID, err := strconv.ParseUint(buildEntry.Name(), 10, 64)
			if err != nil {
				continue
			}
			var count int64
			if err := store.WithoutTenantScope(s.db.WithContext(ctx)).Model(&model.ClientBuild{}).
				Where("organization_id = ? AND id = ?", orgID, buildID).Count(&count).Error; err != nil {
				errs = append(errs, err)
				continue
			}
			if count > 0 {
				continue
			}
			info, err := buildEntry.Info()
			if err != nil || now.Sub(info.ModTime()) <= 24*time.Hour {
				continue
			}
			if err := os.RemoveAll(filepath.Join(root, orgEntry.Name(), buildEntry.Name())); err != nil {
				errs = append(errs, err)
				continue
			}
			changed++
		}
	}
	return changed, errors.Join(errs...)
}
