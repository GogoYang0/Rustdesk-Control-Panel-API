package clientbuild

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/audit"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

var activeBuildStatuses = []string{
	model.ClientBuildStatusDispatching,
	model.ClientBuildStatusDispatched,
	model.ClientBuildStatusRunning,
	model.ClientBuildStatusIngesting,
}

var reconcileBuildStatuses = []string{
	model.ClientBuildStatusDispatching,
	model.ClientBuildStatusDispatched,
	model.ClientBuildStatusRunning,
}

func (s *Service) Advance(ctx context.Context) (int64, error) {
	if s.github == nil {
		return 0, fmt.Errorf("clientbuild: github client is not configured")
	}
	if s.recorder == nil {
		return 0, ErrUnaudited
	}
	var changed int64
	var errs []error

	// Timeouts run before claims: a pending build that already exceeded
	// pendingTimeout must fail rather than be claimed and dispatched with a
	// fresh bundle token.
	n, err := s.advanceTimeouts(ctx)
	changed += n
	if err != nil {
		errs = append(errs, err)
	}
	n, err = s.advancePending(ctx)
	changed += n
	if err != nil {
		errs = append(errs, err)
	}
	n, err = s.advanceDispatching(ctx)
	changed += n
	if err != nil {
		errs = append(errs, err)
	}
	n, err = s.advanceActive(ctx)
	changed += n
	if err != nil {
		errs = append(errs, err)
	}
	return changed, errors.Join(errs...)
}

func (s *Service) advancePending(ctx context.Context) (int64, error) {
	var active int64
	if err := store.WithoutTenantScope(s.db.WithContext(ctx)).Model(&model.ClientBuild{}).
		Where("status IN ?", activeBuildStatuses).Count(&active).Error; err != nil {
		return 0, err
	}
	remaining := s.cfg.MaxActiveBuilds - int(active)
	if remaining <= 0 {
		return 0, nil
	}
	var pending []model.ClientBuild
	if err := store.WithoutTenantScope(s.db.WithContext(ctx)).Model(&model.ClientBuild{}).
		Where("status = ?", model.ClientBuildStatusPending).
		Order("id").Limit(remaining).Find(&pending).Error; err != nil {
		return 0, err
	}
	var changed int64
	for i := range pending {
		res := store.WithoutTenantScope(s.db.WithContext(ctx)).Model(&model.ClientBuild{}).
			Where("id = ? AND status = ?", pending[i].ID, model.ClientBuildStatusPending).
			Updates(map[string]any{
				"status":        model.ClientBuildStatusDispatching,
				"dispatched_at": s.now(),
			})
		if res.Error != nil {
			return changed, res.Error
		}
		changed += res.RowsAffected
	}
	return changed, nil
}

func (s *Service) advanceDispatching(ctx context.Context) (int64, error) {
	var builds []model.ClientBuild
	if err := store.WithoutTenantScope(s.db.WithContext(ctx)).Model(&model.ClientBuild{}).
		Where("status = ?", model.ClientBuildStatusDispatching).Order("id").Find(&builds).Error; err != nil {
		return 0, err
	}
	if len(builds) == 0 {
		return 0, nil
	}
	var changed int64
	var recoverable []model.ClientBuild
	for i := range builds {
		build := &builds[i]
		if build.DispatchAttemptedAt == nil && build.CancelRequestedAt != nil {
			if err := s.cancelBuild(ctx, build, "user_cancelled"); err != nil {
				return changed, err
			}
			changed++
			continue
		}
		if build.DispatchAttemptedAt == nil {
			ok, err := s.dispatchBuild(ctx, build)
			if err != nil {
				return changed, err
			}
			if ok {
				changed++
			}
			continue
		}
		recoverable = append(recoverable, *build)
	}
	if len(recoverable) == 0 {
		return changed, nil
	}

	since := recoverable[0].CreatedAt
	for _, build := range recoverable {
		base := dispatchBase(build)
		if base.Before(since) {
			since = base
		}
	}
	runs, err := s.github.ListRuns(ctx, since.Add(-2*time.Minute))
	if err != nil {
		return changed, err
	}
	for i := range recoverable {
		build := &recoverable[i]
		run := matchRun(runs, build.ID)
		if run == nil {
			continue
		}
		ok, err := s.applyRun(ctx, build, *run)
		if err != nil {
			return changed, err
		}
		if ok {
			changed++
		}
	}
	return changed, nil
}

func (s *Service) dispatchBuild(ctx context.Context, build *model.ClientBuild) (bool, error) {
	res := store.WithoutTenantScope(s.db.WithContext(ctx)).Model(&model.ClientBuild{}).
		Where("id = ? AND status = ? AND cancel_requested_at IS NULL AND dispatch_attempted_at IS NULL",
			build.ID, model.ClientBuildStatusDispatching).
		Update("dispatch_attempted_at", s.now())
	if res.Error != nil {
		return false, res.Error
	}
	if res.RowsAffected == 0 {
		return false, nil
	}
	bundleURL, err := s.BundleURL(build.ID)
	if err != nil {
		if failErr := s.failBuild(ctx, build, "bundle is unavailable"); failErr != nil {
			return false, errors.Join(err, failErr)
		}
		return false, err
	}
	platforms, err := ParsePlatforms(build.PlatformsJSON)
	if err != nil {
		if failErr := s.failBuild(ctx, build, "stored platforms are unreadable"); failErr != nil {
			return false, errors.Join(err, failErr)
		}
		return false, err
	}
	result, err := s.github.Dispatch(ctx, DispatchInput{
		BuildID:         build.ID,
		BundleURL:       bundleURL,
		Platforms:       platforms,
		RustdeskVersion: build.UpstreamVersion,
	})
	if err != nil {
		var apiErr *APIError
		if errors.As(err, &apiErr) {
			switch apiErr.Status {
			case 401, 403, 404, 422:
				if failErr := s.failBuild(ctx, build, "github dispatch rejected"); failErr != nil {
					return false, errors.Join(err, failErr)
				}
				return false, nil
			}
		}
		s.logger.Warn("github dispatch result is unknown", zap.Uint("build_id", build.ID))
		return false, nil
	}
	if result.RunID == 0 {
		return false, nil
	}
	updates := map[string]any{
		"status":         model.ClientBuildStatusDispatched,
		"github_run_id":  result.RunID,
		"github_run_url": result.URL,
	}
	res = store.WithoutTenantScope(s.db.WithContext(ctx)).Model(&model.ClientBuild{}).
		Where("id = ? AND status = ?", build.ID, model.ClientBuildStatusDispatching).
		Updates(updates)
	if res.Error != nil {
		return false, res.Error
	}
	return res.RowsAffected > 0, nil
}

func (s *Service) advanceActive(ctx context.Context) (int64, error) {
	var builds []model.ClientBuild
	if err := store.WithoutTenantScope(s.db.WithContext(ctx)).Model(&model.ClientBuild{}).
		Where("status IN ? AND github_run_id IS NOT NULL", reconcileBuildStatuses).
		Order("id").Find(&builds).Error; err != nil {
		return 0, err
	}
	var changed int64
	var errs []error
	for i := range builds {
		build := &builds[i]
		if build.CancelRequestedAt != nil {
			if err := s.cancelGitHubRun(ctx, *build.GitHubRunID); err != nil {
				errs = append(errs, err)
			}
		}
		run, err := s.github.GetRun(ctx, *build.GitHubRunID)
		if err != nil {
			var apiErr *APIError
			if errors.As(err, &apiErr) && apiErr.Status == 404 {
				if failErr := s.failBuild(ctx, build, "github run not found"); failErr != nil {
					errs = append(errs, failErr)
				} else {
					changed++
				}
				continue
			}
			errs = append(errs, err)
			continue
		}
		if run.ID == 0 {
			continue
		}
		if run.Status != "completed" {
			ok, err := s.applyRun(ctx, build, run)
			if err != nil {
				errs = append(errs, err)
			}
			if ok {
				changed++
			}
			continue
		}
		if build.CancelRequestedAt != nil || run.Conclusion == "cancelled" {
			if err := s.cancelBuild(ctx, build, "github_cancelled"); err != nil {
				errs = append(errs, err)
			} else {
				changed++
			}
			continue
		}
		if run.Conclusion != "success" {
			if err := s.failBuild(ctx, build, "github run "+run.Conclusion); err != nil {
				errs = append(errs, err)
			} else {
				changed++
			}
			continue
		}
		ok, err := s.markIngesting(ctx, build.ID, build.OrganizationID, s.now())
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if !ok {
			continue
		}
		var current model.ClientBuild
		if err := store.WithoutTenantScope(s.db.WithContext(ctx)).First(&current, build.ID).Error; err != nil {
			errs = append(errs, err)
			continue
		}
		ingestCtx, cancel := context.WithTimeout(ctx, s.cfg.IngestTimeout)
		err = s.ingestRun(ingestCtx, &current)
		cancel()
		if err != nil {
			errs = append(errs, err)
			continue
		}
		changed++
	}
	return changed, errors.Join(errs...)
}

func (s *Service) advanceTimeouts(ctx context.Context) (int64, error) {
	now := s.now()
	var changed int64
	var errs []error

	var pending []model.ClientBuild
	if err := store.WithoutTenantScope(s.db.WithContext(ctx)).Model(&model.ClientBuild{}).
		Where("status = ?", model.ClientBuildStatusPending).Find(&pending).Error; err != nil {
		return 0, err
	}
	for i := range pending {
		if now.Sub(pending[i].CreatedAt) > s.cfg.PendingTimeout {
			if err := s.failBuild(ctx, &pending[i], "queue timeout"); err != nil {
				errs = append(errs, err)
			} else {
				changed++
			}
		}
	}

	var dispatching []model.ClientBuild
	if err := store.WithoutTenantScope(s.db.WithContext(ctx)).Model(&model.ClientBuild{}).
		Where("status = ? AND github_run_id IS NULL", model.ClientBuildStatusDispatching).
		Find(&dispatching).Error; err != nil {
		return changed, err
	}
	for i := range dispatching {
		build := &dispatching[i]
		if now.Sub(dispatchBase(*build)) <= s.cfg.DispatchTimeout {
			continue
		}
		if build.CancelRequestedAt != nil {
			if err := s.cancelBuild(ctx, build, "user_cancelled"); err != nil {
				errs = append(errs, err)
			} else {
				changed++
			}
			continue
		}
		if err := s.failBuild(ctx, build, "github run not found"); err != nil {
			errs = append(errs, err)
		} else {
			changed++
		}
	}

	var running []model.ClientBuild
	if err := store.WithoutTenantScope(s.db.WithContext(ctx)).Model(&model.ClientBuild{}).
		Where("status IN ?", []string{model.ClientBuildStatusDispatched, model.ClientBuildStatusRunning}).
		Find(&running).Error; err != nil {
		return changed, err
	}
	for i := range running {
		build := &running[i]
		base := build.CreatedAt
		if build.DispatchedAt != nil {
			base = *build.DispatchedAt
		}
		if now.Sub(base) <= s.cfg.BuildTimeout {
			continue
		}
		if build.GitHubRunID != nil {
			if err := s.cancelGitHubRun(ctx, *build.GitHubRunID); err != nil {
				errs = append(errs, err)
			}
		}
		if build.CancelRequestedAt != nil {
			if err := s.cancelBuild(ctx, build, "user_cancelled"); err != nil {
				errs = append(errs, err)
			} else {
				changed++
			}
			continue
		}
		if err := s.failBuild(ctx, build, "build timeout"); err != nil {
			errs = append(errs, err)
		} else {
			changed++
		}
	}

	var ingesting []model.ClientBuild
	if err := store.WithoutTenantScope(s.db.WithContext(ctx)).Model(&model.ClientBuild{}).
		Where("status = ?", model.ClientBuildStatusIngesting).Find(&ingesting).Error; err != nil {
		return changed, err
	}
	for i := range ingesting {
		build := &ingesting[i]
		if build.IngestingAt == nil || now.Sub(*build.IngestingAt) <= s.cfg.IngestTimeout {
			continue
		}
		if err := s.failBuild(ctx, build, "ingest timeout"); err != nil {
			errs = append(errs, err)
		} else {
			changed++
		}
	}
	return changed, errors.Join(errs...)
}

func (s *Service) applyRun(ctx context.Context, build *model.ClientBuild, run Run) (bool, error) {
	updates := map[string]any{
		"github_run_id":  run.ID,
		"github_run_url": run.URL,
	}
	switch run.Status {
	case "in_progress":
		updates["status"] = model.ClientBuildStatusRunning
	case "queued":
		if build.Status == model.ClientBuildStatusDispatching {
			updates["status"] = model.ClientBuildStatusDispatched
		}
	default:
		if build.Status == model.ClientBuildStatusDispatching {
			updates["status"] = model.ClientBuildStatusDispatched
		}
	}
	res := store.WithoutTenantScope(s.db.WithContext(ctx)).Model(&model.ClientBuild{}).
		Where("id = ? AND status IN ?", build.ID, activeBuildStatuses).Updates(updates)
	if res.Error != nil {
		return false, res.Error
	}
	return res.RowsAffected > 0, nil
}

func (s *Service) cancelBuild(ctx context.Context, build *model.ClientBuild, reason string) error {
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		res := store.ScopedByOrg(tx, build.OrganizationID).Model(&model.ClientBuild{}).
			Where("id = ? AND status NOT IN ?", build.ID, []string{
				model.ClientBuildStatusSucceeded, model.ClientBuildStatusFailed, model.ClientBuildStatusCancelled,
			}).Updates(map[string]any{
			"status":        model.ClientBuildStatusCancelled,
			"finished_at":   s.now(),
			"error_message": "",
		})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return nil
		}
		return s.recorder.RecordTx(tx, audit.Entry{
			OrganizationID: build.OrganizationID,
			Action:         "client_build.cancelled",
			TargetType:     "client_build",
			TargetID:       strconv.FormatUint(uint64(build.ID), 10),
			Detail:         map[string]any{"reason": reason},
		})
	})
	return err
}

func (s *Service) cancelGitHubRun(ctx context.Context, runID int64) error {
	err := s.github.CancelRun(ctx, runID)
	var apiErr *APIError
	if errors.As(err, &apiErr) && (apiErr.Status == 404 || apiErr.Status == 409) {
		return nil
	}
	return err
}

func matchRun(runs []Run, buildID uint) *Run {
	want := "panel-client-" + strconv.FormatUint(uint64(buildID), 10)
	var best *Run
	for i := range runs {
		if runs[i].DisplayTitle != want {
			continue
		}
		if best == nil || runs[i].CreatedAt.Before(best.CreatedAt) ||
			(runs[i].CreatedAt.Equal(best.CreatedAt) && runs[i].ID < best.ID) {
			best = &runs[i]
		}
	}
	return best
}

func dispatchBase(build model.ClientBuild) time.Time {
	if build.DispatchAttemptedAt != nil {
		return *build.DispatchAttemptedAt
	}
	if build.DispatchedAt != nil {
		return *build.DispatchedAt
	}
	return build.CreatedAt
}
