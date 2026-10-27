package clientbuild

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/audit"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

type BuildFilter struct {
	Status    string
	ProfileID *uint
	Page      int
	PageSize  int
}

type BuildPage struct {
	Items    []model.ClientBuild
	Page     int
	PageSize int
	Total    int64
}

type BuildDetail struct {
	Build     model.ClientBuild
	Manifest  Manifest
	Artifacts []model.ClientBuildArtifact
}

func (s *Service) CreateBuild(ctx context.Context, orgID, actorID, profileID uint, platforms []string) (*BuildDetail, error) {
	if !s.cfg.Enabled {
		return nil, ErrDisabled
	}
	if s.recorder == nil {
		return nil, ErrUnaudited
	}
	profile, err := s.GetProfile(ctx, orgID, profileID)
	if err != nil {
		return nil, err
	}
	normalized, err := ValidatePlatforms(platforms, s.cfg.Platforms)
	if err != nil {
		return nil, err
	}
	if !versionPattern.MatchString(s.cfg.RustdeskVersion) {
		return nil, fmt.Errorf("%w: rustdesk version is not configured", ErrInvalidInput)
	}
	var logoBytes []byte
	if profile.LogoPath != "" {
		f, err := s.storage.Open(profile.LogoPath)
		if err != nil {
			return nil, fmt.Errorf("%w: profile logo is unreadable", ErrConflict)
		}
		logoBytes, err = io.ReadAll(io.LimitReader(f, 1<<20+1))
		f.Close()
		if err != nil || len(logoBytes) == 0 || len(logoBytes) > 1<<20 {
			return nil, fmt.Errorf("%w: profile logo is unreadable", ErrConflict)
		}
	}

	var org model.Organization
	if err := s.db.WithContext(ctx).Select("id", "provisioning_disabled").
		First(&org, orgID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if org.ProvisioningDisabled {
		return nil, fmt.Errorf("%w: provisioning is disabled", ErrServerNotReady)
	}
	var sg model.ServerGroup
	if err := store.ScopedByOrg(s.db.WithContext(ctx), orgID).First(&sg).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("%w: server group is missing", ErrServerNotReady)
		}
		return nil, err
	}
	if sg.State != model.ServerGroupDeployed {
		return nil, fmt.Errorf("%w: server group is %s", ErrServerNotReady, sg.State)
	}
	if _, err := DeriveServer(s.cfg.RelayHost, sg.HbbsPort); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrServerNotReady, err)
	}
	if err := ValidateServerKey(sg.PubKey); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrServerNotReady, err)
	}
	platformsJSON, err := MarshalPlatforms(normalized)
	if err != nil {
		return nil, err
	}

	row := model.ClientBuild{
		OrganizationID:  orgID,
		ProfileID:       profile.ID,
		ProfileName:     profile.Name,
		AppName:         profile.AppName,
		UpstreamVersion: s.cfg.RustdeskVersion,
		ManifestJSON:    "{}",
		PlatformsJSON:   platformsJSON,
		Status:          model.ClientBuildStatusPending,
		CreatedBy:       actorID,
		CreatedAt:       s.now(),
	}
	var manifest Manifest
	bundleWritten := false
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var lockedOrg model.Organization
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Select("id").
			First(&lockedOrg, orgID).Error; err != nil {
			return err
		}
		scoped := store.ScopedByOrg(tx, orgID)
		var active int64
		if err := scoped.Model(&model.ClientBuild{}).
			Where("status NOT IN ?", []string{
				model.ClientBuildStatusSucceeded, model.ClientBuildStatusFailed, model.ClientBuildStatusCancelled,
			}).Count(&active).Error; err != nil {
			return err
		}
		if active >= int64(s.cfg.MaxConcurrentPerOrg) {
			return fmt.Errorf("%w: organization already has %d active builds", ErrQuotaExceeded, active)
		}
		if err := scoped.Create(&row).Error; err != nil {
			return err
		}
		manifest, err = NewManifest(row.ID, profile, &sg, s.cfg.RelayHost, s.cfg.PublicBaseURL,
			s.cfg.RustdeskVersion, normalized)
		if err != nil {
			return err
		}
		manifestJSON, err := manifest.JSON()
		if err != nil {
			return err
		}
		row.ManifestJSON = string(manifestJSON)
		if err := scoped.Model(&model.ClientBuild{}).Where("id = ?", row.ID).
			Update("manifest_json", row.ManifestJSON).Error; err != nil {
			return err
		}
		if err := s.recorder.RecordTx(tx, audit.Entry{
			OrganizationID: orgID,
			ActorUserID:    actorID,
			Action:         "client_build.start",
			TargetType:     "client_build",
			TargetID:       strconv.FormatUint(uint64(row.ID), 10),
			Detail: map[string]any{
				"profile_id":   profile.ID,
				"profile_name": profile.Name,
				"platforms":    normalized,
				"server":       manifest.Server,
				"api_server":   manifest.APIServer,
			},
		}); err != nil {
			return err
		}
		if err := s.storage.WriteBundle(row.ID, manifestJSON, logoBytes); err != nil {
			return err
		}
		bundleWritten = true
		return nil
	})
	if err != nil {
		if bundleWritten {
			_ = s.storage.RemoveBundle(row.ID)
		}
		return nil, err
	}
	return &BuildDetail{Build: row, Manifest: manifest}, nil
}

func (s *Service) ListBuilds(ctx context.Context, orgID uint, filter BuildFilter) (BuildPage, error) {
	if filter.Status != "" && !validBuildStatus(filter.Status) {
		return BuildPage{}, fmt.Errorf("%w: unknown build status", ErrInvalidInput)
	}
	page, pageSize := normalizePage(filter.Page, filter.PageSize)
	scoped := store.ScopedByOrg(s.db.WithContext(ctx), orgID).Model(&model.ClientBuild{})
	if filter.Status != "" {
		scoped = scoped.Where("status = ?", filter.Status)
	}
	if filter.ProfileID != nil {
		scoped = scoped.Where("profile_id = ?", *filter.ProfileID)
	}
	var total int64
	if err := scoped.Count(&total).Error; err != nil {
		return BuildPage{}, err
	}
	var rows []model.ClientBuild
	if err := scoped.Order("id DESC").Offset((page - 1) * pageSize).Limit(pageSize).
		Find(&rows).Error; err != nil {
		return BuildPage{}, err
	}
	return BuildPage{Items: rows, Page: page, PageSize: pageSize, Total: total}, nil
}

func (s *Service) GetBuild(ctx context.Context, orgID, id uint) (*BuildDetail, error) {
	var row model.ClientBuild
	if err := store.ScopedByOrg(s.db.WithContext(ctx), orgID).First(&row, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	manifest, err := ParseManifest(row.ManifestJSON)
	if err != nil {
		return nil, err
	}
	var artifacts []model.ClientBuildArtifact
	if err := store.ScopedByOrg(s.db.WithContext(ctx), orgID).
		Where("build_id = ?", row.ID).Order("platform").Find(&artifacts).Error; err != nil {
		return nil, err
	}
	return &BuildDetail{Build: row, Manifest: manifest, Artifacts: artifacts}, nil
}

func (s *Service) CancelBuild(ctx context.Context, orgID, actorID, id uint) (*BuildDetail, error) {
	if s.recorder == nil {
		return nil, ErrUnaudited
	}
	var build model.ClientBuild
	if err := store.ScopedByOrg(s.db.WithContext(ctx), orgID).First(&build, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if model.ClientBuildTerminal(build.Status) || build.Status == model.ClientBuildStatusIngesting {
		return nil, fmt.Errorf("%w: build is already %s", ErrConflict, build.Status)
	}
	now := s.now()
	switch build.Status {
	case model.ClientBuildStatusPending:
		if err := s.cancelWithoutRun(ctx, orgID, actorID, id, model.ClientBuildStatusPending, "", now); err != nil {
			return nil, err
		}
		return s.GetBuild(ctx, orgID, id)
	case model.ClientBuildStatusDispatching:
		if build.DispatchAttemptedAt == nil {
			err := s.cancelWithoutRun(ctx, orgID, actorID, id, model.ClientBuildStatusDispatching,
				" AND dispatch_attempted_at IS NULL", now)
			if err == nil {
				return s.GetBuild(ctx, orgID, id)
			}
			if !errors.Is(err, ErrConflict) {
				return nil, err
			}
			var latest model.ClientBuild
			if err := store.ScopedByOrg(s.db.WithContext(ctx), orgID).First(&latest, id).Error; err != nil {
				return nil, err
			}
			if model.ClientBuildTerminal(latest.Status) || latest.Status == model.ClientBuildStatusIngesting {
				return nil, fmt.Errorf("%w: build is already %s", ErrConflict, latest.Status)
			}
			build = latest
		}
		return s.requestCancel(ctx, orgID, actorID, id, &build, now)
	case model.ClientBuildStatusDispatched, model.ClientBuildStatusRunning:
		return s.requestCancel(ctx, orgID, actorID, id, &build, now)
	default:
		return nil, fmt.Errorf("%w: build is %s", ErrConflict, build.Status)
	}
}

func (s *Service) cancelWithoutRun(
	ctx context.Context, orgID, actorID, id uint, status, extraWhere string, now time.Time,
) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		q := store.ScopedByOrg(tx, orgID).Model(&model.ClientBuild{}).
			Where("id = ? AND status = ?", id, status)
		if extraWhere != "" {
			q = q.Where(strings.TrimPrefix(extraWhere, " AND "))
		}
		res := q.Updates(map[string]any{
			"status":              model.ClientBuildStatusCancelled,
			"cancel_requested_at": now,
			"finished_at":         now,
			"error_message":       "",
		})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return ErrConflict
		}
		if err := s.recorder.RecordTx(tx, audit.Entry{
			OrganizationID: orgID,
			ActorUserID:    actorID,
			Action:         "client_build.cancel",
			TargetType:     "client_build",
			TargetID:       strconv.FormatUint(uint64(id), 10),
			Detail:         map[string]any{"from_status": status},
		}); err != nil {
			return err
		}
		return s.recorder.RecordTx(tx, audit.Entry{
			OrganizationID: orgID,
			Action:         "client_build.cancelled",
			TargetType:     "client_build",
			TargetID:       strconv.FormatUint(uint64(id), 10),
			Detail:         map[string]any{"reason": "user_cancelled"},
		})
	})
}

func (s *Service) requestCancel(
	ctx context.Context, orgID, actorID, id uint, build *model.ClientBuild, now time.Time,
) (*BuildDetail, error) {
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		res := store.ScopedByOrg(tx, orgID).Model(&model.ClientBuild{}).
			Where("id = ? AND status IN ?", id, []string{
				model.ClientBuildStatusDispatching, model.ClientBuildStatusDispatched, model.ClientBuildStatusRunning,
			}).Update("cancel_requested_at", now)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return ErrConflict
		}
		return s.recorder.RecordTx(tx, audit.Entry{
			OrganizationID: orgID,
			ActorUserID:    actorID,
			Action:         "client_build.cancel",
			TargetType:     "client_build",
			TargetID:       strconv.FormatUint(uint64(id), 10),
			Detail:         map[string]any{"status": build.Status},
		})
	})
	if err != nil {
		return nil, err
	}
	if build.GitHubRunID != nil && s.github != nil {
		if err := s.github.CancelRun(ctx, *build.GitHubRunID); err != nil {
			var apiErr *APIError
			if !errors.As(err, &apiErr) || (apiErr.Status != 404 && apiErr.Status != 409) {
				s.logger.Warn("github run cancel failed", zap.Int64("run_id", *build.GitHubRunID))
			}
		}
	}
	return s.GetBuild(ctx, orgID, id)
}

func (s *Service) BundleURL(buildID uint) (string, error) {
	if !s.cfg.Enabled {
		return "", ErrDisabled
	}
	if buildID == 0 {
		return "", fmt.Errorf("%w: build id is required", ErrInvalidInput)
	}
	if strings.TrimSpace(s.cfg.BundleKey) == "" {
		return "", ErrDisabled
	}
	if !s.storage.BundleExists(buildID) {
		return "", ErrArtifactUnavailable
	}
	token, err := SignBundleToken([]byte(s.cfg.BundleKey), buildID, s.now(), s.cfg.BundleTTL)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s/api/v1/client-builds/%d/bundle?token=%s",
		s.cfg.PublicBaseURL, buildID, url.QueryEscape(token)), nil
}

func (s *Service) ServeBundle(ctx context.Context, buildID uint, token string) (*os.File, error) {
	if s.auditor == nil {
		return nil, ErrUnaudited
	}
	tokenBuildID, err := VerifyBundleToken([]byte(s.cfg.BundleKey), token, s.now())
	if err != nil || tokenBuildID != buildID {
		return nil, ErrTokenInvalid
	}
	var build model.ClientBuild
	err = store.WithoutTenantScope(s.db.WithContext(ctx)).First(&build, buildID).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	f, err := s.storage.OpenBundle(buildID)
	if err != nil {
		return nil, ErrArtifactUnavailable
	}
	if err := s.auditor.Record(ctx, audit.Entry{
		OrganizationID: build.OrganizationID,
		Action:         "client_build.bundle.served",
		TargetType:     "client_build",
		TargetID:       strconv.FormatUint(uint64(buildID), 10),
		Detail:         map[string]any{"build_id": buildID},
	}); err != nil {
		f.Close()
		return nil, ErrUnaudited
	}
	return f, nil
}

func validBuildStatus(status string) bool {
	switch status {
	case model.ClientBuildStatusPending, model.ClientBuildStatusDispatching,
		model.ClientBuildStatusDispatched, model.ClientBuildStatusRunning,
		model.ClientBuildStatusIngesting, model.ClientBuildStatusSucceeded,
		model.ClientBuildStatusFailed, model.ClientBuildStatusCancelled:
		return true
	default:
		return false
	}
}
