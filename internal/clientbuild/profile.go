package clientbuild

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/audit"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

type ProfileInput struct {
	Name    string
	AppName string
}

type ProfileUpdate struct {
	Name    *string
	AppName *string
}

type ProfilePage struct {
	Items    []model.ClientBuildProfile
	Page     int
	PageSize int
	Total    int64
}

type ProfileLogo struct {
	File   *os.File
	SHA256 string
	Width  int
	Height int
}

func (s *Service) ListProfiles(ctx context.Context, orgID uint, page, pageSize int) (ProfilePage, error) {
	page, pageSize = normalizePage(page, pageSize)
	scoped := store.ScopedByOrg(s.db.WithContext(ctx), orgID)
	var total int64
	if err := scoped.Model(&model.ClientBuildProfile{}).Count(&total).Error; err != nil {
		return ProfilePage{}, err
	}
	var rows []model.ClientBuildProfile
	if err := scoped.Order("name").Offset((page - 1) * pageSize).Limit(pageSize).Find(&rows).Error; err != nil {
		return ProfilePage{}, err
	}
	return ProfilePage{Items: rows, Page: page, PageSize: pageSize, Total: total}, nil
}

func (s *Service) CreateProfile(ctx context.Context, orgID, actorID uint, in ProfileInput) (*model.ClientBuildProfile, error) {
	if s.recorder == nil {
		return nil, ErrUnaudited
	}
	name, key, err := ValidateProfileName(in.Name)
	if err != nil {
		return nil, err
	}
	appName, err := ValidateAppName(in.AppName)
	if err != nil {
		return nil, err
	}
	scoped := store.ScopedByOrg(s.db.WithContext(ctx), orgID)
	var count int64
	if err := scoped.Model(&model.ClientBuildProfile{}).Count(&count).Error; err != nil {
		return nil, err
	}
	if count >= int64(s.cfg.MaxProfilesPerOrg) {
		return nil, fmt.Errorf("%w: organization already has %d profiles", ErrQuotaExceeded, count)
	}

	row := model.ClientBuildProfile{
		OrganizationID: orgID,
		Name:           name,
		NameKey:        key,
		AppName:        appName,
		CreatedBy:      actorID,
		CreatedAt:      s.now(),
		UpdatedAt:      s.now(),
	}
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := store.ScopedByOrg(tx, orgID).Create(&row).Error; err != nil {
			if errors.Is(err, gorm.ErrDuplicatedKey) {
				return ErrDuplicateName
			}
			return err
		}
		return s.recorder.RecordTx(tx, audit.Entry{
			OrganizationID: orgID,
			ActorUserID:    actorID,
			Action:         "client_build.profile.create",
			TargetType:     "client_build_profile",
			TargetID:       strconv.FormatUint(uint64(row.ID), 10),
			Detail:         map[string]any{"name": row.Name, "app_name": row.AppName},
		})
	})
	if err != nil {
		return nil, err
	}
	return &row, nil
}

func (s *Service) GetProfile(ctx context.Context, orgID, id uint) (*model.ClientBuildProfile, error) {
	var row model.ClientBuildProfile
	err := store.ScopedByOrg(s.db.WithContext(ctx), orgID).First(&row, id).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &row, nil
}

func (s *Service) UpdateProfile(ctx context.Context, orgID, actorID, id uint, in ProfileUpdate) (*model.ClientBuildProfile, error) {
	if s.recorder == nil {
		return nil, ErrUnaudited
	}
	if in.Name == nil && in.AppName == nil {
		return nil, fmt.Errorf("%w: at least one field is required", ErrInvalidInput)
	}
	var row model.ClientBuildProfile
	err := store.ScopedByOrg(s.db.WithContext(ctx), orgID).First(&row, id).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	updates := map[string]any{}
	newName, newApp := row.Name, row.AppName
	if in.Name != nil {
		name, key, err := ValidateProfileName(*in.Name)
		if err != nil {
			return nil, err
		}
		if name != row.Name {
			updates["name"] = name
			updates["name_key"] = key
			newName = name
		}
	}
	if in.AppName != nil {
		appName, err := ValidateAppName(*in.AppName)
		if err != nil {
			return nil, err
		}
		if appName != row.AppName {
			updates["app_name"] = appName
			newApp = appName
		}
	}
	if len(updates) == 0 {
		return &row, nil
	}
	updates["updated_at"] = s.now()
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		res := store.ScopedByOrg(tx, orgID).Model(&model.ClientBuildProfile{}).
			Where("id = ?", id).Updates(updates)
		if res.Error != nil {
			if errors.Is(res.Error, gorm.ErrDuplicatedKey) {
				return ErrDuplicateName
			}
			return res.Error
		}
		if res.RowsAffected == 0 {
			return ErrNotFound
		}
		return s.recorder.RecordTx(tx, audit.Entry{
			OrganizationID: orgID,
			ActorUserID:    actorID,
			Action:         "client_build.profile.update",
			TargetType:     "client_build_profile",
			TargetID:       strconv.FormatUint(uint64(id), 10),
			Detail:         map[string]any{"name": newName, "app_name": newApp},
		})
	})
	if err != nil {
		return nil, err
	}
	row.Name = newName
	row.AppName = newApp
	row.UpdatedAt = updates["updated_at"].(time.Time)
	return &row, nil
}

func (s *Service) DeleteProfile(ctx context.Context, orgID, actorID, id uint) error {
	if s.recorder == nil {
		return ErrUnaudited
	}
	var row model.ClientBuildProfile
	err := store.ScopedByOrg(s.db.WithContext(ctx), orgID).First(&row, id).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		scoped := store.ScopedByOrg(tx, orgID)
		var active int64
		if err := scoped.Model(&model.ClientBuild{}).
			Where("profile_id = ? AND status NOT IN ?", id,
				[]string{model.ClientBuildStatusSucceeded, model.ClientBuildStatusFailed, model.ClientBuildStatusCancelled}).
			Count(&active).Error; err != nil {
			return err
		}
		if active > 0 {
			return ErrProfileInUse
		}
		res := scoped.Delete(&model.ClientBuildProfile{}, id)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return ErrNotFound
		}
		return s.recorder.RecordTx(tx, audit.Entry{
			OrganizationID: orgID,
			ActorUserID:    actorID,
			Action:         "client_build.profile.delete",
			TargetType:     "client_build_profile",
			TargetID:       strconv.FormatUint(uint64(id), 10),
			Detail:         map[string]any{"name": row.Name},
		})
	})
	if err != nil {
		return err
	}
	if row.LogoPath != "" {
		if err := s.storage.Remove(row.LogoPath); err != nil {
			s.logger.Warn("remove profile logo after delete failed", zap.Error(err))
		}
	}
	return nil
}

func (s *Service) SetProfileLogo(ctx context.Context, orgID, actorID, id uint, rawPNG []byte) (*model.ClientBuildProfile, error) {
	if s.recorder == nil {
		return nil, ErrUnaudited
	}
	logo, err := ValidateLogoPNG(rawPNG)
	if err != nil {
		return nil, err
	}
	var row model.ClientBuildProfile
	err = store.ScopedByOrg(s.db.WithContext(ctx), orgID).First(&row, id).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	rel, err := s.storage.SaveLogo(orgID, id, logo.SHA256[:16], logo.PNG)
	if err != nil {
		return nil, err
	}
	now := s.now()
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		res := store.ScopedByOrg(tx, orgID).Model(&model.ClientBuildProfile{}).
			Where("id = ?", id).Updates(map[string]any{
			"logo_path":   rel,
			"logo_sha256": logo.SHA256,
			"logo_width":  logo.Width,
			"logo_height": logo.Height,
			"updated_at":  now,
		})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return ErrNotFound
		}
		return s.recorder.RecordTx(tx, audit.Entry{
			OrganizationID: orgID,
			ActorUserID:    actorID,
			Action:         "client_build.logo.set",
			TargetType:     "client_build_profile",
			TargetID:       strconv.FormatUint(uint64(id), 10),
			Detail:         map[string]any{"sha256": logo.SHA256, "width": logo.Width, "height": logo.Height},
		})
	})
	if err != nil {
		_ = s.storage.Remove(rel)
		return nil, err
	}
	if row.LogoPath != "" && row.LogoPath != rel {
		if err := s.storage.Remove(row.LogoPath); err != nil {
			s.logger.Warn("remove replaced profile logo failed", zap.Error(err))
		}
	}
	row.LogoPath = rel
	row.LogoSHA256 = logo.SHA256
	row.LogoWidth = logo.Width
	row.LogoHeight = logo.Height
	row.UpdatedAt = now
	return &row, nil
}

func (s *Service) DeleteProfileLogo(ctx context.Context, orgID, actorID, id uint) error {
	if s.recorder == nil {
		return ErrUnaudited
	}
	var row model.ClientBuildProfile
	err := store.ScopedByOrg(s.db.WithContext(ctx), orgID).First(&row, id).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if row.LogoPath == "" {
		return nil
	}
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		res := store.ScopedByOrg(tx, orgID).Model(&model.ClientBuildProfile{}).
			Where("id = ?", id).Updates(map[string]any{
			"logo_path":   "",
			"logo_sha256": "",
			"logo_width":  0,
			"logo_height": 0,
			"updated_at":  s.now(),
		})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return ErrNotFound
		}
		return s.recorder.RecordTx(tx, audit.Entry{
			OrganizationID: orgID,
			ActorUserID:    actorID,
			Action:         "client_build.logo.delete",
			TargetType:     "client_build_profile",
			TargetID:       strconv.FormatUint(uint64(id), 10),
			Detail:         map[string]any{"name": row.Name},
		})
	})
	if err != nil {
		return err
	}
	if err := s.storage.Remove(row.LogoPath); err != nil {
		s.logger.Warn("remove profile logo failed", zap.Error(err))
	}
	return nil
}

func (s *Service) OpenProfileLogo(ctx context.Context, orgID, id uint) (*ProfileLogo, error) {
	row, err := s.GetProfile(ctx, orgID, id)
	if err != nil {
		return nil, err
	}
	if row.LogoPath == "" {
		return nil, ErrNotFound
	}
	f, err := s.storage.Open(row.LogoPath)
	if err != nil {
		return nil, ErrNotFound
	}
	return &ProfileLogo{File: f, SHA256: row.LogoSHA256, Width: row.LogoWidth, Height: row.LogoHeight}, nil
}
