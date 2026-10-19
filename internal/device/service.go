// Package device implements device registration and heartbeat tracking.
package device

import (
	"context"
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// ErrDeviceNotFound is returned when a device id does not exist in the org.
var ErrDeviceNotFound = errors.New("device not found")

// RegisterInput carries the fields accepted by the contract.
type RegisterInput struct {
	Name       string
	RustdeskID string
}

// Service owns device persistence.
type Service struct {
	db  *gorm.DB
	now func() time.Time
}

// NewService builds the device service.
func NewService(db *gorm.DB, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{db: db, now: now}
}

// Register upserts a device by (organization, rustdesk_id).
func (s *Service) Register(ctx context.Context, orgID uint, in RegisterInput) (*model.Device, error) {
	if err := store.RequireOrgID(orgID); err != nil {
		return nil, err
	}
	if in.Name == "" || in.RustdeskID == "" {
		return nil, fmt.Errorf("name and rustdesk_id are required")
	}

	row := model.Device{
		OrganizationID: orgID,
		RustdeskID:     in.RustdeskID,
		Name:           in.Name,
	}
	err := store.ScopedByOrg(s.db.WithContext(ctx), orgID).
		Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "organization_id"}, {Name: "rustdesk_id"}},
			DoUpdates: clause.AssignmentColumns([]string{"name", "updated_at"}),
		}).
		Create(&row).Error
	if err != nil {
		return nil, fmt.Errorf("register device: %w", err)
	}

	var stored model.Device
	if err := store.ScopedByOrg(s.db.WithContext(ctx), orgID).
		Where("rustdesk_id = ?", in.RustdeskID).
		First(&stored).Error; err != nil {
		return nil, fmt.Errorf("load device: %w", err)
	}
	return &stored, nil
}

// Heartbeat records a heartbeat and refreshes last_seen_at.
func (s *Service) Heartbeat(ctx context.Context, orgID, deviceID uint) (*model.Device, error) {
	if err := store.RequireOrgID(orgID); err != nil {
		return nil, err
	}

	now := s.now()
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var dev model.Device
		if err := store.ScopedByOrg(tx, orgID).First(&dev, deviceID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrDeviceNotFound
			}
			return err
		}
		if err := store.ScopedByOrg(tx, orgID).Model(&model.Device{}).
			Where("id = ?", dev.ID).
			Update("last_seen_at", now).Error; err != nil {
			return err
		}
		return store.ScopedByOrg(tx, orgID).Create(&model.DeviceHeartbeat{
			OrganizationID: orgID,
			DeviceID:       dev.ID,
			At:             now,
			Source:         "api",
		}).Error
	})
	if err != nil {
		return nil, err
	}

	var stored model.Device
	if err := store.ScopedByOrg(s.db.WithContext(ctx), orgID).First(&stored, deviceID).Error; err != nil {
		return nil, fmt.Errorf("load device: %w", err)
	}
	return &stored, nil
}

// Status maps a device to the contract's online/offline value.
func Status(d *model.Device, now time.Time) string {
	if d.Online(now) {
		return "online"
	}
	return "offline"
}
