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

// ErrInvalidInput reports client input that does not satisfy the contract.
var ErrInvalidInput = errors.New("invalid device input")

// Field limits mirror the contract and the column sizes.
const (
	maxNameLen       = 128
	maxRustdeskIDLen = 64
	maxBoundUUIDLen  = 255
)

// RegisterInput carries the fields accepted by the contract.
type RegisterInput struct {
	Name       string
	RustdeskID string
	// BoundUUID records the client instance claiming the device; it is
	// only written on first registration — the upsert never overwrites an
	// existing binding (compat layer ownership anchor, CWE-863).
	BoundUUID string
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
		return nil, fmt.Errorf("%w: name and rustdesk_id are required", ErrInvalidInput)
	}
	if len([]rune(in.Name)) > maxNameLen {
		return nil, fmt.Errorf("%w: name exceeds %d characters", ErrInvalidInput, maxNameLen)
	}
	if len(in.RustdeskID) > maxRustdeskIDLen {
		return nil, fmt.Errorf("%w: rustdesk_id exceeds %d characters", ErrInvalidInput, maxRustdeskIDLen)
	}
	if len(in.BoundUUID) > maxBoundUUIDLen {
		return nil, fmt.Errorf("%w: bound uuid exceeds %d characters", ErrInvalidInput, maxBoundUUIDLen)
	}

	row := model.Device{
		OrganizationID: orgID,
		RustdeskID:     in.RustdeskID,
		Name:           in.Name,
		BoundUUID:      in.BoundUUID,
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

// heartbeatSourceLog marks heartbeats derived from collected server logs, so
// the audit trail can tell them apart from client-reported ones.
const heartbeatSourceLog = "log"

// logHeartbeatMinInterval deduplicates log-derived heartbeats: a busy device
// can emit many matching lines per minute, and each one must not add a
// device_heartbeat row on top of the client's own heartbeat stream.
const logHeartbeatMinInterval = 30 * time.Second

// RecordLogActivity refreshes the heartbeat of the device that owns the given
// RustDesk id (C11 auxiliary source): a parsed hbbs/hbbr connection line is
// proof of liveness even when the client's own heartbeat is in flight. A log
// line older than the online window is ignored, an unknown device is not an
// error (the collector stores the event without the association), and a
// device refreshed within logHeartbeatMinInterval is left alone to keep the
// heartbeat table bounded.
func (s *Service) RecordLogActivity(ctx context.Context, orgID uint, rustdeskID string, at time.Time) (*model.Device, error) {
	if err := store.RequireOrgID(orgID); err != nil {
		return nil, err
	}
	if rustdeskID == "" {
		return nil, ErrInvalidInput
	}
	now := s.now()
	if now.Sub(at) > model.OnlineWindow {
		// Replayed/backfilled lines must not resurrect stale liveness.
		return nil, nil
	}

	var dev model.Device
	err := store.ScopedByOrg(s.db.WithContext(ctx), orgID).
		Where("rustdesk_id = ?", rustdeskID).First(&dev).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if dev.LastSeenAt != nil && now.Sub(*dev.LastSeenAt) < logHeartbeatMinInterval {
		return &dev, nil
	}
	return s.heartbeatLog(ctx, orgID, dev, now)
}

// heartbeatLog records the auxiliary log heartbeat only when the device has not
// been refreshed within logHeartbeatMinInterval. The window check and the
// insert share one transaction and the update itself is conditional, so two
// tailers (hbbs and hbbr) handling the same device concurrently cannot both
// pass the check and write a row each.
func (s *Service) heartbeatLog(ctx context.Context, orgID uint, dev model.Device, now time.Time) (*model.Device, error) {
	refreshed := false
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// The RowsAffected guard is the real deduplication: the outer check is
		// only a fast path and can be raced.
		result := store.ScopedByOrg(tx, orgID).Model(&model.Device{}).
			Where("id = ?", dev.ID).
			Where("last_seen_at IS NULL OR last_seen_at <= ?", now.Add(-logHeartbeatMinInterval)).
			Update("last_seen_at", now)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected == 0 {
			return nil
		}
		refreshed = true
		return store.ScopedByOrg(tx, orgID).Create(&model.DeviceHeartbeat{
			OrganizationID: orgID,
			DeviceID:       dev.ID,
			At:             now,
			Source:         heartbeatSourceLog,
		}).Error
	})
	if err != nil {
		return nil, err
	}
	if !refreshed {
		// Another tailer refreshed the device inside the window.
		return &dev, nil
	}
	var stored model.Device
	if err := store.ScopedByOrg(s.db.WithContext(ctx), orgID).First(&stored, dev.ID).Error; err != nil {
		return nil, fmt.Errorf("load device: %w", err)
	}
	return &stored, nil
}

// Heartbeat records a client-reported heartbeat and refreshes last_seen_at.
func (s *Service) Heartbeat(ctx context.Context, orgID, deviceID uint) (*model.Device, error) {
	if err := store.RequireOrgID(orgID); err != nil {
		return nil, err
	}
	var dev model.Device
	if err := store.ScopedByOrg(s.db.WithContext(ctx), orgID).First(&dev, deviceID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrDeviceNotFound
		}
		return nil, err
	}
	return s.heartbeat(ctx, orgID, dev, "api")
}

// heartbeat records one heartbeat row for an already loaded device. The
// source column keeps the provenance: "api" for client reports, "log" for the
// auxiliary log-derived source (C11).
func (s *Service) heartbeat(ctx context.Context, orgID uint, dev model.Device, source string) (*model.Device, error) {
	now := s.now()
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Only move the timestamp forward: a slower in-flight heartbeat must not
		// overwrite a newer one and make the device look offline.
		if err := store.ScopedByOrg(tx, orgID).Model(&model.Device{}).
			Where("id = ?", dev.ID).
			Where("last_seen_at IS NULL OR last_seen_at < ?", now).
			Update("last_seen_at", now).Error; err != nil {
			return err
		}
		return store.ScopedByOrg(tx, orgID).Create(&model.DeviceHeartbeat{
			OrganizationID: orgID,
			DeviceID:       dev.ID,
			At:             now,
			Source:         source,
		}).Error
	})
	if err != nil {
		return nil, err
	}

	var stored model.Device
	if err := store.ScopedByOrg(s.db.WithContext(ctx), orgID).First(&stored, dev.ID).Error; err != nil {
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
