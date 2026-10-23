// Package device implements device registration and heartbeat tracking.
package device

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/audit"
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
	db       *gorm.DB
	recorder audit.TxRecorder
	now      func() time.Time
}

// NewService builds the device service. recorder may be nil for callers that
// never mutate bindings; ResetBinding fails closed without one, because an
// unrecorded binding change is exactly what an administrator must be able to
// trace.
func NewService(db *gorm.DB, recorder audit.TxRecorder, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{db: db, recorder: recorder, now: now}
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
		// A registration that carries a binding is the first claim: the
		// generation starts at 1 so a session can never match generation 0
		// (no binding yet).
		BindingGeneration: firstBindingGeneration(in.BoundUUID),
	}
	return RegisterTx(s.db.WithContext(ctx), orgID, row)
}

// firstBindingGeneration maps a registration binding to its generation: a
// bound row starts at 1, an unbound row at 0.
func firstBindingGeneration(boundUUID string) uint64 {
	if boundUUID == "" {
		return 0
	}
	return 1
}

// RegisterTx is Register on a caller-supplied transaction, so the compat
// login can claim a device and persist its session atomically. The upsert
// never touches bound_uuid or binding_generation on conflict: the stored
// binding belongs to whoever claimed first.
func RegisterTx(db *gorm.DB, orgID uint, row model.Device) (*model.Device, error) {
	// The binding generation is normalized here so every caller agrees on
	// it: a row that arrives with a binding starts at 1, an unbound row at
	// 0 — no session can ever match the unbound generation.
	row.BindingGeneration = firstBindingGeneration(row.BoundUUID)
	err := store.ScopedByOrg(db, orgID).
		Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "organization_id"}, {Name: "rustdesk_id"}},
			DoUpdates: clause.AssignmentColumns([]string{"name", "updated_at"}),
		}).
		Create(&row).Error
	if err != nil {
		return nil, fmt.Errorf("register device: %w", err)
	}

	// The re-read after a unique-key conflict must be a current read: under
	// MySQL REPEATABLE READ a plain SELECT keeps seeing the transaction's
	// snapshot and would report the rival's just-committed row as missing.
	// SQLite has no row locks, so it keeps the plain read.
	var stored model.Device
	lookup := store.ScopedByOrg(db, orgID).
		Where("rustdesk_id = ?", row.RustdeskID)
	if db.Name() != "sqlite" {
		lookup = lookup.Clauses(clause.Locking{Strength: "UPDATE"})
	}
	if err := lookup.First(&stored).Error; err != nil {
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

// apiHeartbeatMinInterval bounds the durable history of the credential-free
// compat reports: one DeviceHeartbeat row per device per window. The client
// treats heartbeats as idempotent, so coalescing is invisible to it; the
// log-derived source keeps its own (equal) window in RecordLogActivity.
const apiHeartbeatMinInterval = 30 * time.Second

// heartbeat records one heartbeat row for an already loaded device. The
// source column keeps the provenance: "api" for client reports, "log" for the
// auxiliary log-derived source (C11).
func (s *Service) heartbeat(ctx context.Context, orgID uint, dev model.Device, source string) (*model.Device, error) {
	now := s.now()
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// The RowsAffected guard is the real coalescing: two concurrent reports
		// can both read the same stale last_seen_at, so the outer fast path is
		// only an optimization and the window check has to be atomic with the
		// insert (the heartbeatLog path uses the same pattern). It also keeps
		// the timestamp forward-only: a slower in-flight heartbeat must not
		// overwrite a newer one and make the device look offline.
		result := store.ScopedByOrg(tx, orgID).Model(&model.Device{}).
			Where("id = ?", dev.ID).
			Where("last_seen_at IS NULL OR last_seen_at <= ?", now.Add(-apiHeartbeatMinInterval)).
			Update("last_seen_at", now)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected == 0 {
			return nil
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

	// Return the stored state in both branches: a coalesced caller raced
	// against the winner and must not answer with its own stale copy, which
	// for a first heartbeat still carries last_seen_at == nil.
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

// Device listing pagination bounds mirror the contract and the session listing.
const (
	defaultDevicePageSize = 50
	maxDevicePageSize     = 200
	maxDevicePage         = 100_000
)

// DeviceFilter carries the list parameters accepted by the contract.
type DeviceFilter struct {
	// Query matches name or rustdesk_id as a case-insensitive substring.
	Query    string
	Bound    *bool
	Page     int
	PageSize int
}

// NormalisedPagination returns the page and page size actually applied, so the
// HTTP layer can echo them instead of repeating the clamping rules. Input is
// clamped rather than rejected: a pager that asks for page 0 or an oversized
// page is a client bug, not a 500.
func (f DeviceFilter) NormalisedPagination() (page, pageSize int) {
	page, pageSize = f.Page, f.PageSize
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = defaultDevicePageSize
	}
	if pageSize > maxDevicePageSize {
		pageSize = maxDevicePageSize
	}
	if page > maxDevicePage {
		page = maxDevicePage
	}
	return page, pageSize
}

// List returns one page of the organization's devices plus the unpaginated
// total. Ordering is id ascending so pages stay stable.
func (s *Service) List(ctx context.Context, orgID uint, f DeviceFilter) ([]model.Device, int64, error) {
	if orgID == 0 {
		return nil, 0, fmt.Errorf("%w: organization is required", ErrInvalidInput)
	}
	page, pageSize := f.NormalisedPagination()

	query := store.ScopedByOrg(s.db.WithContext(ctx), orgID).Model(&model.Device{})
	if q := strings.TrimSpace(f.Query); q != "" {
		// Escape with '!' rather than a backslash: the SQL literal '\' is a
		// syntax error on MySQL and a two-character string on PostgreSQL, so
		// no backslash form works on all three dialects.
		escaped := strings.NewReplacer("!", "!!", "%", "!%", "_", "!_").Replace(strings.ToLower(q))
		pattern := "%" + escaped + "%"
		query = query.Where(
			"LOWER(name) LIKE ? ESCAPE '!' OR LOWER(rustdesk_id) LIKE ? ESCAPE '!'",
			pattern, pattern,
		)
	}
	if f.Bound != nil {
		if *f.Bound {
			query = query.Where("bound_uuid <> ''")
		} else {
			query = query.Where("bound_uuid = ''")
		}
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("count devices: %w", err)
	}

	var items []model.Device
	if err := query.
		Order("id ASC").
		Offset((page - 1) * pageSize).
		Limit(pageSize).
		Find(&items).Error; err != nil {
		return nil, 0, fmt.Errorf("list devices: %w", err)
	}
	return items, total, nil
}

// maxResetReasonLen mirrors the contract's reason maxLength, counted in runes.
const maxResetReasonLen = 500

// ResetBinding clears the device binding, advances its binding generation and
// records the operator's reason in the same transaction. It exists because a
// machine swap changes the client uuid while the rustdesk id stays: without
// this action the only recovery was editing the database by hand, and a hand
// edit that forgot the generation left the old client's session able to drive
// the device.
func (s *Service) ResetBinding(ctx context.Context, orgID, deviceID, actorID uint, reason string) (*model.Device, error) {
	if orgID == 0 {
		return nil, fmt.Errorf("%w: organization is required", ErrInvalidInput)
	}
	reason = strings.TrimSpace(reason)
	if reason == "" || utf8.RuneCountInString(reason) > maxResetReasonLen {
		return nil, fmt.Errorf("%w: reason is required (max %d characters)", ErrInvalidInput, maxResetReasonLen)
	}

	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var dev model.Device
		// Lock the row on the dialects that support it: a concurrent compat
		// login can claim the device between this read and the update below,
		// and the reset would then clear the fresh binding while reporting a
		// stale had_binding. SQLite has no row locks (same convention as
		// RegisterTx / claimDeviceTx).
		read := store.ScopedByOrg(tx, orgID)
		if tx.Name() != "sqlite" {
			read = read.Clauses(clause.Locking{Strength: "UPDATE"})
		}
		if err := read.First(&dev, deviceID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrDeviceNotFound
			}
			return err
		}
		hadBinding := dev.BoundUUID != ""

		// The generation always moves: even an unbound row gets +1 so every
		// previously issued snapshot is invalidated unconditionally, and the
		// affected-row count stays 1 on MySQL (clearing an already empty
		// bound_uuid on its own would report 0 changed rows there).
		result := store.ScopedByOrg(tx, orgID).Model(&model.Device{}).
			Where("id = ?", dev.ID).
			Updates(map[string]any{
				"bound_uuid":         "",
				"binding_generation": gorm.Expr("binding_generation + 1"),
				"updated_at":         s.now(),
			})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected == 0 {
			return ErrDeviceNotFound
		}

		return s.record(tx, audit.Entry{
			OrganizationID: orgID,
			ActorUserID:    actorID,
			Action:         "device.binding.reset",
			TargetType:     "device",
			TargetID:       fmt.Sprint(dev.ID),
			Detail: map[string]any{
				"reason":      reason,
				"had_binding": hadBinding,
				"rustdesk_id": dev.RustdeskID,
			},
		})
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

// record writes the audit entry on the caller's transaction. A service without
// a recorder refuses the mutation rather than commit an unauditable one.
func (s *Service) record(tx *gorm.DB, entry audit.Entry) error {
	if s.recorder == nil {
		return errors.New("device: no audit recorder configured")
	}
	return s.recorder.RecordTx(tx, entry)
}
