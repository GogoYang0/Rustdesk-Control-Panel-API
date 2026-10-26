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
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/authz"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// ErrDeviceNotFound is returned when a device id does not exist in the org.
var ErrDeviceNotFound = errors.New("device not found")

// ErrDeviceDisabled reports a device an administrator stopped: logins, client
// claims, heartbeats and ticket redemptions are refused while it is disabled.
var ErrDeviceDisabled = errors.New("device is disabled")

// ErrInvalidInput reports client input that does not satisfy the contract.
var ErrInvalidInput = errors.New("invalid device input")

// ErrOwnerNotMember reports an assignment target that holds no active
// membership in the device's organization.
var ErrOwnerNotMember = errors.New("owner is not an active member")

// ErrDeviceGroupNotFound reports a requested device group that does not exist
// in the organization.
var ErrDeviceGroupNotFound = errors.New("device group not found")

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
	if dev.Disabled {
		// A disabled device is not resurrected by log lines either: the
		// administrator stopped it, so replayed traffic must not make it look
		// online until it is explicitly re-enabled.
		return nil, nil
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
	if dev.Disabled {
		return nil, ErrDeviceDisabled
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

// SetDisabled disables or re-enables a device. Disabling revokes every active
// compat session of that device in the same transaction and records the change
// with its audit entry: a stopped device must not keep a 720h token that still
// drives it. Repeating the current state is a successful no-op with no audit
// row. A service without a recorder refuses the mutation.
func (s *Service) SetDisabled(ctx context.Context, orgID, deviceID, actorID uint, disabled bool) (*model.Device, error) {
	return s.Update(ctx, orgID, deviceID, actorID, UpdateInput{Disabled: &disabled})
}

// AssignInput carries the optional fields of an ownership/annotation update.
// A nil pointer leaves the field alone; a pointer to 0 clears the owner.
type AssignInput struct {
	OwnerUserID *uint
	Note        *string
}

// Assign updates the owner and the note of one device. The owner must be an
// active member of the same organization: ownership decides which devices a
// user reaches, so pointing it at somebody who cannot authenticate would hide
// the device from every non-administrator. Setting the same value twice writes
// no audit row, and a service without a recorder refuses the mutation.
func (s *Service) Assign(ctx context.Context, orgID, deviceID, actorID uint, in AssignInput) (*model.Device, error) {
	return s.Update(ctx, orgID, deviceID, actorID, UpdateInput{OwnerUserID: in.OwnerUserID, Note: in.Note})
}

// maxNoteLen matches the size:255 column of model.Device.Note.
const maxNoteLen = 255

// UpdateInput carries the fields of one device update. A nil pointer leaves the
// field alone; OwnerUserID pointed at 0 clears the owner. DeviceGroupID never
// clears: a device is moved from one group to another (the management API owns
// the explicit ungrouping).
type UpdateInput struct {
	Disabled      *bool
	OwnerUserID   *uint
	Note          *string
	Name          *string
	DeviceGroupID *uint
}

// Update applies every requested change to one device inside a single audited
// transaction: a request that names several fields either takes effect in full
// or not at all, and each changed field writes its own audit row
// (device.assign, device.note, device.rename, device.group,
// device.disable/device.enable). Disabling revokes the device's active compat
// sessions in the same transaction. Fields left at their current value write no
// audit row, and a service without a recorder refuses the whole mutation. It
// never touches the client binding: that belongs to the login path alone.
func (s *Service) Update(ctx context.Context, orgID, deviceID, actorID uint, in UpdateInput) (*model.Device, error) {
	if orgID == 0 {
		return nil, fmt.Errorf("%w: organization is required", ErrInvalidInput)
	}
	if in.Note != nil && len([]rune(*in.Note)) > maxNoteLen {
		return nil, fmt.Errorf("%w: note exceeds %d characters", ErrInvalidInput, maxNoteLen)
	}
	if in.Name != nil {
		if *in.Name == "" {
			return nil, fmt.Errorf("%w: name is required", ErrInvalidInput)
		}
		if len([]rune(*in.Name)) > maxNameLen {
			return nil, fmt.Errorf("%w: name exceeds %d characters", ErrInvalidInput, maxNameLen)
		}
	}
	if in.DeviceGroupID != nil && *in.DeviceGroupID == 0 {
		return nil, fmt.Errorf("%w: device_group_id is required", ErrInvalidInput)
	}

	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var dev model.Device
		read := store.ScopedByOrg(tx, orgID)
		if tx.Name() != "sqlite" {
			// Serialise against a concurrent claim/login: both write the same
			// device row, and the login path re-reads it under this lock.
			read = read.Clauses(clause.Locking{Strength: "UPDATE"})
		}
		if err := read.First(&dev, deviceID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrDeviceNotFound
			}
			return err
		}

		now := s.now()
		updates := map[string]any{}

		ownerChanged := false
		var ownerFrom, ownerTo any
		if in.OwnerUserID != nil {
			next := *in.OwnerUserID
			if next != 0 {
				// The target must be an active member whose role still resolves: a
				// dangling role_id authorizes nothing (authz resolution fails
				// closed), so pointing ownership at it would hide the device
				// from every non-administrator. The role set is a subquery of
				// the same statement, so the check cannot straddle a concurrent
				// role deletion.
				var count int64
				if err := store.ScopedByOrg(tx, orgID).Model(&model.Membership{}).
					Where("user_id = ? AND disabled = ? AND role_id IN (?)", next, false,
						authz.ResolvableRoleIDs(tx, orgID)).
					Count(&count).Error; err != nil {
					return err
				}
				if count == 0 {
					return ErrOwnerNotMember
				}
			}
			if !sameOwner(dev.OwnerUserID, next) {
				ownerChanged = true
				ownerFrom, ownerTo = nullableID(dev.OwnerUserID), nullableID(&next)
				if next == 0 {
					updates["owner_user_id"] = nil
				} else {
					updates["owner_user_id"] = next
				}
			}
		}

		noteChanged := false
		previousNote := dev.Note
		if in.Note != nil && dev.Note != *in.Note {
			noteChanged = true
			updates["note"] = *in.Note
		}

		disabledChanged := false
		var revoked int64
		if in.Disabled != nil && dev.Disabled != *in.Disabled {
			disabledChanged = true
			updates["disabled"] = *in.Disabled
			if *in.Disabled {
				updates["disabled_at"] = now
				updates["disabled_by"] = actorID
				n, err := revokeDeviceSessions(tx, orgID, dev.RustdeskID, now)
				if err != nil {
					return fmt.Errorf("revoke compat sessions: %w", err)
				}
				revoked = n
			} else {
				updates["disabled_at"] = nil
				updates["disabled_by"] = uint(0)
			}
		}

		renameChanged := false
		previousName := dev.Name
		if in.Name != nil && dev.Name != *in.Name {
			renameChanged = true
			updates["name"] = *in.Name
		}

		groupChanged := false
		var groupFrom, groupTo any
		if in.DeviceGroupID != nil && (dev.DeviceGroupID == nil || *dev.DeviceGroupID != *in.DeviceGroupID) {
			// The group is resolved by the caller, so a dangling id can only
			// arrive from a race with a group deletion. The row is read with a
			// write lock on the served dialects, which serialises against
			// DeleteDeviceGroup: either the deletion has not committed yet and
			// waits for this transaction (its own ungrouping sweep then sees the
			// device), or the locked current read reports the group as gone.
			groupRead := store.ScopedByOrg(tx, orgID).Select("id").Where("id = ?", *in.DeviceGroupID)
			if tx.Name() != "sqlite" {
				groupRead = groupRead.Clauses(clause.Locking{Strength: "UPDATE"})
			}
			var group model.DeviceGroup
			err := groupRead.First(&group).Error
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrDeviceGroupNotFound
			}
			if err != nil {
				return err
			}
			groupChanged = true
			groupFrom = nullableID(dev.DeviceGroupID)
			groupTo = nullableID(in.DeviceGroupID)
			updates["device_group_id"] = *in.DeviceGroupID
		}

		if !ownerChanged && !noteChanged && !disabledChanged && !renameChanged && !groupChanged {
			return nil
		}
		updates["updated_at"] = now

		res := store.ScopedByOrg(tx, orgID).Model(&model.Device{}).
			Where("id = ?", dev.ID).Updates(updates)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return ErrDeviceNotFound
		}

		if ownerChanged {
			if err := s.record(tx, audit.Entry{
				OrganizationID: orgID,
				ActorUserID:    actorID,
				Action:         "device.assign",
				TargetType:     "device",
				TargetID:       fmt.Sprint(dev.ID),
				Detail: map[string]any{
					"rustdesk_id": dev.RustdeskID,
					"from":        ownerFrom,
					"to":          ownerTo,
				},
			}); err != nil {
				return err
			}
		}
		if noteChanged {
			if err := s.record(tx, audit.Entry{
				OrganizationID: orgID,
				ActorUserID:    actorID,
				Action:         "device.note",
				TargetType:     "device",
				TargetID:       fmt.Sprint(dev.ID),
				Detail: map[string]any{
					"rustdesk_id": dev.RustdeskID,
					"previous":    previousNote,
					"note":        *in.Note,
				},
			}); err != nil {
				return err
			}
		}
		if disabledChanged {
			action := "device.enable"
			if *in.Disabled {
				action = "device.disable"
			}
			if err := s.record(tx, audit.Entry{
				OrganizationID: orgID,
				ActorUserID:    actorID,
				Action:         action,
				TargetType:     "device",
				TargetID:       fmt.Sprint(dev.ID),
				Detail: map[string]any{
					"rustdesk_id":      dev.RustdeskID,
					"revoked_sessions": revoked,
				},
			}); err != nil {
				return err
			}
		}
		if renameChanged {
			if err := s.record(tx, audit.Entry{
				OrganizationID: orgID,
				ActorUserID:    actorID,
				Action:         "device.rename",
				TargetType:     "device",
				TargetID:       fmt.Sprint(dev.ID),
				Detail: map[string]any{
					"rustdesk_id": dev.RustdeskID,
					"from":        previousName,
					"to":          *in.Name,
				},
			}); err != nil {
				return err
			}
		}
		if groupChanged {
			if err := s.record(tx, audit.Entry{
				OrganizationID: orgID,
				ActorUserID:    actorID,
				Action:         "device.group",
				TargetType:     "device",
				TargetID:       fmt.Sprint(dev.ID),
				Detail: map[string]any{
					"rustdesk_id": dev.RustdeskID,
					"from":        groupFrom,
					"to":          groupTo,
				},
			}); err != nil {
				return err
			}
		}
		return nil
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

// sameOwner reports whether the stored owner already is the requested one.
func sameOwner(current *uint, next uint) bool {
	if next == 0 {
		return current == nil
	}
	return current != nil && *current == next
}

// nullableID renders a nullable reference for an audit detail. A zero pointer
// renders as nil because 0 is never a valid id: it means "nobody" or "no
// group".
func nullableID(v *uint) any {
	if v == nil || *v == 0 {
		return nil
	}
	return *v
}

// revokeDeviceSessions revokes the active compat sessions bound to a rustdesk
// id inside one organization. The compat session table keys the client-visible
// device id (a string), not the device row id, so both are passed through.
func revokeDeviceSessions(tx *gorm.DB, orgID uint, rustdeskID string, now time.Time) (int64, error) {
	res := store.WithoutTenantScope(tx).
		Model(&model.CompatSession{}).
		Where("organization_id = ? AND device_id = ? AND revoked_at IS NULL AND expires_at > ?",
			orgID, rustdeskID, now).
		Update("revoked_at", now)
	if res.Error != nil {
		return 0, res.Error
	}
	return res.RowsAffected, nil
}

// record writes the audit entry on the caller's transaction. A service without
// a recorder refuses the mutation rather than commit an unauditable one.
func (s *Service) record(tx *gorm.DB, entry audit.Entry) error {
	if s.recorder == nil {
		return errors.New("device: no audit recorder configured")
	}
	return s.recorder.RecordTx(tx, entry)
}
