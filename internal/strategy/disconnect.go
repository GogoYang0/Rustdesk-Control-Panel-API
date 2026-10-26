package strategy

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/audit"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// DisconnectTTL bounds how long a pending request may wait for a heartbeat. The
// client heartbeats every 30 seconds, so fifteen minutes covers a laptop that
// was asleep; anything older would risk tearing down a connection the operator
// never saw.
const DisconnectTTL = 15 * time.Minute

// maxReasonLen mirrors the column width.
const maxReasonLen = 255

// Disconnect-specific errors.
var (
	ErrDisconnectPending = errors.New("a disconnect request is already pending for this device")
	ErrInvalidReason     = errors.New("a disconnect reason is required")
)

// RequestDisconnect records the intent to drop a device's live connections.
//
// The panel cannot close a connection itself (design D10): the client does it
// when a heartbeat response carries `disconnect`. This row is therefore a
// request with an outcome, not a live action — a pending request that nobody
// consumes expires rather than firing days later.
func (s *Service) RequestDisconnect(ctx context.Context, orgID, actorID, deviceID uint, reason string) (*model.DeviceDisconnect, error) {
	if s.recorder == nil {
		return nil, ErrUnaudited
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return nil, ErrInvalidReason
	}
	if utf8.RuneCountInString(reason) > maxReasonLen {
		return nil, ErrInvalidReason
	}

	var row model.DeviceDisconnect
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		scoped := store.ScopedByOrg(tx, orgID)
		read := scoped
		if tx.Name() != "sqlite" {
			// Two concurrent requests both see zero pending rows otherwise and
			// both insert; the loser would fire a second teardown minutes later
			// on connections nobody asked about. The row lock serialises them.
			read = read.Clauses(clause.Locking{Strength: "UPDATE"})
		}
		var dev model.Device
		if err := read.First(&dev, deviceID).Error; err != nil {
			return notFoundOr(err)
		}

		var pending int64
		if err := scoped.Model(&model.DeviceDisconnect{}).
			Where("device_id = ? AND status = ?", dev.ID, model.DisconnectStatusPending).
			Count(&pending).Error; err != nil {
			return err
		}
		if pending > 0 {
			return ErrDisconnectPending
		}

		now := s.now()
		row = model.DeviceDisconnect{
			OrganizationID: orgID,
			DeviceID:       dev.ID,
			Reason:         reason,
			RequestedBy:    actorID,
			Status:         model.DisconnectStatusPending,
			RequestedAt:    now,
			ExpiresAt:      now.Add(DisconnectTTL),
		}
		if err := scoped.Create(&row).Error; err != nil {
			return err
		}
		return s.recorder.RecordTx(tx, audit.Entry{
			OrganizationID: orgID,
			ActorUserID:    actorID,
			Action:         "device.disconnect.request",
			TargetType:     "device",
			TargetID:       strconv.FormatUint(uint64(dev.ID), 10),
			Detail:         map[string]any{"reason": reason, "expires_at": row.ExpiresAt},
		})
	})
	if err != nil {
		return nil, err
	}
	return &row, nil
}

// TakePendingTx consumes a pending request when the heartbeat reports live
// connections, returning exactly those connection ids.
//
// conns come from the client's own heartbeat payload: the panel cannot invent a
// connection id, so a request can only ever close connections the client just
// told us about. An empty conns means there was nothing to drop, and the
// request stays pending instead of being burned.
func (s *Service) TakePendingTx(tx *gorm.DB, orgID, deviceID uint, conns []int64) ([]int64, error) {
	if len(conns) == 0 {
		return nil, nil
	}
	scoped := store.ScopedByOrg(tx, orgID)

	// An expired request must not fire: the sweep runs every five minutes, so
	// without this condition a heartbeat arriving in that window (or at any
	// time, if the worker is down) could still tear down a connection the
	// operator asked about long ago.
	var row model.DeviceDisconnect
	err := scoped.Where("device_id = ? AND status = ? AND expires_at > ?",
		deviceID, model.DisconnectStatusPending, s.now()).
		Order("id").First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	now := s.now()
	res := scoped.Model(&model.DeviceDisconnect{}).
		Where("id = ? AND status = ?", row.ID, model.DisconnectStatusPending).
		Updates(map[string]any{
			"status":       model.DisconnectStatusFulfilled,
			"fulfilled_at": now,
			"conn_count":   len(conns),
		})
	if res.Error != nil {
		return nil, res.Error
	}
	if res.RowsAffected != 1 {
		// Another heartbeat consumed it first: do not disconnect twice.
		return nil, nil
	}
	if s.recorder != nil {
		if err := s.recorder.RecordTx(tx, audit.Entry{
			OrganizationID: orgID,
			ActorUserID:    row.RequestedBy,
			Action:         "device.disconnect.fulfilled",
			TargetType:     "device",
			TargetID:       strconv.FormatUint(uint64(deviceID), 10),
			Detail:         map[string]any{"conn_count": len(conns), "request_id": row.ID},
		}); err != nil {
			return nil, err
		}
	}
	return conns, nil
}

// ExpireStale closes requests whose TTL passed without a consuming heartbeat.
// The audit entry is written with no actor: nobody acted, the clock did.
func (s *Service) ExpireStale(ctx context.Context, now time.Time) (int64, error) {
	var expired int64
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Expiry is a cross-tenant sweep over a system-clock condition, so it
		// runs unscoped; the rows it touches are selected by status + time.
		var rows []model.DeviceDisconnect
		if err := store.WithoutTenantScope(tx).
			Where("status = ? AND expires_at <= ?", model.DisconnectStatusPending, now).
			Find(&rows).Error; err != nil {
			return err
		}
		for _, row := range rows {
			res := store.WithoutTenantScope(tx).Model(&model.DeviceDisconnect{}).
				Where("id = ? AND status = ?", row.ID, model.DisconnectStatusPending).
				Update("status", model.DisconnectStatusExpired)
			if res.Error != nil {
				return res.Error
			}
			if res.RowsAffected != 1 {
				continue
			}
			expired++
			if s.recorder != nil {
				if err := s.recorder.RecordTx(tx, audit.Entry{
					OrganizationID: row.OrganizationID,
					Action:         "device.disconnect.expired",
					TargetType:     "device",
					TargetID:       strconv.FormatUint(uint64(row.DeviceID), 10),
					Detail:         map[string]any{"request_id": row.ID, "reason": row.Reason},
				}); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return expired, nil
}

// NoteConns records the connection ids the client reported, on the device's
// newest heartbeat row.
//
// It is informational: the disconnect path uses the ids from the request that
// consumed it, so a missing row (the heartbeat lane coalesces to one row per
// 30-second window) loses nothing but a debugging aid.
func (s *Service) NoteConns(ctx context.Context, orgID, deviceID uint, conns []int64) error {
	if len(conns) == 0 {
		return nil
	}
	blob, err := json.Marshal(conns)
	if err != nil {
		return err
	}
	scoped := store.ScopedByOrg(s.db.WithContext(ctx), orgID)
	var row model.DeviceHeartbeat
	err = scoped.Where("device_id = ?", deviceID).Order("at DESC, id DESC").First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	return scoped.Model(&model.DeviceHeartbeat{}).
		Where("id = ?", row.ID).
		Update("conn_ids", string(blob)).Error
}
