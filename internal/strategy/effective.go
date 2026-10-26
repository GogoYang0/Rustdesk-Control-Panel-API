package strategy

import (
	"context"
	"encoding/json"
	"errors"

	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// Delivery is what a heartbeat should put on the wire. Deliver=false means the
// response carries neither `strategy` nor `modified_at`.
//
// The two fields travel together on purpose: the client stores `modified_at`
// independently of `strategy` (src/hbbs_http/sync.rs), so sending the version
// without the options would make the client believe it is up to date while it
// still holds the old configuration — and it would never ask again.
type Delivery struct {
	Options    map[string]string
	Version    int64
	Deliver    bool
	StrategyID *uint
}

// EffectiveForDevice resolves the strategy that applies to a device inside the
// organization, following design D1:
//
//	device.strategy_id ?? device_group.strategy_id ?? owner's membership.strategy_id
//
// A layer whose assignment points at a missing row is skipped (that is an
// integrity accident, e.g. a row deleted out of band, not an administrator's
// intent). A layer that resolves to a disabled strategy stops the walk and
// yields nothing: "disabled" is an explicit decision to deliver no policy, so
// falling through to a broader layer would silently re-apply the very options
// the operator just switched off.
//
// A device id from another organization, or one that does not exist, resolves
// to nil rather than an error: the heartbeat path must stay silent.
func (s *Service) EffectiveForDevice(ctx context.Context, orgID, deviceID uint) (*model.Strategy, error) {
	return s.effective(store.ScopedByOrg(s.db.WithContext(ctx), orgID), deviceID)
}

// EffectiveForDeviceTx is the transactional form used when the resolution has
// to share a transaction with the write that depends on it.
func (s *Service) EffectiveForDeviceTx(tx *gorm.DB, orgID, deviceID uint) (*model.Strategy, error) {
	return s.effective(store.ScopedByOrg(tx, orgID), deviceID)
}

func (s *Service) effective(scoped *gorm.DB, deviceID uint) (*model.Strategy, error) {
	var dev model.Device
	if err := scoped.First(&dev, deviceID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}

	ids := []*uint{dev.StrategyID}
	if dev.DeviceGroupID != nil {
		var grp model.DeviceGroup
		if err := scoped.First(&grp, *dev.DeviceGroupID).Error; err == nil {
			ids = append(ids, grp.StrategyID)
		} else if !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, err
		}
	}
	if dev.OwnerUserID != nil {
		var mem model.Membership
		if err := scoped.Where("user_id = ?", *dev.OwnerUserID).First(&mem).Error; err == nil {
			ids = append(ids, mem.StrategyID)
		} else if !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, err
		}
	}

	for _, id := range ids {
		if id == nil {
			continue
		}
		var row model.Strategy
		if err := scoped.First(&row, *id).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				// Dangling assignment: skip this layer, not the whole walk.
				continue
			}
			return nil, err
		}
		if !row.Enabled {
			return nil, nil
		}
		return &row, nil
	}
	return nil, nil
}

// DeliveryFor decides what to send on a heartbeat. clientVersion is the
// `modified_at` the client echoed back; an equal version means it already
// applied these options and nothing is sent.
//
// The stored options are re-validated against the whitelist on the way out:
// rows written by an older build, by a manual UPDATE or by a future bug must
// not smuggle a network key to the client, which applies whatever it receives.
func (s *Service) DeliveryFor(ctx context.Context, orgID, deviceID uint, clientVersion int64) (Delivery, error) {
	row, err := s.EffectiveForDevice(ctx, orgID, deviceID)
	if err != nil {
		return Delivery{}, err
	}
	if row == nil {
		return Delivery{}, nil
	}
	version := row.Version
	id := row.ID
	if version == clientVersion {
		return Delivery{Version: version, StrategyID: &id}, nil
	}

	options := map[string]string{}
	if row.ConfigOptionsJSON != "" {
		if err := json.Unmarshal([]byte(row.ConfigOptionsJSON), &options); err != nil {
			return Delivery{}, err
		}
	}
	if _, err := NormalizeOptions(options); err != nil {
		return Delivery{}, err
	}
	return Delivery{Options: options, Version: version, Deliver: true, StrategyID: &id}, nil
}
