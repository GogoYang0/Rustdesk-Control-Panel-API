package oidc

import (
	"context"
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
)

// ticketTTL is how long the SPA has to exchange the ticket the callback put in
// the URL. It is short on purpose: the ticket is a bearer value in a browser
// history entry (design O6).
const ticketTTL = 60 * time.Second

// createFlow records one authorization request before the browser leaves for
// the IdP.
func (s *Service) createFlow(ctx context.Context, flow *model.ExternalLoginFlow) error {
	return s.db.WithContext(ctx).Create(flow).Error
}

// consumeState burns the state row exactly once. The conditional UPDATE is what
// makes a replayed callback fail even when two arrive at the same instant.
func (s *Service) consumeState(ctx context.Context, state string) (*model.ExternalLoginFlow, error) {
	now := s.cfg.Now()
	res := s.db.WithContext(ctx).Model(&model.ExternalLoginFlow{}).
		Where("state = ? AND consumed_at IS NULL AND expires_at > ?", state, now).
		Update("consumed_at", now)
	if res.Error != nil {
		return nil, res.Error
	}
	if res.RowsAffected == 0 {
		return nil, s.stateRejection(ctx, state, now)
	}

	var flow model.ExternalLoginFlow
	if err := s.db.WithContext(ctx).Where("state = ?", state).First(&flow).Error; err != nil {
		return nil, err
	}
	return &flow, nil
}

// stateRejection re-reads the row only to report *why* the update matched
// nothing. The decision itself was already made by the UPDATE above.
func (s *Service) stateRejection(ctx context.Context, state string, now time.Time) error {
	var flow model.ExternalLoginFlow
	err := s.db.WithContext(ctx).Where("state = ?", state).First(&flow).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ErrInvalidState
	}
	if err != nil {
		return err
	}
	if flow.ConsumedAt != nil {
		return ErrStateUsed
	}
	if !flow.ExpiresAt.After(now) {
		return ErrStateExpired
	}
	return ErrInvalidState
}

// attachTicket stores the hashed ticket on an already-consumed flow. Requiring
// consumed_at keeps the two phases ordered: a ticket can never exist for a
// callback that has not passed the state check.
func (s *Service) attachTicket(ctx context.Context, state, ticketHash string, userID uint, ttl time.Duration) error {
	now := s.cfg.Now()
	res := s.db.WithContext(ctx).Model(&model.ExternalLoginFlow{}).
		Where("state = ? AND consumed_at IS NOT NULL AND ticket_hash = ''", state).
		Updates(map[string]any{
			"ticket_hash":       ticketHash,
			"ticket_expires_at": now.Add(ttl),
			"user_id":           userID,
		})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected != 1 {
		return fmt.Errorf("%w: flow is not ready for a ticket", ErrInvalidState)
	}
	return nil
}

// consumeTicket burns a ticket and returns the account it was issued for.
func (s *Service) consumeTicket(ctx context.Context, ticketHash string) (uint, error) {
	now := s.cfg.Now()
	res := s.db.WithContext(ctx).Model(&model.ExternalLoginFlow{}).
		Where("ticket_hash = ? AND ticket_consumed_at IS NULL AND ticket_expires_at > ?", ticketHash, now).
		Update("ticket_consumed_at", now)
	if res.Error != nil {
		return 0, res.Error
	}
	if res.RowsAffected != 1 {
		return 0, ErrInvalidTicket
	}

	var flow model.ExternalLoginFlow
	if err := s.db.WithContext(ctx).Where("ticket_hash = ?", ticketHash).First(&flow).Error; err != nil {
		return 0, err
	}
	if flow.UserID == nil {
		return 0, ErrInvalidTicket
	}
	return *flow.UserID, nil
}

// Sweep drops flows that can no longer be used. Expiry already blocks every
// consumption path; this only reclaims space.
func (s *Service) Sweep(ctx context.Context, before time.Time) (int64, error) {
	res := s.db.WithContext(ctx).
		Where("expires_at < ? OR (ticket_expires_at IS NOT NULL AND ticket_expires_at < ?)", before, before).
		Delete(&model.ExternalLoginFlow{})
	return res.RowsAffected, res.Error
}
