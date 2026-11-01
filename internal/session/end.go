package session

import (
	"context"
	"errors"
	"fmt"

	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/audit"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// ErrSessionNotOpen reports a session that is not in the open state.
var ErrSessionNotOpen = errors.New("session is not open")

// EndByAdmin closes one open session and appends its timeline entry. The
// conditional status update makes it race-safe against the native disconnect
// ingest and the background sweeps: exactly one writer appends the event.
func (s *Service) EndByAdmin(ctx context.Context, orgID, sessionID, actorID uint) (*model.Session, error) {
	if orgID == 0 || sessionID == 0 {
		return nil, fmt.Errorf("%w: organization and session are required", ErrInvalidInput)
	}
	var out model.Session
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var sess model.Session
		if err := store.ScopedByOrg(tx, orgID).First(&sess, sessionID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrSessionNotFound
			}
			return err
		}
		if sess.Status != model.SessionStatusOpen {
			return ErrSessionNotOpen
		}
		now := s.now().UTC()
		res := store.ScopedByOrg(tx, orgID).Model(&model.Session{}).
			Where("id = ? AND status = ?", sess.ID, model.SessionStatusOpen).
			Updates(map[string]any{
				"status":     model.SessionStatusClosed,
				"ended_at":   now,
				"end_reason": model.SessionEndAdminEnded,
				"revision":   gorm.Expr("revision + 1"),
				"updated_at": now,
			})
		if res.Error != nil {
			return fmt.Errorf("end session: %w", res.Error)
		}
		if res.RowsAffected != 1 {
			return ErrSessionNotOpen
		}
		if err := s.appendEvent(tx, orgID, sess.ID, model.SessionEndAdminEnded, now,
			map[string]any{"actor_user_id": actorID}); err != nil {
			return err
		}
		if err := s.record(tx, audit.Entry{
			OrganizationID: orgID,
			ActorUserID:    actorID,
			Action:         "session.end",
			TargetType:     "session",
			TargetID:       fmt.Sprint(sess.ID),
			Detail: map[string]any{
				"origin":    sess.Origin,
				"device_id": sess.DeviceID,
			},
		}); err != nil {
			return err
		}
		if err := store.ScopedByOrg(tx, orgID).First(&out, sess.ID).Error; err != nil {
			return fmt.Errorf("reload ended session: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}
