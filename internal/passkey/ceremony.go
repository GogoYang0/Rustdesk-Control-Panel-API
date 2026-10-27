package passkey

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
)

// beginCeremony stores a fresh session and returns the opaque handle the client
// echoes back. The handle is random and carries no data.
func (s *Service) beginCeremony(ctx context.Context, purpose model.CeremonyPurpose, userID *uint, session *webauthn.SessionData) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate ceremony handle: %w", err)
	}
	handle := base64.RawURLEncoding.EncodeToString(raw)

	encoded, err := json.Marshal(session)
	if err != nil {
		return "", fmt.Errorf("encode ceremony session: %w", err)
	}
	row := model.WebAuthnCeremony{
		Handle:      handle,
		Purpose:     purpose,
		UserID:      userID,
		SessionJSON: string(encoded),
		ExpiresAt:   s.now().Add(s.cfg.CeremonyTTL),
		CreatedAt:   s.now(),
	}
	if err := s.db.WithContext(ctx).Create(&row).Error; err != nil {
		return "", fmt.Errorf("store ceremony: %w", err)
	}
	return handle, nil
}

// loadCeremony reads a ceremony without consuming it, for callers that only
// need its metadata (the login begin step resolves the user first).
func (s *Service) loadCeremony(ctx context.Context, handle string, purpose model.CeremonyPurpose) (model.WebAuthnCeremony, webauthn.SessionData, error) {
	var row model.WebAuthnCeremony
	err := s.db.WithContext(ctx).Where("handle = ? AND purpose = ?", handle, purpose).First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return row, webauthn.SessionData{}, ErrCeremonyNotFound
	}
	if err != nil {
		return row, webauthn.SessionData{}, err
	}
	var session webauthn.SessionData
	if err := json.Unmarshal([]byte(row.SessionJSON), &session); err != nil {
		return row, session, fmt.Errorf("decode ceremony session: %w", err)
	}
	return row, session, nil
}

// consumeCeremony burns a ceremony in one conditional UPDATE, so two concurrent
// finishes can never both succeed.
func (s *Service) consumeCeremony(ctx context.Context, handle string, purpose model.CeremonyPurpose) (model.WebAuthnCeremony, webauthn.SessionData, error) {
	var (
		row     model.WebAuthnCeremony
		session webauthn.SessionData
	)
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		now := s.now()
		res := tx.Model(&model.WebAuthnCeremony{}).
			Where("handle = ? AND purpose = ? AND consumed_at IS NULL AND expires_at > ?", handle, purpose, now).
			Update("consumed_at", now)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected != 1 {
			return classifyCeremonyMiss(tx, handle, purpose, now)
		}
		if err := tx.Where("handle = ?", handle).First(&row).Error; err != nil {
			return err
		}
		return json.Unmarshal([]byte(row.SessionJSON), &session)
	})
	if err != nil {
		return model.WebAuthnCeremony{}, webauthn.SessionData{}, err
	}
	return row, session, nil
}

// consumeStepup burns the step-up half of a ceremony row. A step-up token is
// valid for one business action only.
func (s *Service) consumeStepup(ctx context.Context, handle string) error {
	now := s.now()
	res := s.db.WithContext(ctx).Model(&model.WebAuthnCeremony{}).
		Where("handle = ? AND purpose = ? AND stepup_used_at IS NULL AND consumed_at IS NOT NULL", handle, model.CeremonyStepup).
		Update("stepup_used_at", now)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected != 1 {
		return ErrStepupUsed
	}
	return nil
}

// classifyCeremonyMiss turns a no-op UPDATE into the specific reason, for logs
// and tests. Callers still answer 401 to the client.
func classifyCeremonyMiss(tx *gorm.DB, handle string, purpose model.CeremonyPurpose, now time.Time) error {
	var row model.WebAuthnCeremony
	err := tx.Where("handle = ?", handle).First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ErrCeremonyNotFound
	}
	if err != nil {
		return err
	}
	if row.Purpose != purpose {
		return ErrCeremonyNotFound
	}
	if row.ConsumedAt != nil {
		return ErrCeremonyUsed
	}
	if !row.ExpiresAt.After(now) {
		return ErrCeremonyExpired
	}
	return ErrCeremonyNotFound
}
