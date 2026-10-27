package passkey

import (
	"context"
	"errors"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
)

// List returns the caller's credentials, oldest first.
func (s *Service) List(ctx context.Context, userID uint) ([]model.UserPasskey, error) {
	return s.credentials(ctx, userID)
}

// Count reports how many credentials an account holds.
func (s *Service) Count(ctx context.Context, userID uint) (int64, error) {
	var count int64
	err := s.db.WithContext(ctx).Model(&model.UserPasskey{}).Where("user_id = ?", userID).Count(&count).Error
	return count, err
}

// Rename changes the display name of one credential the caller owns.
func (s *Service) Rename(ctx context.Context, userID, passkeyID uint, name string) (*model.UserPasskey, error) {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" || len(trimmed) > maxPasskeyNameLen {
		return nil, ErrInvalidName
	}
	// Existence is checked with a SELECT: MySQL reports the *changed* row count,
	// so renaming a credential to its current name would look like a miss.
	var row model.UserPasskey
	err := s.db.WithContext(ctx).Where("id = ? AND user_id = ?", passkeyID, userID).First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrPasskeyNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := s.db.WithContext(ctx).Model(&model.UserPasskey{}).
		Where("id = ? AND user_id = ?", passkeyID, userID).
		Update("name", trimmed).Error; err != nil {
		return nil, err
	}
	row.Name = trimmed
	return &row, nil
}

// Delete removes one credential. The last credential of an account without a
// password is refused: removing it would leave the account with no way to log
// in. The count and the delete share a transaction, and non-SQLite dialects
// lock the rows so two concurrent deletes cannot both observe "two left".
func (s *Service) Delete(ctx context.Context, userID, passkeyID uint) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var user model.User
		if err := tx.Where("id = ?", userID).First(&user).Error; err != nil {
			return err
		}

		query := tx.Model(&model.UserPasskey{}).Where("user_id = ?", userID)
		if tx.Name() != "sqlite" {
			query = query.Clauses(clause.Locking{Strength: "UPDATE"})
		}
		var rows []model.UserPasskey
		if err := query.Find(&rows).Error; err != nil {
			return err
		}

		target := false
		for _, row := range rows {
			if row.ID == passkeyID {
				target = true
				break
			}
		}
		if !target {
			return ErrPasskeyNotFound
		}
		if len(rows) == 1 && user.PasswordHash == "" {
			return ErrLastCredential
		}
		return tx.Where("id = ? AND user_id = ?", passkeyID, userID).Delete(&model.UserPasskey{}).Error
	})
}

// Sweep deletes ceremonies that expired before the cutoff. Expiry already
// blocks consumption, so this only reclaims space.
func (s *Service) Sweep(ctx context.Context, before time.Time) (int64, error) {
	res := s.db.WithContext(ctx).Where("expires_at < ?", before).Delete(&model.WebAuthnCeremony{})
	return res.RowsAffected, res.Error
}
