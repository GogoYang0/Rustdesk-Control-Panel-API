package passkey

import (
	"context"
	"strings"

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
	res := s.db.WithContext(ctx).Model(&model.UserPasskey{}).
		Where("id = ? AND user_id = ?", passkeyID, userID).
		Update("name", trimmed)
	if res.Error != nil {
		return nil, res.Error
	}
	if res.RowsAffected == 0 {
		return nil, ErrPasskeyNotFound
	}

	var row model.UserPasskey
	if err := s.db.WithContext(ctx).Where("id = ?", passkeyID).First(&row).Error; err != nil {
		return nil, err
	}
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
		if tx.Dialector.Name() != "sqlite" {
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
