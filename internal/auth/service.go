package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
)

// Logger is the minimal logging surface used by the auth service.
// Implementations must never receive token material from this package.
type Logger interface {
	Info(msg string, keysAndValues ...any)
}

// Service issues and rotates authentication tokens.
type Service struct {
	db     *gorm.DB
	issuer *Issuer
	logger Logger
}

// NewService builds the auth service. logger may be nil.
func NewService(db *gorm.DB, issuer *Issuer, logger Logger) *Service {
	return &Service{db: db, issuer: issuer, logger: logger}
}

// Issuer exposes the underlying token issuer (used by middleware wiring).
func (s *Service) Issuer() *Issuer { return s.issuer }

// IssueTokens mints a fresh access/refresh pair and persists the refresh hash.
func (s *Service) IssueTokens(userID uint) (access, refresh string, err error) {
	access, refresh, err = s.issuer.Issue(userID)
	if err != nil {
		return "", "", err
	}
	if err := s.storeRefresh(userID, refresh); err != nil {
		return "", "", err
	}
	return access, refresh, nil
}

// RotateRefresh validates an opaque refresh token against its stored hash,
// revokes it, and issues a new pair. Reusing a revoked token revokes every
// refresh token of that user (token-family revocation, design C3).
func (s *Service) RotateRefresh(oldRefresh string) (access, newRefresh string, err error) {
	hash := hashToken(oldRefresh)

	var row model.RefreshToken
	if err := s.db.Where("token_hash = ?", hash).First(&row).Error; err != nil {
		return "", "", fmt.Errorf("refresh token not found")
	}

	if row.RevokedAt != nil {
		// 重放已撤销的 token：撤销该用户全部 refresh token
		now := time.Now()
		if err := s.db.Model(&model.RefreshToken{}).
			Where("user_id = ? AND revoked_at IS NULL", row.UserID).
			Update("revoked_at", now).Error; err != nil {
			return "", "", fmt.Errorf("revoke token family: %w", err)
		}
		return "", "", fmt.Errorf("refresh token already used")
	}

	if time.Now().After(row.ExpiresAt) {
		return "", "", fmt.Errorf("refresh token expired")
	}

	access, newRefresh, err = s.issuer.Issue(row.UserID)
	if err != nil {
		return "", "", err
	}

	err = s.db.Transaction(func(tx *gorm.DB) error {
		now := time.Now()
		newHash := hashToken(newRefresh)
		var next model.RefreshToken
		if err := tx.Create(&model.RefreshToken{
			UserID:    row.UserID,
			TokenHash: newHash,
			ExpiresAt: now.Add(s.issuer.RefreshTTL()),
		}).Error; err != nil {
			return fmt.Errorf("persist refresh token: %w", err)
		}
		if err := tx.Where("token_hash = ?", newHash).First(&next).Error; err != nil {
			return fmt.Errorf("load new refresh token: %w", err)
		}
		return tx.Model(&model.RefreshToken{}).
			Where("id = ?", row.ID).
			Updates(map[string]any{"revoked_at": now, "replaced_by": next.ID}).Error
	})
	if err != nil {
		return "", "", err
	}

	if s.logger != nil {
		// 只记录用户与事件，绝不记录 token 内容
		s.logger.Info("refresh token rotated", "user_id", row.UserID)
	}
	return access, newRefresh, nil
}

func (s *Service) storeRefresh(userID uint, refresh string) error {
	row := model.RefreshToken{
		UserID:    userID,
		TokenHash: hashToken(refresh),
		ExpiresAt: time.Now().Add(s.issuer.RefreshTTL()),
	}
	if err := s.db.Create(&row).Error; err != nil {
		return fmt.Errorf("persist refresh token: %w", err)
	}
	return nil
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
