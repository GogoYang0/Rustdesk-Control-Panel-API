package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

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

// ErrRefreshReplay reports a reused refresh token (replay). Callers should
// clear client credentials and require a fresh login.
var ErrRefreshReplay = fmt.Errorf("refresh token already used")

// RotateRefresh validates an opaque refresh token against its stored hash,
// revokes it, and issues a new pair. Reusing a revoked token revokes every
// refresh token of that user (token-family revocation, design C3).
//
// Validation and revocation run in a single transaction with a row lock and a
// conditional update (WHERE revoked_at IS NULL), so concurrent submissions of the
// same refresh token let exactly one request win; the rest are treated as replays
// (CWE-367). Family revocation on replay runs after the transaction: revoking
// inside it would be rolled back together with the error.
func (s *Service) RotateRefresh(oldRefresh string) (access, newRefresh string, err error) {
	hash := hashToken(oldRefresh)
	var userID uint

	err = s.db.Transaction(func(tx *gorm.DB) error {
		var row model.RefreshToken
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("token_hash = ?", hash).First(&row).Error; err != nil {
			return fmt.Errorf("refresh token not found")
		}
		userID = row.UserID

		now := time.Now()
		if row.RevokedAt != nil {
			return ErrRefreshReplay
		}
		if now.After(row.ExpiresAt) {
			return fmt.Errorf("refresh token expired")
		}

		access, newRefresh, err = s.issuer.Issue(row.UserID)
		if err != nil {
			return err
		}

		// Conditional update: under concurrency only one caller can hit the row
		res := tx.Model(&model.RefreshToken{}).
			Where("id = ? AND revoked_at IS NULL", row.ID).
			Update("revoked_at", now)
		if res.Error != nil {
			return fmt.Errorf("revoke refresh token: %w", res.Error)
		}
		if res.RowsAffected == 0 {
			return ErrRefreshReplay
		}

		next := model.RefreshToken{
			UserID:    row.UserID,
			TokenHash: hashToken(newRefresh),
			ExpiresAt: now.Add(s.issuer.RefreshTTL()),
		}
		if err := tx.Create(&next).Error; err != nil {
			return fmt.Errorf("persist refresh token: %w", err)
		}
		return tx.Model(&model.RefreshToken{}).
			Where("id = ?", row.ID).
			Update("replaced_by", next.ID).Error
	})

	if errors.Is(err, ErrRefreshReplay) {
		// The transaction rolled back; family revocation must run outside it to persist
		if revokeErr := revokeFamily(s.db, userID, time.Now()); revokeErr != nil {
			return "", "", revokeErr
		}
		return "", "", ErrRefreshReplay
	}
	if err != nil {
		return "", "", err
	}

	if s.logger != nil {
		// Log the event and user only; never log token material
		s.logger.Info("refresh token rotated", "user_id", userID)
	}
	return access, newRefresh, nil
}

// RevokeUserRefreshTokens revokes every active refresh token of one user. It
// accepts a transaction so credential changes can commit the revoke together
// with the password/MFA update.
func RevokeUserRefreshTokens(tx *gorm.DB, userID uint, now time.Time) error {
	if userID == 0 {
		return nil
	}
	return tx.Model(&model.RefreshToken{}).
		Where("user_id = ? AND revoked_at IS NULL", userID).
		Update("revoked_at", now).Error
}

// revokeFamily revokes every non-revoked refresh token of the user.
func revokeFamily(tx *gorm.DB, userID uint, now time.Time) error {
	if err := tx.Model(&model.RefreshToken{}).
		Where("user_id = ? AND revoked_at IS NULL", userID).
		Update("revoked_at", now).Error; err != nil {
		return fmt.Errorf("revoke token family: %w", err)
	}
	return nil
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
