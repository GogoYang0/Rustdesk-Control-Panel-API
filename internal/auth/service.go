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

// ErrRefreshReplay 表示 refresh token 已被使用（重放）。遇到该错误时调用方
// 应清除客户端凭据并要求重新登录。
var ErrRefreshReplay = fmt.Errorf("refresh token already used")

// RotateRefresh validates an opaque refresh token against its stored hash,
// revokes it, and issues a new pair. Reusing a revoked token revokes every
// refresh token of that user (token-family revocation, design C3).
//
// 校验与撤销在同一事务内完成：行锁 + 条件更新（WHERE revoked_at IS NULL），
// 并发提交同一 refresh 时只有一个请求能成功，其余按重放处理（CWE-367）。
// 重放时的"全族撤销"在事务提交/回滚之后单独执行——在事务内撤销会随错误回滚失效。
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

		// 条件更新：并发下仅一次能命中，未命中视为重放
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
		// 事务已回滚，族撤销必须在事务外单独执行才能生效
		if revokeErr := revokeFamily(s.db, userID, time.Now()); revokeErr != nil {
			return "", "", revokeErr
		}
		return "", "", ErrRefreshReplay
	}
	if err != nil {
		return "", "", err
	}

	if s.logger != nil {
		// 只记录用户与事件，绝不记录 token 内容
		s.logger.Info("refresh token rotated", "user_id", userID)
	}
	return access, newRefresh, nil
}

// revokeFamily 撤销该用户全部未撤销的 refresh token。
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
