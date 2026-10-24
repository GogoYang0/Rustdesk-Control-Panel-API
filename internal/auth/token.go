package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// Personal token format and lifecycle bounds.
const (
	// TokenPlainPrefix marks a personal token so it is recognisable in logs and
	// never mistaken for a JWT.
	TokenPlainPrefix = "rdt_"
	// MaxTokensPerUserOrg bounds active tokens per user per organization.
	MaxTokensPerUserOrg = 20
	// DefaultTokenTTL is the default lifetime when the request omits one.
	DefaultTokenTTL = 90 * 24 * time.Hour
	// MinTokenTTLDays and MaxTokenTTLDays bound the requested lifetime.
	MinTokenTTLDays = 1
	MaxTokenTTLDays = 365
	maxTokenNameLen = 128
)

// Token errors mapped to HTTP statuses by the handler.
var (
	ErrTokenNotFound     = errors.New("token not found")
	ErrTokenInactive     = errors.New("token is revoked or expired")
	ErrTooManyTokens     = errors.New("too many active tokens for this organization")
	ErrInvalidTokenInput = errors.New("invalid token input")
)

// TokenService creates, authenticates, lists and revokes personal tokens.
// Authentication is cross-tenant by design (the digest alone identifies the
// row), while listing and creation stay inside the tenant scope.
type TokenService struct {
	db  *gorm.DB
	now func() time.Time
}

// NewTokenService builds the service.
func NewTokenService(db *gorm.DB, now func() time.Time) *TokenService {
	if now == nil {
		now = time.Now
	}
	return &TokenService{db: db, now: now}
}

// Create mints a token and returns its plaintext exactly once. permissions must
// already be validated by the caller against the user's current role; the
// effective set is re-intersected on every request anyway.
func (s *TokenService) Create(ctx context.Context, userID, orgID uint, name string, permissions []string, ttl time.Duration) (string, *model.APIToken, error) {
	if userID == 0 || orgID == 0 {
		return "", nil, fmt.Errorf("%w: user and organization are required", ErrInvalidTokenInput)
	}
	name = trimTokenName(name)
	if name == "" {
		return "", nil, fmt.Errorf("%w: name is required", ErrInvalidTokenInput)
	}
	if ttl <= 0 {
		ttl = DefaultTokenTTL
	}

	now := s.now().UTC()
	var active int64
	if err := store.ScopedByOrg(s.db.WithContext(ctx), orgID).
		Model(&model.APIToken{}).
		Where("user_id = ? AND revoked_at IS NULL AND expires_at > ?", userID, now).
		Count(&active).Error; err != nil {
		return "", nil, err
	}
	if active >= MaxTokensPerUserOrg {
		return "", nil, ErrTooManyTokens
	}

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, fmt.Errorf("generate token: %w", err)
	}
	plaintext := TokenPlainPrefix + base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(plaintext))

	row := &model.APIToken{
		UserID:         userID,
		OrganizationID: orgID,
		Name:           name,
		TokenPrefix:    plaintext[:8],
		TokenHash:      hex.EncodeToString(sum[:]),
		ExpiresAt:      now.Add(ttl),
	}
	if err := row.SetPermissions(permissions); err != nil {
		return "", nil, err
	}
	if err := store.ScopedByOrg(s.db.WithContext(ctx), orgID).Create(row).Error; err != nil {
		return "", nil, err
	}
	return plaintext, row, nil
}

// Authenticate resolves a plaintext token to its row and refreshes last_used_at.
func (s *TokenService) Authenticate(ctx context.Context, plaintext string) (*model.APIToken, error) {
	if plaintext == "" {
		return nil, ErrTokenNotFound
	}
	sum := sha256.Sum256([]byte(plaintext))
	var row model.APIToken
	// Cross-tenant lookup: the digest identifies the token before any org
	// context is known. The returned org is then matched against the path.
	if err := store.WithoutTenantScope(s.db.WithContext(ctx)).
		Where("token_hash = ?", hex.EncodeToString(sum[:])).
		First(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrTokenNotFound
		}
		return nil, err
	}
	now := s.now().UTC()
	if !row.Active(now) {
		return nil, ErrTokenInactive
	}
	if err := store.ScopedByOrg(s.db.WithContext(ctx), row.OrganizationID).
		Model(&model.APIToken{}).
		Where("id = ?", row.ID).
		Update("last_used_at", now).Error; err != nil {
		return nil, err
	}
	row.LastUsedAt = &now
	return &row, nil
}

// List returns the caller's tokens of one organization, without plaintext.
func (s *TokenService) List(ctx context.Context, userID, orgID uint) ([]model.APIToken, error) {
	var rows []model.APIToken
	if err := store.ScopedByOrg(s.db.WithContext(ctx), orgID).
		Where("user_id = ?", userID).
		Order("id DESC").
		Find(&rows).Error; err != nil {
		return nil, err
	}
	return rows, nil
}

// Revoke marks one of the caller's tokens revoked. Revoking an already revoked
// token is idempotent; another user's token is a not-found.
func (s *TokenService) Revoke(ctx context.Context, userID, tokenID uint) error {
	if userID == 0 || tokenID == 0 {
		return ErrTokenNotFound
	}
	res := store.WithoutTenantScope(s.db.WithContext(ctx)).
		Model(&model.APIToken{}).
		Where("id = ? AND user_id = ?", tokenID, userID).
		Update("revoked_at", s.now().UTC())
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrTokenNotFound
	}
	return nil
}

// trimTokenName trims and bounds a display name.
func trimTokenName(name string) string {
	trimmed := strings.TrimSpace(name)
	if utf8.RuneCountInString(trimmed) > maxTokenNameLen {
		return ""
	}
	return trimmed
}
