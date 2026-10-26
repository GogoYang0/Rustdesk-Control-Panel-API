package compatapi

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"

	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// Second-factor challenge bounds. The client treats the secret as opaque and
// replays it on the second request; it exists only to prove that the request
// carrying the code is the one that passed the password step.
const (
	compatChallengeTTL      = 5 * time.Minute
	compatChallengeAttempts = 5
)

// errChallengeInvalid collapses every unusable-challenge state into one answer:
// expired, already used, wrong device, too many attempts or simply unknown must
// not be distinguishable.
var errChallengeInvalid = errors.New("invalid or expired second-factor challenge")

func hashChallenge(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// startChallenge mints the opaque secret handed to the client. Only its digest
// is stored, so a database leak cannot be replayed as a login.
func (s *Server) startChallenge(ctx context.Context, orgID, userID uint, deviceID, uuid string) (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	secret := base64.RawURLEncoding.EncodeToString(buf)
	now := s.deps.Now()
	row := model.CompatLoginChallenge{
		UserID:         userID,
		OrganizationID: orgID,
		DeviceID:       deviceID,
		UUID:           uuid,
		SecretHash:     hashChallenge(secret),
		ExpiresAt:      now.Add(compatChallengeTTL),
		CreatedAt:      now,
	}
	if err := store.WithoutTenantScope(s.deps.DB.WithContext(ctx)).Create(&row).Error; err != nil {
		return "", err
	}
	return secret, nil
}

// loadChallenge validates everything except the code itself. Device identity is
// compared in constant time: a challenge minted for one machine must not be
// usable from another.
func (s *Server) loadChallenge(ctx context.Context, secret, deviceID, uuid string) (*model.CompatLoginChallenge, error) {
	if secret == "" {
		return nil, errChallengeInvalid
	}
	var row model.CompatLoginChallenge
	err := store.WithoutTenantScope(s.deps.DB.WithContext(ctx)).
		Where("secret_hash = ?", hashChallenge(secret)).First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, errChallengeInvalid
	}
	if err != nil {
		return nil, err
	}
	if row.UsedAt != nil || !row.ExpiresAt.After(s.deps.Now()) || row.Attempts >= compatChallengeAttempts {
		return nil, errChallengeInvalid
	}
	if subtle.ConstantTimeCompare([]byte(row.DeviceID), []byte(deviceID)) != 1 ||
		subtle.ConstantTimeCompare([]byte(row.UUID), []byte(uuid)) != 1 {
		return nil, errChallengeInvalid
	}
	return &row, nil
}

// failChallenge counts one wrong code. The attempt counter is the only brake on
// guessing six digits inside one challenge's lifetime.
func (s *Server) failChallenge(ctx context.Context, id uint) error {
	return store.WithoutTenantScope(s.deps.DB.WithContext(ctx)).
		Model(&model.CompatLoginChallenge{}).
		Where("id = ?", id).
		UpdateColumn("attempts", gorm.Expr("attempts + 1")).Error
}

// consumeChallenge marks the challenge used. A false result means a concurrent
// request consumed it first; only one of them may mint a token.
func (s *Server) consumeChallenge(ctx context.Context, id uint) (bool, error) {
	res := store.WithoutTenantScope(s.deps.DB.WithContext(ctx)).
		Model(&model.CompatLoginChallenge{}).
		Where("id = ? AND used_at IS NULL", id).
		Update("used_at", s.deps.Now())
	return res.RowsAffected == 1, res.Error
}
