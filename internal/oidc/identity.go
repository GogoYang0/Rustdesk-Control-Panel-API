package oidc

import (
	"context"
	"errors"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/auth"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
)

// identityClaims is the subset of the ID token that decides which panel account
// the login belongs to.
type identityClaims struct {
	Issuer        string
	Subject       string
	Email         string
	EmailVerified bool
}

// normalizeEmailVerified accepts the shapes real providers emit: a JSON boolean,
// the string "true", or nothing at all. Anything else is false — a claim we
// cannot read is not evidence that the mailbox was verified (S3).
func normalizeEmailVerified(raw any) bool {
	switch v := raw.(type) {
	case bool:
		return v
	case string:
		return strings.EqualFold(strings.TrimSpace(v), "true")
	default:
		return false
	}
}

// resolveIdentity maps a verified ID token onto a panel account, binding on the
// first login and refusing anything ambiguous.
func (s *Service) resolveIdentity(ctx context.Context, c identityClaims) (model.User, error) {
	now := s.cfg.Now()

	var identity model.UserIdentity
	err := s.db.WithContext(ctx).
		Where("provider = ? AND issuer = ? AND subject = ?", model.IdentityProviderOIDC, c.Issuer, c.Subject).
		First(&identity).Error
	switch {
	case err == nil:
		return s.loginExistingIdentity(ctx, &identity, c, now)
	case errors.Is(err, gorm.ErrRecordNotFound):
		return s.bindNewIdentity(ctx, c, now)
	default:
		return model.User{}, err
	}
}

// loginExistingIdentity handles the returning user. The binding wins over the
// mailbox, except when the mailbox now belongs to a different panel account —
// that is the recycled-address takeover path (O4).
func (s *Service) loginExistingIdentity(ctx context.Context, identity *model.UserIdentity, c identityClaims, now time.Time) (model.User, error) {
	if identity.ConflictAt != nil {
		// Already known-broken: SSO stays closed until an administrator resets.
		return model.User{}, ErrIdentityConflict
	}

	var user model.User
	if err := s.db.WithContext(ctx).Where("id = ?", identity.UserID).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return model.User{}, ErrNoAccount
		}
		return model.User{}, err
	}

	if email := strings.ToLower(strings.TrimSpace(c.Email)); email != "" {
		var other model.User
		err := s.db.WithContext(ctx).Where("LOWER(email) = ?", email).First(&other).Error
		switch {
		case err == nil && other.ID != identity.UserID:
			if markErr := s.markConflict(ctx, identity.ID, now); markErr != nil {
				return model.User{}, markErr
			}
			return model.User{}, ErrIdentityConflict
		case err != nil && !errors.Is(err, gorm.ErrRecordNotFound):
			return model.User{}, err
		}
	}

	if !user.EmailVerified {
		return model.User{}, ErrEmailUnverified
	}
	if err := s.db.WithContext(ctx).Model(&model.UserIdentity{}).
		Where("id = ?", identity.ID).Update("last_login_at", now).Error; err != nil {
		return model.User{}, err
	}
	return user, nil
}

// bindNewIdentity handles the first login: the mailbox must be verified and must
// already belong to a panel account (no just-in-time provisioning, O2).
func (s *Service) bindNewIdentity(ctx context.Context, c identityClaims, now time.Time) (model.User, error) {
	if !c.EmailVerified {
		return model.User{}, ErrEmailUnverified
	}
	email := strings.ToLower(strings.TrimSpace(c.Email))
	if email == "" {
		return model.User{}, ErrEmailUnverified
	}

	var user model.User
	if err := s.db.WithContext(ctx).Where("LOWER(email) = ?", email).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return model.User{}, ErrNoAccount
		}
		return model.User{}, err
	}
	if !user.EmailVerified {
		return model.User{}, ErrEmailUnverified
	}

	var existing model.UserIdentity
	err := s.db.WithContext(ctx).
		Where("user_id = ? AND provider = ? AND issuer = ? AND subject <> ?", user.ID, model.IdentityProviderOIDC, c.Issuer, c.Subject).
		First(&existing).Error
	switch {
	case err == nil:
		// The account is bound to a different subject under this issuer: a
		// second human is claiming an account that is already linked.
		return model.User{}, ErrIdentityConflict
	case !errors.Is(err, gorm.ErrRecordNotFound):
		return model.User{}, err
	}

	row := model.UserIdentity{
		UserID:      user.ID,
		Provider:    model.IdentityProviderOIDC,
		Issuer:      c.Issuer,
		Subject:     c.Subject,
		Email:       email,
		LinkedAt:    now,
		LastLoginAt: &now,
	}
	if err := s.db.WithContext(ctx).Create(&row).Error; err != nil {
		// A concurrent first login may have won the unique key. Accept that only
		// when it bound the same account; anything else is a conflict.
		var winner model.UserIdentity
		if rerr := s.db.WithContext(ctx).
			Where("provider = ? AND issuer = ? AND subject = ?", model.IdentityProviderOIDC, c.Issuer, c.Subject).
			First(&winner).Error; rerr == nil && winner.UserID == user.ID {
			return user, nil
		}
		return model.User{}, ErrIdentityConflict
	}
	return user, nil
}

func (s *Service) markConflict(ctx context.Context, identityID uint, now time.Time) error {
	return s.db.WithContext(ctx).Model(&model.UserIdentity{}).
		Where("id = ?", identityID).Update("conflict_at", now).Error
}

// ListIdentities returns the caller's external bindings, newest first.
func (s *Service) ListIdentities(ctx context.Context, userID uint) ([]model.UserIdentity, error) {
	var rows []model.UserIdentity
	if err := s.db.WithContext(ctx).
		Where("user_id = ?", userID).Order("id DESC").Find(&rows).Error; err != nil {
		return nil, err
	}
	return rows, nil
}

// Unlink removes one of the caller's bindings. It refuses the unlink that would
// leave the account with no way to sign in: without a password, without
// passkeys and without another identity there is no self-service recovery
// (design §6, endpoint 6).
//
// The whole decision runs in one transaction, and the account row is locked
// first (SELECT ... FOR UPDATE on dialects that support it): two concurrent
// unlinks of a passwordless account's last two credentials therefore serialize
// instead of both passing a stale count. The lock also keeps the count out of
// the DELETE statement — MySQL rejects a same-table subquery there outright
// (ER_UPDATE_TABLE_USED), which is exactly the dialect-only failure the
// handover warns about.
func (s *Service) Unlink(ctx context.Context, userID, identityID uint) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		read := tx
		if tx.Name() != "sqlite" {
			read = read.Clauses(clause.Locking{Strength: "UPDATE"})
		}

		var user model.User
		if err := read.Where("id = ?", userID).First(&user).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrIdentityNotFound
			}
			return err
		}

		var identity model.UserIdentity
		if err := read.Where("id = ? AND user_id = ?", identityID, userID).First(&identity).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrIdentityNotFound
			}
			return err
		}

		if !auth.HasPassword(user) {
			// The password cannot vouch for this account; only a passkey or a
			// second binding can remain afterwards.
			var passkeys, others int64
			if err := tx.Model(&model.UserPasskey{}).Where("user_id = ?", userID).Count(&passkeys).Error; err != nil {
				return err
			}
			if err := tx.Model(&model.UserIdentity{}).
				Where("user_id = ? AND id <> ?", userID, identityID).Count(&others).Error; err != nil {
				return err
			}
			if passkeys == 0 && others == 0 {
				return ErrLastCredential
			}
		}

		return tx.Where("id = ? AND user_id = ?", identityID, userID).Delete(&model.UserIdentity{}).Error
	})
}

// StaleIssuerCount reports how many identities are bound under an issuer other
// than the configured one. A deployment that switched IdP keeps the old rows:
// they simply never match again, and this count is what the startup warning
// shows the operator (design O11).
func (s *Service) StaleIssuerCount(ctx context.Context) (int64, error) {
	var count int64
	err := s.db.WithContext(ctx).Model(&model.UserIdentity{}).
		Where("provider = ? AND issuer <> ?", model.IdentityProviderOIDC, s.cfg.Issuer).
		Count(&count).Error
	return count, err
}
