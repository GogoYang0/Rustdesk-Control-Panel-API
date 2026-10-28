package passkey

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
)

// stepupTTL is deliberately short: the token authorizes one sensitive action
// right after the user proved presence.
const stepupTTL = 2 * time.Minute

// ErrStepupInvalid covers a malformed, expired or wrong-user step-up token.
// The HTTP layer maps it (and ErrStepupUsed) onto 401.
var ErrStepupInvalid = errors.New("stepup token invalid")

// BeginStepup starts an assertion ceremony used to authorize a sensitive
// action (removing or restoring the local password).
func (s *Service) BeginStepup(ctx context.Context, u model.User) (string, *protocol.CredentialAssertion, error) {
	rows, err := s.credentials(ctx, u.ID)
	if err != nil {
		return "", nil, err
	}
	if len(rows) == 0 {
		return "", nil, ErrNoCredentials
	}
	user, err := s.webauthnUser(u, rows)
	if err != nil {
		return "", nil, err
	}

	options, session, err := s.wa.BeginLogin(user,
		webauthn.WithAllowedCredentials(credentialDescriptors(user.creds)),
		webauthn.WithUserVerification(protocol.VerificationRequired),
	)
	if err != nil {
		return "", nil, fmt.Errorf("begin stepup: %w", err)
	}
	handle, err := s.beginCeremony(ctx, model.CeremonyStepup, &u.ID, session)
	if err != nil {
		return "", nil, err
	}
	return handle, options, nil
}

// FinishStepup validates the assertion and returns a two-minute token bound to
// this ceremony.
func (s *Service) FinishStepup(ctx context.Context, u model.User, token string, body []byte) (string, error) {
	parsed, err := protocol.ParseCredentialRequestResponseBytes(body)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrAssertionFailed, err)
	}
	ceremony, session, err := s.consumeCeremony(ctx, token, model.CeremonyStepup)
	if err != nil {
		return "", err
	}
	if ceremony.UserID == nil || *ceremony.UserID != u.ID {
		return "", ErrCeremonyNotFound
	}

	rows, err := s.credentials(ctx, u.ID)
	if err != nil {
		return "", err
	}
	user, err := s.webauthnUser(u, rows)
	if err != nil {
		return "", err
	}
	cred, err := s.wa.ValidateLogin(user, session, parsed)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrAssertionFailed, err)
	}
	row, err := s.passkeyByCredentialID(ctx, cred.ID)
	if err != nil {
		return "", err
	}
	if row.UserID != u.ID {
		return "", ErrAssertionFailed
	}
	if cred.Authenticator.CloneWarning {
		if err := s.db.WithContext(ctx).Model(&model.UserPasskey{}).
			Where("id = ?", row.ID).Update("clone_warning", true).Error; err != nil {
			return "", err
		}
		return "", ErrCloneWarning
	}
	now := s.now()
	if err := s.db.WithContext(ctx).Model(&model.UserPasskey{}).
		Where("id = ?", row.ID).
		Updates(map[string]any{"sign_count": cred.Authenticator.SignCount, "last_used_at": now}).Error; err != nil {
		return "", err
	}

	return s.issuer.IssueStepup(u.ID, ceremony.Handle, stepupTTL)
}

// VerifyStepup checks a step-up token for this user and burns it. A token can
// authorize exactly one action.
func (s *Service) VerifyStepup(ctx context.Context, userID uint, token string) error {
	uid, handle, err := s.issuer.ParseStepup(token)
	if err != nil || uid != userID {
		return ErrStepupInvalid
	}
	if err := s.consumeStepup(ctx, handle); err != nil {
		if errors.Is(err, ErrStepupUsed) {
			return ErrStepupUsed
		}
		return ErrStepupInvalid
	}
	return nil
}
