package passkey

import (
	"context"
	"errors"
	"fmt"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
)

// BeginLogin starts an assertion ceremony. A nil user starts a discoverable
// (usernameless) ceremony: the authenticator picks the credential and returns
// the user handle on finish.
func (s *Service) BeginLogin(ctx context.Context, u *model.User) (string, *protocol.CredentialAssertion, error) {
	var (
		options *protocol.CredentialAssertion
		session *webauthn.SessionData
		err     error
	)

	if u == nil {
		options, session, err = s.wa.BeginDiscoverableLogin(
			webauthn.WithUserVerification(protocol.VerificationRequired),
		)
	} else {
		rows, listErr := s.credentials(ctx, u.ID)
		if listErr != nil {
			return "", nil, listErr
		}
		if len(rows) == 0 {
			return "", nil, ErrNoCredentials
		}
		user, decodeErr := s.webauthnUser(*u, rows)
		if decodeErr != nil {
			return "", nil, decodeErr
		}
		options, session, err = s.wa.BeginLogin(user,
			webauthn.WithAllowedCredentials(credentialDescriptors(user.creds)),
			webauthn.WithUserVerification(protocol.VerificationRequired),
		)
	}
	if err != nil {
		return "", nil, fmt.Errorf("begin login: %w", err)
	}

	var userID *uint
	if u != nil {
		userID = &u.ID
	}
	handle, err := s.beginCeremony(ctx, model.CeremonyLogin, userID, session)
	if err != nil {
		return "", nil, err
	}
	return handle, options, nil
}

// FinishLogin validates the assertion, applies the signature counter rules and
// returns the authenticated account with the credential that was used.
func (s *Service) FinishLogin(ctx context.Context, token string, body []byte) (model.User, *model.UserPasskey, error) {
	parsed, err := protocol.ParseCredentialRequestResponseBytes(body)
	if err != nil {
		return model.User{}, nil, fmt.Errorf("%w: %v", ErrAssertionFailed, err)
	}

	ceremony, session, err := s.consumeCeremony(ctx, token, model.CeremonyLogin)
	if err != nil {
		return model.User{}, nil, err
	}

	var (
		user model.User
		cred *webauthn.Credential
	)

	if ceremony.UserID != nil {
		user, err = s.loadUser(ctx, *ceremony.UserID)
		if err != nil {
			return model.User{}, nil, fmt.Errorf("%w: ceremony user missing", ErrAssertionFailed)
		}
		rows, listErr := s.credentials(ctx, user.ID)
		if listErr != nil {
			return model.User{}, nil, listErr
		}
		wu, decodeErr := s.webauthnUser(user, rows)
		if decodeErr != nil {
			return model.User{}, nil, decodeErr
		}
		if cred, err = s.wa.ValidateLogin(wu, session, parsed); err != nil {
			return model.User{}, nil, fmt.Errorf("%w: %v", ErrAssertionFailed, err)
		}
	} else {
		handler := func(rawID, handle []byte) (webauthn.User, error) {
			uid, ok := userIDFromHandle(handle)
			if !ok {
				return nil, errors.New("unknown user handle")
			}
			u, loadErr := s.loadUser(ctx, uid)
			if loadErr != nil {
				return nil, loadErr
			}
			rows, listErr := s.credentials(ctx, uid)
			if listErr != nil {
				return nil, listErr
			}
			return s.webauthnUser(u, rows)
		}
		discovered, discoveredCred, validateErr := s.wa.ValidatePasskeyLogin(handler, session, parsed)
		if validateErr != nil {
			return model.User{}, nil, fmt.Errorf("%w: %v", ErrAssertionFailed, validateErr)
		}
		uid, ok := userIDFromHandle(discovered.WebAuthnID())
		if !ok {
			return model.User{}, nil, ErrAssertionFailed
		}
		if user, err = s.loadUser(ctx, uid); err != nil {
			return model.User{}, nil, fmt.Errorf("%w: ceremony user missing", ErrAssertionFailed)
		}
		cred = discoveredCred
	}

	row, err := s.passkeyByCredentialID(ctx, cred.ID)
	if err != nil {
		return model.User{}, nil, err
	}
	if row.UserID != user.ID {
		return model.User{}, nil, ErrAssertionFailed
	}

	if cred.Authenticator.CloneWarning {
		if err := s.db.WithContext(ctx).Model(&model.UserPasskey{}).
			Where("id = ?", row.ID).Update("clone_warning", true).Error; err != nil {
			return model.User{}, nil, err
		}
		row.CloneWarning = true
		return user, &row, ErrCloneWarning
	}

	now := s.now()
	if err := s.db.WithContext(ctx).Model(&model.UserPasskey{}).
		Where("id = ?", row.ID).
		Updates(map[string]any{"sign_count": cred.Authenticator.SignCount, "last_used_at": now}).Error; err != nil {
		return model.User{}, nil, err
	}
	row.SignCount = cred.Authenticator.SignCount
	row.LastUsedAt = &now
	return user, &row, nil
}

func (s *Service) loadUser(ctx context.Context, id uint) (model.User, error) {
	var user model.User
	if err := s.db.WithContext(ctx).Where("id = ?", id).First(&user).Error; err != nil {
		return model.User{}, err
	}
	return user, nil
}

// passkeyByCredentialID looks a credential up by its hash index and verifies
// the raw id, so a hash collision cannot authenticate the wrong credential.
func (s *Service) passkeyByCredentialID(ctx context.Context, rawID []byte) (model.UserPasskey, error) {
	var row model.UserPasskey
	err := s.db.WithContext(ctx).Where("credential_id_hash = ?", credentialHash(rawID)).First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return row, ErrAssertionFailed
	}
	if err != nil {
		return row, err
	}
	if row.CredentialID != encodeCredentialID(rawID) {
		return row, ErrAssertionFailed
	}
	return row, nil
}
