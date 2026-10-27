package passkey

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
)

const (
	defaultPasskeyName = "Passkey"
	maxPasskeyNameLen  = 64
)

// webAuthnUser adapts a panel user plus its stored credentials to the library's
// User interface. The credentials are what makes signature verification
// possible, so they travel with the user everywhere.
type webAuthnUser struct {
	id    []byte
	name  string
	creds []webauthn.Credential
}

func (u webAuthnUser) WebAuthnID() []byte                         { return u.id }
func (u webAuthnUser) WebAuthnName() string                       { return u.name }
func (u webAuthnUser) WebAuthnDisplayName() string                { return u.name }
func (u webAuthnUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

// userHandle is the opaque handle a discoverable credential returns on login.
// It is the user id in big endian, which the login handler maps back to a row.
func userHandle(id uint) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(id))
	return buf
}

func userIDFromHandle(handle []byte) (uint, bool) {
	if len(handle) != 8 {
		return 0, false
	}
	return uint(binary.BigEndian.Uint64(handle)), true
}

// credentials lists a user's passkeys. Unscoped on purpose: passkeys carry no
// organization column, they belong to the account.
func (s *Service) credentials(ctx context.Context, userID uint) ([]model.UserPasskey, error) {
	var rows []model.UserPasskey
	if err := s.db.WithContext(ctx).Where("user_id = ?", userID).Order("id").Find(&rows).Error; err != nil {
		return nil, err
	}
	return rows, nil
}

// webauthnUser decodes stored credentials into the library's representation.
// A row that cannot be decoded is an error, not a silent skip: skipping would
// turn a corrupt credential into "credential not found" and let a caller think
// the account has none.
func (s *Service) webauthnUser(u model.User, rows []model.UserPasskey) (webAuthnUser, error) {
	creds := make([]webauthn.Credential, 0, len(rows))
	for _, row := range rows {
		cred, err := decodeCredential(row)
		if err != nil {
			return webAuthnUser{}, err
		}
		creds = append(creds, cred)
	}
	return webAuthnUser{id: userHandle(u.ID), name: u.Email, creds: creds}, nil
}

func decodeCredential(row model.UserPasskey) (webauthn.Credential, error) {
	id, err := base64.RawURLEncoding.DecodeString(row.CredentialID)
	if err != nil {
		return webauthn.Credential{}, fmt.Errorf("decode credential id %d: %w", row.ID, err)
	}
	publicKey, err := base64.StdEncoding.DecodeString(row.PublicKey)
	if err != nil {
		return webauthn.Credential{}, fmt.Errorf("decode credential key %d: %w", row.ID, err)
	}
	var transports []protocol.AuthenticatorTransport
	if row.Transports != "" {
		if err := json.Unmarshal([]byte(row.Transports), &transports); err != nil {
			return webauthn.Credential{}, fmt.Errorf("decode credential transports %d: %w", row.ID, err)
		}
	}
	return webauthn.Credential{
		ID:        id,
		PublicKey: publicKey,
		Transport: transports,
		Flags: webauthn.CredentialFlags{
			UserPresent:    true,
			UserVerified:   true,
			BackupEligible: row.BackupEligible,
			BackupState:    row.BackupState,
		},
		Authenticator: webauthn.Authenticator{
			SignCount:    row.SignCount,
			CloneWarning: row.CloneWarning,
		},
	}, nil
}

// BeginRegistration starts a ceremony that excludes credentials the account
// already holds, so an authenticator cannot silently re-register.
func (s *Service) BeginRegistration(ctx context.Context, u model.User) (string, *protocol.CredentialCreation, error) {
	rows, err := s.credentials(ctx, u.ID)
	if err != nil {
		return "", nil, err
	}
	if len(rows) >= s.cfg.CredentialsPerUser {
		return "", nil, ErrTooManyPasskeys
	}
	user, err := s.webauthnUser(u, rows)
	if err != nil {
		return "", nil, err
	}

	options, session, err := s.wa.BeginRegistration(user,
		webauthn.WithExclusions(credentialDescriptors(user.creds)),
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementPreferred),
		webauthn.WithConveyancePreference(protocol.PreferNoAttestation),
	)
	if err != nil {
		return "", nil, fmt.Errorf("begin registration: %w", err)
	}
	handle, err := s.beginCeremony(ctx, model.CeremonyRegister, &u.ID, session)
	if err != nil {
		return "", nil, err
	}
	return handle, options, nil
}

// FinishRegistration consumes the ceremony and stores the credential. The
// response body is the browser's PublicKeyCredential JSON.
func (s *Service) FinishRegistration(ctx context.Context, u model.User, token string, body []byte, name string) (*model.UserPasskey, error) {
	parsed, err := protocol.ParseCredentialCreationResponseBytes(body)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAssertionFailed, err)
	}

	ceremony, session, err := s.consumeCeremony(ctx, token, model.CeremonyRegister)
	if err != nil {
		return nil, err
	}
	if ceremony.UserID == nil || *ceremony.UserID != u.ID {
		return nil, ErrCeremonyNotFound
	}

	rows, err := s.credentials(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	user, err := s.webauthnUser(u, rows)
	if err != nil {
		return nil, err
	}
	cred, err := s.wa.CreateCredential(user, session, parsed)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAssertionFailed, err)
	}

	normalized, err := normalizePasskeyName(name)
	if err != nil {
		return nil, err
	}
	return s.insertPasskey(ctx, u.ID, normalized, cred)
}

func (s *Service) insertPasskey(ctx context.Context, userID uint, name string, cred *webauthn.Credential) (*model.UserPasskey, error) {
	row := model.UserPasskey{
		UserID:           userID,
		CredentialID:     base64.RawURLEncoding.EncodeToString(cred.ID),
		CredentialIDHash: credentialHash(cred.ID),
		PublicKey:        base64.StdEncoding.EncodeToString(cred.PublicKey),
		SignCount:        cred.Authenticator.SignCount,
		AAGUID:           formatAAGUID(cred.Authenticator.AAGUID),
		Transports:       encodeTransports(cred.Transport),
		Name:             name,
		BackupEligible:   cred.Flags.BackupEligible,
		BackupState:      cred.Flags.BackupState,
		CloneWarning:     cred.Authenticator.CloneWarning,
	}

	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var count int64
		if err := tx.Model(&model.UserPasskey{}).Where("user_id = ?", userID).Count(&count).Error; err != nil {
			return err
		}
		if count >= int64(s.cfg.CredentialsPerUser) {
			return ErrTooManyPasskeys
		}
		return tx.Create(&row).Error
	})
	if errors.Is(err, gorm.ErrDuplicatedKey) {
		return nil, ErrCredentialExists
	}
	if err != nil {
		return nil, err
	}
	return &row, nil
}

func normalizePasskeyName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return defaultPasskeyName, nil
	}
	if len(name) > maxPasskeyNameLen {
		return "", ErrInvalidName
	}
	return name, nil
}

func credentialHash(id []byte) string {
	sum := sha256.Sum256(id)
	return hex.EncodeToString(sum[:])
}

func credentialDescriptors(creds []webauthn.Credential) []protocol.CredentialDescriptor {
	out := make([]protocol.CredentialDescriptor, 0, len(creds))
	for _, cred := range creds {
		out = append(out, protocol.CredentialDescriptor{
			Type:         protocol.PublicKeyCredentialType,
			CredentialID: cred.ID,
			Transport:    cred.Transport,
		})
	}
	return out
}

func formatAAGUID(raw []byte) string {
	if len(raw) != 16 {
		return ""
	}
	return fmt.Sprintf("%x-%x-%x-%x-%x", raw[0:4], raw[4:6], raw[6:8], raw[8:10], raw[10:16])
}

func encodeTransports(transports []protocol.AuthenticatorTransport) string {
	values := make([]string, 0, len(transports))
	for _, t := range transports {
		values = append(values, string(t))
	}
	encoded, err := json.Marshal(values)
	if err != nil {
		return "[]"
	}
	return string(encoded)
}
