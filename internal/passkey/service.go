// Package passkey owns WebAuthn (passkey) registration, login and step-up
// ceremonies plus the credential records they create.
package passkey

import (
	"errors"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/auth"
)

// Config is the relying-party identity the service validates ceremonies
// against. Origin is a single browser origin; the panel is served from one.
type Config struct {
	RPID               string
	RPDisplayName      string
	Origin             string
	CeremonyTTL        time.Duration
	CredentialsPerUser int
}

// Sentinel errors. The HTTP layer maps all of them onto a small, stable set of
// status codes; none of them carries user-supplied text.
var (
	ErrCeremonyNotFound = errors.New("webauthn ceremony not found")
	ErrCeremonyExpired  = errors.New("webauthn ceremony expired")
	ErrCeremonyUsed     = errors.New("webauthn ceremony already used")
	ErrStepupUsed       = errors.New("stepup token already used")

	ErrCredentialExists = errors.New("credential already registered")
	ErrTooManyPasskeys  = errors.New("too many passkeys for this account")
	ErrPasskeyNotFound  = errors.New("passkey not found")
	ErrInvalidName      = errors.New("passkey name must be 1-64 characters")
	ErrLastCredential   = errors.New("cannot delete the last credential of a passwordless account")

	ErrNoCredentials   = errors.New("account has no passkey")
	ErrAssertionFailed = errors.New("passkey assertion failed")
	ErrCloneWarning    = errors.New("authenticator signature counter regressed")
)

// Service runs ceremonies against the database.
type Service struct {
	db     *gorm.DB
	now    func() time.Time
	cfg    Config
	issuer *auth.Issuer
	wa     *webauthn.WebAuthn
}

// NewService builds the relying party and returns the service.
func NewService(db *gorm.DB, cfg Config, issuer *auth.Issuer, now func() time.Time) (*Service, error) {
	if now == nil {
		now = time.Now
	}
	wa, err := webauthn.New(&webauthn.Config{
		RPID:          cfg.RPID,
		RPDisplayName: cfg.RPDisplayName,
		RPOrigins:     []string{cfg.Origin},
	})
	if err != nil {
		return nil, err
	}
	return &Service{db: db, now: now, cfg: cfg, issuer: issuer, wa: wa}, nil
}
