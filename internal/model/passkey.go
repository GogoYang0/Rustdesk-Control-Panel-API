package model

import "time"

// CeremonyPurpose names the three WebAuthn ceremonies. They are distinct
// constants on purpose: a ceremony begun for registration must never be
// consumed by a login.
type CeremonyPurpose string

const (
	CeremonyRegister CeremonyPurpose = "register"
	CeremonyLogin    CeremonyPurpose = "login"
	CeremonyStepup   CeremonyPurpose = "stepup"
)

// UserPasskey is one registered WebAuthn credential.
//
// Binary values are stored as text because this schema must behave identically
// on SQLite, PostgreSQL and MySQL without driver-specific column types:
// CredentialID is base64url, PublicKey is standard base64. Uniqueness rides on
// CredentialIDHash (SHA-256 hex) so the unique index stays a fixed 64 chars on
// every dialect.
type UserPasskey struct {
	ID               uint       `gorm:"primaryKey" json:"id"`
	UserID           uint       `gorm:"index;not null" json:"user_id"`
	CredentialID     string     `gorm:"type:text;not null" json:"-"`
	CredentialIDHash string     `gorm:"size:64;not null;uniqueIndex" json:"-"`
	PublicKey        string     `gorm:"type:text;not null" json:"-"`
	SignCount        uint32     `gorm:"not null;default:0" json:"-"`
	AAGUID           string     `gorm:"size:36;not null;default:''" json:"aaguid"`
	Transports       string     `gorm:"type:text;not null;default:'[]'" json:"-"`
	Name             string     `gorm:"size:64;not null" json:"name"`
	BackupEligible   bool       `gorm:"not null;default:false" json:"backup_eligible"`
	BackupState      bool       `gorm:"not null;default:false" json:"backup_state"`
	CloneWarning     bool       `gorm:"not null;default:false" json:"clone_warning"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
	LastUsedAt       *time.Time `json:"last_used_at"`
}

// WebAuthnCeremony stores the server side of one begin/finish pair. SessionJSON
// is the library's SessionData verbatim; it carries the challenge, so the row
// is single-use and short lived.
type WebAuthnCeremony struct {
	ID           uint            `gorm:"primaryKey"`
	Handle       string          `gorm:"size:64;not null;uniqueIndex"`
	Purpose      CeremonyPurpose `gorm:"size:16;not null"`
	UserID       *uint           `gorm:"index"`
	SessionJSON  string          `gorm:"type:text;not null"`
	ExpiresAt    time.Time       `gorm:"index;not null"`
	ConsumedAt   *time.Time
	StepupUsedAt *time.Time
	CreatedAt    time.Time
}

// TableName pins the names the docs and operations runbooks use; GORM's
// default pluralizer would render WebAuthnCeremony as web_authn_ceremonies.
func (UserPasskey) TableName() string { return "user_passkeys" }

func (WebAuthnCeremony) TableName() string { return "webauthn_ceremonies" }
