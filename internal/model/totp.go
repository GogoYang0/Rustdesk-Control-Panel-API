package model

import "time"

// UserTOTP holds one user's TOTP second-factor configuration.
//
// The secret is stored encrypted (AES-256-GCM, key derived from the auth
// secret by the auth service). RecoveryCodes is a JSON array of Argon2id
// hashes with a used flag; plaintext codes are never stored. LastStep prevents
// replaying a TOTP code within its validity window.
type UserTOTP struct {
	UserID           uint       `gorm:"primaryKey;autoIncrement:false" json:"user_id"`
	SecretCiphertext string     `gorm:"type:text;not null" json:"-"`
	EnabledAt        *time.Time `json:"enabled_at"`
	RecoveryCodes    string     `gorm:"type:text;not null" json:"-"`
	LastStep         int64      `gorm:"not null;default:0" json:"-"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

// RecoveryCode is one stored recovery-code hash.
type RecoveryCode struct {
	Hash string `json:"hash"`
	Used bool   `json:"used"`
}
