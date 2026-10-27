package model

import "time"

// Identity providers. Stored in UserIdentity.Provider; the same column will
// carry "ldap" in the next wave, so the two strings must stay distinct.
const (
	IdentityProviderOIDC = "oidc"
	IdentityProviderLDAP = "ldap"
)

// UserIdentity binds a panel account to an external identity. Issuer is part
// of both unique keys: the same subject string means different people under
// different issuers, so leaving it out would let a new IdP capture an old
// account (design O11).
type UserIdentity struct {
	ID       uint   `gorm:"primaryKey"`
	UserID   uint   `gorm:"not null;uniqueIndex:idx_identity_user_provider_issuer"`
	Provider string `gorm:"size:16;not null;uniqueIndex:idx_identity_user_provider_issuer;uniqueIndex:idx_identity_provider_issuer_subject"`
	Issuer   string `gorm:"size:255;not null;default:'';uniqueIndex:idx_identity_user_provider_issuer;uniqueIndex:idx_identity_provider_issuer_subject"`
	Subject  string `gorm:"size:255;not null;uniqueIndex:idx_identity_provider_issuer_subject"`
	// Email mirrors the IdP's claim at binding time; it is not the account's
	// mailbox of record (users.email is).
	Email string `gorm:"size:255;not null"`
	// ConflictAt marks a binding that no longer matches the account's mailbox
	// (the IdP recycled or changed the address). SSO refuses such a binding
	// until an administrator resets it, so the flag is what tells the operator
	// which row is broken (design O4).
	ConflictAt  *time.Time
	LinkedAt    time.Time
	LastLoginAt *time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// TableName pins the name the runbooks and SQL snippets use.
func (UserIdentity) TableName() string { return "user_identities" }

// ExternalLoginFlow carries one authorization-code flow from start to ticket
// exchange. State and ticket are consumed at different moments, so each has its
// own consumption marker and deadline; a single ConsumedAt could not express
// both and would let a ticket be replayed after the callback used the state.
type ExternalLoginFlow struct {
	ID               uint   `gorm:"primaryKey"`
	State            string `gorm:"size:64;not null;uniqueIndex"`
	Provider         string `gorm:"size:16;not null"`
	Nonce            string `gorm:"size:64;not null"`
	PKCEVerifier     string `gorm:"size:128;not null"`
	RedirectPath     string `gorm:"size:256;not null;default:'/'"`
	UserID           *uint  `gorm:"index"`
	TicketHash       string `gorm:"size:64;index"`
	TicketExpiresAt  *time.Time
	TicketConsumedAt *time.Time
	ExpiresAt        time.Time `gorm:"index;not null"`
	ConsumedAt       *time.Time
	CreatedAt        time.Time
}

// TableName pins the name the runbooks and SQL snippets use.
func (ExternalLoginFlow) TableName() string { return "external_login_flows" }
