package model

import (
	"errors"
	"time"
)

// Address book scopes.
const (
	AddressBookScopePersonal = "personal"
	AddressBookScopeShared   = "shared"
)

// ErrAddressBookScopeInvalid signals an unknown scope value.
var ErrAddressBookScopeInvalid = errors.New("address book scope must be personal or shared")

// AddressBook groups peers for one user (personal) or a whole organization
// (shared). Scope is immutable after creation: personal books carry an
// owner_id while shared books are org-wide, so converting between them
// changes ownership semantics (M2 plan, task 4).
type AddressBook struct {
	ID             uint      `gorm:"primaryKey" json:"id"`
	OrganizationID uint      `gorm:"index;not null;uniqueIndex:idx_ab_org_owner_name" json:"organization_id"`
	OwnerID        *uint     `gorm:"index;uniqueIndex:idx_ab_org_owner_name" json:"owner_id"`
	Scope          string    `gorm:"size:16;not null" json:"scope"`
	Name           string    `gorm:"size:128;not null;uniqueIndex:idx_ab_org_owner_name" json:"name"`
	Revision       uint64    `gorm:"not null;default:0" json:"revision"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// Valid reports whether the scope value is one of the supported constants.
func (b *AddressBook) Valid() error {
	if b.Scope != AddressBookScopePersonal && b.Scope != AddressBookScopeShared {
		return ErrAddressBookScopeInvalid
	}
	return nil
}

// AddressBookPeer is one RustDesk device entry inside an address book. Tags
// are stored as a JSON array of tag names referencing AddressBookTag rows of
// the same book. Hash (unattended-access password hash) and Note are round-
// tripped for the client compat layer (task 9): the personal book carries
// them opaquely, the management contract does not expose them.
type AddressBookPeer struct {
	ID             uint      `gorm:"primaryKey" json:"id"`
	OrganizationID uint      `gorm:"index;not null" json:"organization_id"`
	BookID         uint      `gorm:"index;not null;uniqueIndex:idx_abp_book_peer" json:"book_id"`
	PeerID         string    `gorm:"size:64;not null;uniqueIndex:idx_abp_book_peer" json:"peer_id"`
	Alias          string    `gorm:"size:128" json:"alias"`
	Username       string    `gorm:"size:128" json:"username"`
	Hostname       string    `gorm:"size:128" json:"hostname"`
	Platform       string    `gorm:"size:64" json:"platform"`
	TagsJSON       string    `gorm:"size:2048" json:"tags_json"`
	Hash           string    `gorm:"size:128" json:"-"`
	Note           string    `gorm:"size:512" json:"-"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// AddressBookTag is a named color label scoped to one book. The (book_id,
// name) pair is unique so clients can address tags unambiguously.
type AddressBookTag struct {
	ID             uint      `gorm:"primaryKey" json:"id"`
	OrganizationID uint      `gorm:"index;not null" json:"organization_id"`
	BookID         uint      `gorm:"index;not null;uniqueIndex:idx_abt_book_name" json:"book_id"`
	Name           string    `gorm:"size:64;not null;uniqueIndex:idx_abt_book_name" json:"name"`
	Color          uint32    `gorm:"not null;default:0" json:"color"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// SyncCursor remembers how far a user has synced a book (compat API
// incremental sync, task 9).
type SyncCursor struct {
	ID             uint      `gorm:"primaryKey" json:"id"`
	OrganizationID uint      `gorm:"index;not null" json:"organization_id"`
	UserID         uint      `gorm:"not null;uniqueIndex:idx_sc_user_book" json:"user_id"`
	BookID         uint      `gorm:"not null;uniqueIndex:idx_sc_user_book" json:"book_id"`
	LastRevision   uint64    `gorm:"not null;default:0" json:"last_revision"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}
