package model

import "time"

// Address book grant subject kinds and access levels.
const (
	GrantSubjectUser     = "user"
	GrantSubjectEveryone = "everyone"

	GrantAccessRead  = "read"
	GrantAccessWrite = "write"
	GrantAccessFull  = "full"
)

// AddressBookGrant grants one subject access to one shared address book.
//
// SubjectUserID is 0 for the everyone grant. Using a sentinel instead of a
// nullable column keeps the (book, kind, user) uniqueness constraint valid on
// all three dialects: SQLite, MySQL and PostgreSQL all treat NULLs as distinct
// in unique indexes, so a NULL subject would allow duplicate everyone rows.
type AddressBookGrant struct {
	ID             uint      `gorm:"primaryKey" json:"id"`
	OrganizationID uint      `gorm:"index;not null" json:"organization_id"`
	BookID         uint      `gorm:"not null;uniqueIndex:idx_abg_book_subject,priority:1" json:"book_id"`
	SubjectKind    string    `gorm:"size:16;not null;uniqueIndex:idx_abg_book_subject,priority:2" json:"subject_kind"`
	SubjectUserID  uint      `gorm:"not null;default:0;uniqueIndex:idx_abg_book_subject,priority:3" json:"subject_user_id"`
	Access         string    `gorm:"size:16;not null" json:"access"`
	CreatedBy      uint      `gorm:"not null;default:0" json:"created_by"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}
