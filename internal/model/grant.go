package model

import "time"

// Address book grant subject kinds and access levels.
const (
	GrantSubjectUser      = "user"
	GrantSubjectEveryone  = "everyone"
	GrantSubjectUserGroup = "user_group"

	GrantAccessRead  = "read"
	GrantAccessWrite = "write"
	GrantAccessFull  = "full"
)

// AddressBookGrant grants one subject access to one shared address book.
//
// SubjectUserID is 0 for the everyone and user_group grants; SubjectGroupID is
// 0 for the user and everyone grants. Using sentinels instead of nullable
// columns keeps the (book, kind, user, group) uniqueness constraint valid on
// all three dialects: SQLite, MySQL and PostgreSQL all treat NULLs as distinct
// in unique indexes, so a NULL subject would allow duplicate rows.
type AddressBookGrant struct {
	ID             uint   `gorm:"primaryKey" json:"id"`
	OrganizationID uint   `gorm:"index;not null" json:"organization_id"`
	BookID         uint   `gorm:"not null;uniqueIndex:idx_abg_book_subject,priority:1" json:"book_id"`
	SubjectKind    string `gorm:"size:16;not null;uniqueIndex:idx_abg_book_subject,priority:2" json:"subject_kind"`
	SubjectUserID  uint   `gorm:"not null;default:0;uniqueIndex:idx_abg_book_subject,priority:3" json:"subject_user_id"`
	// SubjectGroupID identifies the user group of a user_group grant. The index
	// carries it as the fourth column, which the pre-upgrade three-column index
	// did not: that shape collapsed every group grant onto SubjectUserID=0 and
	// allowed only one of them per book (see MigrateGrantSubjectIndex).
	SubjectGroupID uint      `gorm:"not null;default:0;uniqueIndex:idx_abg_book_subject,priority:4" json:"subject_group_id"`
	Access         string    `gorm:"size:16;not null" json:"access"`
	CreatedBy      uint      `gorm:"not null;default:0" json:"created_by"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}
