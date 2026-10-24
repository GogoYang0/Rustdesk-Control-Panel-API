package addressbook

import (
	"errors"
	"fmt"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/authz"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// Access is the effective level a user has on one address book.
type Access string

// Access levels, ordered from weak to strong.
const (
	AccessNone  Access = ""
	AccessRead  Access = "read"
	AccessWrite Access = "write"
	AccessFull  Access = "full"
)

// Grant errors mapped to HTTP statuses by the handler.
var (
	// ErrInvalidGrant reports an unknown subject kind or access level.
	ErrInvalidGrant = errors.New("invalid grant: subject_kind must be user or everyone and access must be read, write or full")
	// ErrGrantNotShared reports grant management on a personal book.
	ErrGrantNotShared = errors.New("grants only apply to shared address books")
	// ErrSubjectNotMember reports a user grant for someone outside the tenant.
	ErrSubjectNotMember = errors.New("grant subject is not a member of this organization")
	// ErrGrantNotFound reports a grant id outside this book.
	ErrGrantNotFound = errors.New("grant not found")
)

func accessRank(a Access) int {
	switch a {
	case AccessRead:
		return 1
	case AccessWrite:
		return 2
	case AccessFull:
		return 3
	default:
		return 0
	}
}

// AtLeast reports whether access meets the required level.
func AtLeast(access, required Access) bool {
	return accessRank(access) >= accessRank(required)
}

func accessFromGrant(raw string) Access {
	switch raw {
	case model.GrantAccessRead:
		return AccessRead
	case model.GrantAccessWrite:
		return AccessWrite
	case model.GrantAccessFull:
		return AccessFull
	default:
		return AccessNone
	}
}

// AccessFor resolves the effective access level of one user on one book.
//
// Personal books stay owner-only. Shared books keep the M2 default — every
// member may read — and grants can only raise it, except that an explicit user
// grant takes precedence over the everyone grant (a user-specific read grant
// deliberately caps a broadly granted write/full). The builtin addressbook
// write permission (owner/admin, or a custom role holding it) is always full.
func AccessFor(perms []string, book *model.AddressBook, userID uint, grants []model.AddressBookGrant) Access {
	if book == nil {
		return AccessNone
	}
	if book.Scope == model.AddressBookScopePersonal {
		if book.OwnerID != nil && *book.OwnerID == userID {
			return AccessFull
		}
		return AccessNone
	}
	if authz.Has(perms, authz.PermAddressBook) {
		return AccessFull
	}

	everyone := AccessRead
	for _, g := range grants {
		switch g.SubjectKind {
		case model.GrantSubjectUser:
			if g.SubjectUserID == userID && userID != 0 {
				return accessFromGrant(g.Access)
			}
		case model.GrantSubjectEveryone:
			if level := accessFromGrant(g.Access); accessRank(level) > accessRank(everyone) {
				everyone = level
			}
		}
	}
	return everyone
}

// accessFor loads the grants of a book and resolves the caller's level.
func (s *Service) accessFor(userID, orgID uint, book *model.AddressBook, perms []string) (Access, error) {
	if book.Scope != model.AddressBookScopeShared {
		// Personal books never consult grants: ownership alone decides.
		return AccessFor(perms, book, userID, nil), nil
	}
	grants, err := s.grantsFor(orgID, book.ID)
	if err != nil {
		return AccessNone, err
	}
	return AccessFor(perms, book, userID, grants), nil
}

// grantsFor returns every grant of one book inside the tenant scope.
func (s *Service) grantsFor(orgID, bookID uint) ([]model.AddressBookGrant, error) {
	var grants []model.AddressBookGrant
	if err := store.ScopedByOrg(s.db, orgID).
		Where("book_id = ?", bookID).
		Order("id").
		Find(&grants).Error; err != nil {
		return nil, fmt.Errorf("load address book grants: %w", err)
	}
	return grants, nil
}

// sharedBookForGrants loads the book and requires full access plus the shared
// scope; grant management is meaningless on a personal book.
func (s *Service) sharedBookForGrants(userID, orgID, bookID uint, perms []string) (*model.AddressBook, error) {
	book, err := s.getBook(userID, orgID, bookID)
	if err != nil {
		return nil, err
	}
	if book.Scope != model.AddressBookScopeShared {
		return nil, ErrGrantNotShared
	}
	access, err := s.accessFor(userID, orgID, book, perms)
	if err != nil {
		return nil, err
	}
	if !AtLeast(access, AccessFull) {
		return nil, ErrForbidden
	}
	return book, nil
}

// ListGrants returns the grants of a shared book. Only a full-access caller may
// inspect who else can reach the book.
func (s *Service) ListGrants(userID, orgID, bookID uint, perms []string) ([]model.AddressBookGrant, error) {
	book, err := s.sharedBookForGrants(userID, orgID, bookID, perms)
	if err != nil {
		return nil, err
	}
	return s.grantsFor(orgID, book.ID)
}

// UpsertGrant creates or replaces one subject's grant on a shared book and
// reports whether a new row was inserted. The unique (book, kind, user) index
// makes the upsert atomic on all three dialects.
func (s *Service) UpsertGrant(userID, orgID, bookID, subjectUserID uint, subjectKind, accessLevel string, perms []string) (*model.AddressBookGrant, bool, error) {
	if subjectKind != model.GrantSubjectUser && subjectKind != model.GrantSubjectEveryone {
		return nil, false, ErrInvalidGrant
	}
	if accessLevel != model.GrantAccessRead && accessLevel != model.GrantAccessWrite && accessLevel != model.GrantAccessFull {
		return nil, false, ErrInvalidGrant
	}
	if subjectKind == model.GrantSubjectEveryone {
		subjectUserID = 0
	} else {
		if subjectUserID == 0 {
			return nil, false, ErrInvalidGrant
		}
		var count int64
		if err := store.ScopedByOrg(s.db, orgID).Model(&model.Membership{}).
			Where("user_id = ?", subjectUserID).Count(&count).Error; err != nil {
			return nil, false, err
		}
		if count == 0 {
			return nil, false, ErrSubjectNotMember
		}
	}

	book, err := s.sharedBookForGrants(userID, orgID, bookID, perms)
	if err != nil {
		return nil, false, err
	}

	var row model.AddressBookGrant
	created := false
	err = s.db.Transaction(func(tx *gorm.DB) error {
		if _, err := lockBook(tx, orgID, book.ID); err != nil {
			return err
		}
		var existing model.AddressBookGrant
		findErr := store.ScopedByOrg(tx, orgID).
			Where("book_id = ? AND subject_kind = ? AND subject_user_id = ?", book.ID, subjectKind, subjectUserID).
			First(&existing).Error
		switch {
		case findErr == nil:
			res := store.ScopedByOrg(tx, orgID).Model(&model.AddressBookGrant{}).
				Where("id = ?", existing.ID).
				Updates(map[string]any{"access": accessLevel, "created_by": userID})
			if res.Error != nil {
				return res.Error
			}
			if err := store.ScopedByOrg(tx, orgID).First(&row, existing.ID).Error; err != nil {
				return err
			}
		case errors.Is(findErr, gorm.ErrRecordNotFound):
			row = model.AddressBookGrant{
				OrganizationID: orgID,
				BookID:         book.ID,
				SubjectKind:    subjectKind,
				SubjectUserID:  subjectUserID,
				Access:         accessLevel,
				CreatedBy:      userID,
			}
			// The unique index decides a race between two creators; the loser
			// updates the row instead of failing on a duplicate.
			if err := store.ScopedByOrg(tx, orgID).
				Clauses(clause.OnConflict{
					Columns:   []clause.Column{{Name: "book_id"}, {Name: "subject_kind"}, {Name: "subject_user_id"}},
					DoUpdates: clause.AssignmentColumns([]string{"access", "created_by", "updated_at"}),
				}).
				Create(&row).Error; err != nil {
				return err
			}
			if err := store.ScopedByOrg(tx, orgID).
				Where("book_id = ? AND subject_kind = ? AND subject_user_id = ?", book.ID, subjectKind, subjectUserID).
				First(&row).Error; err != nil {
				return err
			}
			created = true
		default:
			return findErr
		}
		return nil
	})
	if err != nil {
		return nil, false, err
	}
	return &row, created, nil
}

// DeleteGrant revokes one grant of a shared book.
func (s *Service) DeleteGrant(userID, orgID, bookID, grantID uint, perms []string) error {
	book, err := s.sharedBookForGrants(userID, orgID, bookID, perms)
	if err != nil {
		return err
	}
	res := store.ScopedByOrg(s.db, orgID).
		Where("book_id = ? AND id = ?", book.ID, grantID).
		Delete(&model.AddressBookGrant{})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrGrantNotFound
	}
	return nil
}
