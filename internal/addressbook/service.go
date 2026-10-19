// Package addressbook implements the personal/shared address book domain:
// CRUD over books, full-replacement peer/tag updates with a revision
// counter, and the authorization rules that keep personal books private.
package addressbook

import (
	"encoding/json"
	"errors"
	"fmt"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/authz"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// Service-level errors mapped to HTTP statuses by the handler.
var (
	ErrBookNotFound  = errors.New("address book not found")
	ErrDuplicateName = errors.New("address book name already exists")
	ErrForbidden     = errors.New("not allowed to access this address book")
)

// Service carries the scoped handle; every query goes through
// store.ScopedByOrg so the tenant plugin can enforce isolation.
type Service struct {
	db *gorm.DB
}

// NewService builds the address book service.
func NewService(db *gorm.DB) *Service { return &Service{db: db} }

// PeerInput is the service-level shape of one peer entry (decoded from the
// contract type by the handler).
type PeerInput struct {
	PeerID   string
	Alias    string
	Username string
	Hostname string
	Platform string
	Tags     []string
}

// TagInput is the service-level shape of one tag entry.
type TagInput struct {
	Name  string
	Color uint32
}

// List returns the books the user may see: shared books of the organization
// plus their own personal books.
func (s *Service) List(userID, orgID uint) ([]model.AddressBook, error) {
	var books []model.AddressBook
	err := store.ScopedByOrg(s.db, orgID).
		Where("scope = ? OR owner_id = ?", model.AddressBookScopeShared, userID).
		Order("id").
		Find(&books).Error
	return books, err
}

// Create adds a book. Personal books bind the caller as owner; shared books
// are org-wide (the handler checks the write permission before calling).
func (s *Service) Create(userID, orgID uint, scope, name string) (*model.AddressBook, error) {
	book := &model.AddressBook{OrganizationID: orgID, Scope: scope, Name: name}
	if err := book.Valid(); err != nil {
		return nil, err
	}
	if scope == model.AddressBookScopePersonal {
		book.OwnerID = &userID
	}

	// The duplicate-name pre-check alone cannot stop two concurrent creations
	// (it protects no existing row), so Create serialises on the organization
	// row; the shared-book unique index cannot deduplicate NULL owners.
	err := s.db.Transaction(func(tx *gorm.DB) error {
		if err := lockOrgRow(tx, orgID); err != nil {
			return err
		}
		var count int64
		q := store.ScopedByOrg(tx, orgID).Model(&model.AddressBook{}).
			Where("scope = ? AND name = ?", scope, name)
		if scope == model.AddressBookScopePersonal {
			q = q.Where("owner_id = ?", userID)
		}
		if err := q.Count(&count).Error; err != nil {
			return err
		}
		if count > 0 {
			return ErrDuplicateName
		}
		if err := store.ScopedByOrg(tx, orgID).Create(book).Error; err != nil {
			if errors.Is(err, gorm.ErrDuplicatedKey) {
				return ErrDuplicateName
			}
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return book, nil
}

// getBook loads one book and enforces read access: personal books are only
// visible to their owner; shared books to every member (membership is
// already enforced by the handler).
func (s *Service) getBook(userID, orgID, bookID uint) (*model.AddressBook, error) {
	var book model.AddressBook
	err := store.ScopedByOrg(s.db, orgID).First(&book, bookID).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrBookNotFound
	}
	if err != nil {
		return nil, err
	}
	if book.Scope == model.AddressBookScopePersonal {
		if book.OwnerID == nil || *book.OwnerID != userID {
			return nil, ErrBookNotFound
		}
	}
	return &book, nil
}

// canWrite reports whether the user may modify the book: personal — owner
// only; shared — roles holding the addressbook write permission.
func canWrite(book *model.AddressBook, userID uint, role string) bool {
	if book.Scope == model.AddressBookScopePersonal {
		return book.OwnerID != nil && *book.OwnerID == userID
	}
	return authz.Can(role, authz.PermAddressBook)
}

// Get returns the book together with its peers and tags.
func (s *Service) Get(userID, orgID, bookID uint) (*model.AddressBook, []model.AddressBookPeer, []model.AddressBookTag, error) {
	book, err := s.getBook(userID, orgID, bookID)
	if err != nil {
		return nil, nil, nil, err
	}

	var peers []model.AddressBookPeer
	if err := store.ScopedByOrg(s.db, orgID).
		Where("book_id = ?", book.ID).Order("id").Find(&peers).Error; err != nil {
		return nil, nil, nil, err
	}
	var tags []model.AddressBookTag
	if err := store.ScopedByOrg(s.db, orgID).
		Where("book_id = ?", book.ID).Order("name").Find(&tags).Error; err != nil {
		return nil, nil, nil, err
	}
	return book, peers, tags, nil
}

// Update renames the book. Scope stays immutable (contract 0.3.0). The
// duplicate-name check and the rename run inside one transaction holding the
// organization row lock — the same serialisation as Create — otherwise a
// concurrent Create could insert the target name between the check and the
// write and produce two same-named shared books (NULL owner is not
// deduplicated by the unique index).
func (s *Service) Update(userID uint, role string, orgID, bookID uint, name string) (*model.AddressBook, error) {
	book, err := s.getBook(userID, orgID, bookID)
	if err != nil {
		return nil, err
	}
	if !canWrite(book, userID, role) {
		return nil, ErrForbidden
	}
	err = s.db.Transaction(func(tx *gorm.DB) error {
		if err := lockOrgRow(tx, orgID); err != nil {
			return err
		}
		// Re-read under the book row lock: a concurrent Delete may have
		// removed the book between the pre-transaction read and here.
		current, err := lockBook(tx, orgID, book.ID)
		if err != nil {
			return err
		}
		book = current
		if book.Name == name {
			return nil
		}
		var count int64
		q := store.ScopedByOrg(tx, orgID).Model(&model.AddressBook{}).
			Where("scope = ? AND name = ? AND id <> ?", book.Scope, name, book.ID)
		if book.Scope == model.AddressBookScopePersonal {
			q = q.Where("owner_id = ?", userID)
		}
		if err := q.Count(&count).Error; err != nil {
			return err
		}
		if count > 0 {
			return ErrDuplicateName
		}
		res := store.ScopedByOrg(tx, orgID).Model(book).
			Update("name", name)
		if res.Error != nil {
			if errors.Is(res.Error, gorm.ErrDuplicatedKey) {
				return ErrDuplicateName
			}
			return res.Error
		}
		if res.RowsAffected == 0 {
			return ErrBookNotFound
		}
		book.Name = name
		return nil
	})
	if err != nil {
		return nil, err
	}
	return book, nil
}

// lockOrgRow takes a write lock on the organization row so check-then-insert
// sequences (duplicate-name pre-checks, quota-like counts) serialise across
// concurrent requests. SQLite has no SELECT ... FOR UPDATE and serialises
// writers itself, so the clause is skipped there.
func lockOrgRow(tx *gorm.DB, orgID uint) error {
	query := tx
	if tx.Name() != "sqlite" {
		query = query.Clauses(clause.Locking{Strength: "UPDATE"})
	}
	var org model.Organization
	return query.Select("id").First(&org, orgID).Error
}

// lockBook takes a write lock on the book row inside a transaction so
// concurrent full-replaces serialise instead of merging lists, and so a
// concurrent Delete cannot orphan child rows. SQLite has no SELECT ... FOR
// UPDATE and serialises writers itself, so the clause is skipped there.
func lockBook(tx *gorm.DB, orgID, bookID uint) (*model.AddressBook, error) {
	query := store.ScopedByOrg(tx, orgID)
	if tx.Name() != "sqlite" {
		query = query.Clauses(clause.Locking{Strength: "UPDATE"})
	}
	var book model.AddressBook
	err := query.First(&book, bookID).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrBookNotFound
	}
	if err != nil {
		return nil, err
	}
	return &book, nil
}

// bumpRevision increments the revision under the held row lock and fails the
// transaction if the row vanished (RowsAffected == 0).
func bumpRevision(tx *gorm.DB, orgID, bookID uint) error {
	res := store.ScopedByOrg(tx, orgID).Model(&model.AddressBook{}).
		Where("id = ?", bookID).
		UpdateColumn("revision", gorm.Expr("revision + 1"))
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrBookNotFound
	}
	return nil
}

// Delete removes the book together with its peers and tags. The book row is
// locked first so a concurrent replace cannot re-insert children after the
// cascading deletes.
func (s *Service) Delete(userID uint, role string, orgID, bookID uint) (*model.AddressBook, error) {
	book, err := s.getBook(userID, orgID, bookID)
	if err != nil {
		return nil, err
	}
	if !canWrite(book, userID, role) {
		return nil, ErrForbidden
	}
	err = s.db.Transaction(func(tx *gorm.DB) error {
		if _, err := lockBook(tx, orgID, book.ID); err != nil {
			return err
		}
		if err := store.ScopedByOrg(tx, orgID).
			Where("book_id = ?", book.ID).Delete(&model.AddressBookPeer{}).Error; err != nil {
			return err
		}
		if err := store.ScopedByOrg(tx, orgID).
			Where("book_id = ?", book.ID).Delete(&model.AddressBookTag{}).Error; err != nil {
			return err
		}
		return store.ScopedByOrg(tx, orgID).Delete(book).Error
	})
	if err != nil {
		return nil, err
	}
	return book, nil
}

// ReplacePeers swaps the full peer list inside a transaction and bumps the
// book revision. The book row is locked for the whole transaction so two
// concurrent replaces serialise instead of merging their lists, and the
// refreshed row is read before commit (no post-commit reload race).
func (s *Service) ReplacePeers(userID uint, role string, orgID, bookID uint, peers []PeerInput) (*model.AddressBook, error) {
	book, err := s.getBook(userID, orgID, bookID)
	if err != nil {
		return nil, err
	}
	if !canWrite(book, userID, role) {
		return nil, ErrForbidden
	}

	var fresh model.AddressBook
	err = s.db.Transaction(func(tx *gorm.DB) error {
		if _, err := lockBook(tx, orgID, book.ID); err != nil {
			return err
		}
		if err := store.ScopedByOrg(tx, orgID).
			Where("book_id = ?", book.ID).Delete(&model.AddressBookPeer{}).Error; err != nil {
			return err
		}
		for _, p := range peers {
			row := model.AddressBookPeer{
				OrganizationID: orgID,
				BookID:         book.ID,
				PeerID:         p.PeerID,
				Alias:          p.Alias,
				Username:       p.Username,
				Hostname:       p.Hostname,
				Platform:       p.Platform,
				TagsJSON:       TagsJSON(p.Tags),
			}
			if err := store.ScopedByOrg(tx, orgID).Create(&row).Error; err != nil {
				return err
			}
		}
		if err := bumpRevision(tx, orgID, book.ID); err != nil {
			return err
		}
		return store.ScopedByOrg(tx, orgID).First(&fresh, book.ID).Error
	})
	if err != nil {
		return nil, err
	}
	return &fresh, nil
}

// ReplaceTags swaps the full tag list inside a transaction and bumps the
// book revision, under the same row lock as ReplacePeers.
func (s *Service) ReplaceTags(userID uint, role string, orgID, bookID uint, tags []TagInput) (*model.AddressBook, error) {
	book, err := s.getBook(userID, orgID, bookID)
	if err != nil {
		return nil, err
	}
	if !canWrite(book, userID, role) {
		return nil, ErrForbidden
	}

	var fresh model.AddressBook
	err = s.db.Transaction(func(tx *gorm.DB) error {
		if _, err := lockBook(tx, orgID, book.ID); err != nil {
			return err
		}
		if err := store.ScopedByOrg(tx, orgID).
			Where("book_id = ?", book.ID).Delete(&model.AddressBookTag{}).Error; err != nil {
			return err
		}
		for _, tg := range tags {
			row := model.AddressBookTag{
				OrganizationID: orgID,
				BookID:         book.ID,
				Name:           tg.Name,
				Color:          tg.Color,
			}
			if err := store.ScopedByOrg(tx, orgID).Create(&row).Error; err != nil {
				return err
			}
		}
		if err := bumpRevision(tx, orgID, book.ID); err != nil {
			return err
		}
		return store.ScopedByOrg(tx, orgID).First(&fresh, book.ID).Error
	})
	if err != nil {
		return nil, err
	}
	return &fresh, nil
}

// tagsJSON serialises the tag name list; nil becomes an empty array so the
// stored value is always valid JSON.
func TagsJSON(tags []string) string {
	if tags == nil {
		tags = []string{}
	}
	b, err := json.Marshal(tags)
	if err != nil {
		return "[]"
	}
	return string(b)
}

// DecodeTagsJSON parses the stored tags back into a slice.
func DecodeTagsJSON(raw string) ([]string, error) {
	var tags []string
	if err := json.Unmarshal([]byte(raw), &tags); err != nil {
		return nil, fmt.Errorf("decode peer tags: %w", err)
	}
	return tags, nil
}
