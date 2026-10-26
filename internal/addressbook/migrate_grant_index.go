package addressbook

import (
	"fmt"

	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
)

// grantSubjectIndex is the unique index that keeps one grant per
// (book, subject kind, user, group) tuple.
const grantSubjectIndex = "idx_abg_book_subject"

// MigrateGrantSubjectIndex rebuilds the grant uniqueness index with the user
// group as its fourth column.
//
// The pre-upgrade index covered (book_id, subject_kind, subject_user_id) only.
// A user_group grant stores 0 in subject_user_id, so every group grant of one
// book collapsed onto the same tuple and the second insert was rejected as a
// duplicate. AutoMigrate does not replace an index whose name already exists, so
// the old one is dropped explicitly before the four-column index is created;
// a failure aborts startup rather than leaving the database with no constraint.
func MigrateGrantSubjectIndex(db *gorm.DB) error {
	m := db.Migrator()
	if m.HasIndex(&model.AddressBookGrant{}, grantSubjectIndex) {
		if err := m.DropIndex(&model.AddressBookGrant{}, grantSubjectIndex); err != nil {
			return fmt.Errorf("drop legacy grant index: %w", err)
		}
	}
	if err := m.CreateIndex(&model.AddressBookGrant{}, grantSubjectIndex); err != nil {
		return fmt.Errorf("create grant subject index: %w", err)
	}
	return nil
}
