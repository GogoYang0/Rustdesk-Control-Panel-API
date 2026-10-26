package addressbook

import (
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
)

// grantSubjectIndex is the unique index that keeps one grant per
// (book, subject kind, user, group) tuple.
const grantSubjectIndex = "idx_abg_book_subject"

// GrantSubjectIndexMark is the one-shot marker of the index rebuild. The
// rebuild is destructive (drop + create), so it must not run on every boot: on
// a large MySQL/PostgreSQL table that would rebuild the index on each restart.
const GrantSubjectIndexMark = "2026-10-26-grant-subject-index"

// MigrateGrantSubjectIndex rebuilds the grant uniqueness index with the user
// group as its fourth column, once per database.
//
// The pre-upgrade index covered (book_id, subject_kind, subject_user_id) only.
// A user_group grant stores 0 in subject_user_id, so every group grant of one
// book collapsed onto the same tuple and the second insert was rejected as a
// duplicate. AutoMigrate does not replace an index whose name already exists, so
// the old one is dropped explicitly before the four-column index is created;
// a failure aborts startup rather than leaving the database with no constraint.
func MigrateGrantSubjectIndex(db *gorm.DB) error {
	var mark model.MigrationMark
	err := db.Where("name = ?", GrantSubjectIndexMark).First(&mark).Error
	if err == nil {
		return nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return fmt.Errorf("look up grant index mark: %w", err)
	}

	m := db.Migrator()
	if m.HasIndex(&model.AddressBookGrant{}, grantSubjectIndex) {
		if err := m.DropIndex(&model.AddressBookGrant{}, grantSubjectIndex); err != nil {
			return fmt.Errorf("drop legacy grant index: %w", err)
		}
	}
	if err := m.CreateIndex(&model.AddressBookGrant{}, grantSubjectIndex); err != nil {
		return fmt.Errorf("create grant subject index: %w", err)
	}
	return db.Clauses(clause.OnConflict{DoNothing: true}).
		Create(&model.MigrationMark{Name: GrantSubjectIndexMark, AppliedAt: time.Now().UTC()}).Error
}
