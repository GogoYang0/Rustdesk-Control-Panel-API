package authz

import (
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
)

// DropLegacyRoleMark is the one-shot marker of the memberships.role removal.
// Exported so operators and tests can look it up.
const DropLegacyRoleMark = "2026-10-26-drop-membership-role"

// MigrateDropLegacyRole removes the legacy memberships.role string column.
//
// RoleID is the only authorization source since v0.8.0, but the string column
// stayed behind so the staged backfill could read it. Keeping it is a standing
// invitation to read authorization from a string again, so v0.10.0 drops it —
// after MigrateRoles has mapped every membership, which is why the two run in
// that order at startup.
//
// The drop is guarded by a marker rather than by the column's existence: if the
// DROP itself fails, the next boot must retry it instead of skipping. A
// database that never had the column (a fresh install) just records the marker.
func MigrateDropLegacyRole(db *gorm.DB) error {
	var mark model.MigrationMark
	err := db.Where("name = ?", DropLegacyRoleMark).First(&mark).Error
	if err == nil {
		return nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return fmt.Errorf("look up role drop mark: %w", err)
	}

	if !db.Migrator().HasColumn(&model.Membership{}, "role") {
		return recordDropMark(db)
	}
	return db.Transaction(func(tx *gorm.DB) error {
		if err := dropLegacyRoleColumn(tx); err != nil {
			return err
		}
		return recordDropMark(tx)
	})
}

// dropLegacyRoleColumn removes the column with dialect-aware SQL and checks the
// result. Migrator().DropColumn cannot be used: the SQLite driver used here
// returns success without dropping anything, which would leave the column in
// place while the marker claims it is gone. The post-check turns any such
// mismatch into a startup failure instead of a silent half-migration.
func dropLegacyRoleColumn(db *gorm.DB) error {
	statement := "ALTER TABLE memberships DROP COLUMN role"
	if db.Dialector.Name() == "postgres" {
		statement = "ALTER TABLE memberships DROP COLUMN IF EXISTS role"
	}
	if err := db.Exec(statement).Error; err != nil {
		return fmt.Errorf("drop memberships.role: %w", err)
	}
	if db.Migrator().HasColumn(&model.Membership{}, "role") {
		return errors.New("memberships.role still exists after DROP COLUMN")
	}
	return nil
}

// recordDropMark writes the marker idempotently, tolerating a concurrent
// loser of the insert race.
func recordDropMark(db *gorm.DB) error {
	return db.Clauses(clause.OnConflict{DoNothing: true}).
		Create(&model.MigrationMark{Name: DropLegacyRoleMark, AppliedAt: time.Now().UTC()}).Error
}
