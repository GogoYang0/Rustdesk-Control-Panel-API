package model

import "time"

// MigrationMark records one-time data migrations that must succeed exactly
// once and be retried on failure. Unlike DDL (AutoMigrate), a failed data
// backfill must not be skipped just because the schema is already in place:
// the marker row is written only after the backfill succeeds, so a crashed
// startup retries it on the next boot.
type MigrationMark struct {
	ID        uint      `gorm:"primaryKey"`
	Name      string    `gorm:"size:64;uniqueIndex;not null"`
	AppliedAt time.Time `gorm:"not null"`
}
