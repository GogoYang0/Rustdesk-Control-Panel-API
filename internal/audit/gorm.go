package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// maxSeqAttempts bounds the retry loop when concurrent writers collide.
const maxSeqAttempts = 20

// GormAuditor persists audit entries with a per-organization continuous Seq.
//
// Two writers in the same organization may compute the same next Seq. The
// unique index (organization_id, seq) turns that race into a duplicate-key
// error, and the writer retries with a fresh maximum, so the sequence stays
// continuous without a separate counter table.
type GormAuditor struct {
	db *gorm.DB
}

// NewGormAuditor builds a persistent auditor.
func NewGormAuditor(db *gorm.DB) *GormAuditor { return &GormAuditor{db: db} }

// Record implements Auditor.
func (a *GormAuditor) Record(ctx context.Context, entry Entry) error {
	if entry.OrganizationID == 0 {
		// Entries without a tenant (login, health checks) are not persisted:
		// they cannot be given a per-org sequence.
		return nil
	}

	detail := "{}"
	if len(entry.Detail) > 0 {
		b, err := json.Marshal(entry.Detail)
		if err != nil {
			return fmt.Errorf("marshal audit detail: %w", err)
		}
		detail = string(b)
	}

	var lastErr error
	for attempt := 0; attempt < maxSeqAttempts; attempt++ {
		err := a.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			// Locking the organization row serialises sequence allocation on
			// databases that support row locks; SQLite serialises writers anyway.
			var org model.Organization
			if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
				First(&org, entry.OrganizationID).Error; err != nil {
				return err
			}

			// The tenant plugin fails closed without an org context, so the
			// maximum must be read through the scoped handle.
			var maxSeq uint64
			if err := store.ScopedByOrg(tx, entry.OrganizationID).
				Model(&model.AuditLog{}).
				Select("COALESCE(MAX(seq), 0)").
				Scan(&maxSeq).Error; err != nil {
				return err
			}

			row := model.AuditLog{
				OrganizationID: entry.OrganizationID,
				Seq:            maxSeq + 1,
				ActorUserID:    entry.ActorUserID,
				Action:         entry.Action,
				TargetType:     entry.TargetType,
				TargetID:       entry.TargetID,
				Detail:         detail,
				CreatedAt:      time.Now(),
			}
			return tx.Create(&row).Error
		})
		if err == nil {
			return nil
		}
		lastErr = err
		if !errors.Is(err, gorm.ErrDuplicatedKey) {
			return fmt.Errorf("record audit entry: %w", err)
		}
	}
	return fmt.Errorf("record audit entry after %d attempts: %w", maxSeqAttempts, lastErr)
}
