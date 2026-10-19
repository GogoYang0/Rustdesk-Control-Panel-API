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

	detail, err := detailJSON(entry)
	if err != nil {
		return err
	}

	var lastErr error
	for attempt := 0; attempt < maxSeqAttempts; attempt++ {
		err := a.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			return insertAuditRow(tx, entry, detail)
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

// RecordTx implements TxRecorder: it allocates the sequence and inserts the
// entry on the caller's transaction, so the entity change and the audit row
// commit or roll back together (#19). There is deliberately no retry loop —
// a duplicate-key collision fails the whole transaction, and the outer
// entity retry strategy decides what to do.
func (a *GormAuditor) RecordTx(tx *gorm.DB, entry Entry) error {
	if entry.OrganizationID == 0 {
		return nil
	}

	detail, err := detailJSON(entry)
	if err != nil {
		return err
	}
	return insertAuditRow(tx, entry, detail)
}

// detailJSON serialises the entry detail; an empty detail becomes "{}".
func detailJSON(entry Entry) (string, error) {
	if len(entry.Detail) == 0 {
		return "{}", nil
	}
	b, err := json.Marshal(entry.Detail)
	if err != nil {
		return "", fmt.Errorf("marshal audit detail: %w", err)
	}
	return string(b), nil
}

// insertAuditRow locks the organization row, allocates the next sequence and
// inserts the entry — all on the given (possibly transactional) handle.
func insertAuditRow(tx *gorm.DB, entry Entry, detail string) error {
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
}
