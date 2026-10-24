package audit

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// MaxRetentionDays bounds the configurable retention window.
const MaxRetentionDays = 3650

// ErrInvalidRetention reports an out-of-range retention setting.
var ErrInvalidRetention = errors.New("audit retention days must be between 0 and 3650")

// RetentionService archives and purges audit rows per organization.
//
// The order is fixed: write the archive, verify it line-by-line against the
// rows, and only then delete those rows. A failed archive or verification
// leaves the rows untouched (fail closed) so data is never destroyed without a
// readable copy.
type RetentionService struct {
	db       *gorm.DB
	dir      string
	recorder TxRecorder
	now      func() time.Time
}

// NewRetentionService builds the service. A nil recorder makes RunOnce refuse
// to delete anything: system retention actions must be auditable.
func NewRetentionService(db *gorm.DB, archiveDir string, recorder TxRecorder, now func() time.Time) *RetentionService {
	if now == nil {
		now = time.Now
	}
	return &RetentionService{db: db, dir: archiveDir, recorder: recorder, now: now}
}

// Get returns an organization's retention setting.
func (s *RetentionService) Get(ctx context.Context, orgID uint) (int, error) {
	var org model.Organization
	if err := s.db.WithContext(ctx).Select("id", "audit_retention_days").First(&org, orgID).Error; err != nil {
		return 0, err
	}
	return org.AuditRetentionDays, nil
}

// SetDays updates the retention window (0 = keep forever).
func (s *RetentionService) SetDays(ctx context.Context, orgID uint, days int) error {
	return s.SetDaysTx(s.db.WithContext(ctx), orgID, days)
}

// SetDaysTx is SetDays on the caller's transaction, so the setting and its
// audit entry commit together.
func (s *RetentionService) SetDaysTx(tx *gorm.DB, orgID uint, days int) error {
	if days < 0 || days > MaxRetentionDays {
		return ErrInvalidRetention
	}
	// Confirm the organization first: a MySQL update to the same value reports
	// zero affected rows, which must not be mistaken for "not found".
	var org model.Organization
	if err := tx.Select("id").First(&org, orgID).Error; err != nil {
		return err
	}
	return tx.Model(&model.Organization{}).
		Where("id = ?", orgID).
		Update("audit_retention_days", days).Error
}

// RunOnce archives and purges expired audit rows for every organization with a
// positive retention window. It returns the totals and the first error; one
// organization's failure does not stop the others.
func (s *RetentionService) RunOnce(ctx context.Context) (archived, purged int64, err error) {
	if s.recorder == nil {
		return 0, 0, errors.New("audit: no transactional recorder configured for retention")
	}
	var orgs []model.Organization
	if err := s.db.WithContext(ctx).
		Select("id", "audit_retention_days").
		Where("audit_retention_days > 0").
		Order("id").
		Find(&orgs).Error; err != nil {
		return 0, 0, err
	}
	var firstErr error
	for _, org := range orgs {
		a, p, err := s.runOrg(ctx, org)
		archived += a
		purged += p
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return archived, purged, firstErr
}

// runOrg handles one organization: archive the expired rows, verify the file,
// then delete exactly those rows and record both system audit entries in the
// deletion transaction.
func (s *RetentionService) runOrg(ctx context.Context, org model.Organization) (archived, purged int64, err error) {
	cutoff := s.now().UTC().AddDate(0, 0, -org.AuditRetentionDays)
	var rows []model.AuditLog
	if err := store.ScopedByOrg(s.db.WithContext(ctx), org.ID).
		Where("created_at < ?", cutoff).
		Order("created_at").
		Order("id").
		Find(&rows).Error; err != nil {
		return 0, 0, err
	}
	if len(rows) == 0 {
		return 0, 0, nil
	}

	path, sum, err := s.writeArchive(org.ID, rows)
	if err != nil {
		return 0, 0, err
	}
	if err := verifyArchive(path, sum, len(rows)); err != nil {
		return 0, 0, err
	}

	ids := make([]uint, 0, len(rows))
	for _, row := range rows {
		ids = append(ids, row.ID)
	}
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		res := store.ScopedByOrg(tx, org.ID).
			Where("id IN ?", ids).
			Delete(&model.AuditLog{})
		if res.Error != nil {
			return res.Error
		}
		purged = res.RowsAffected
		if err := s.recorder.RecordTx(tx, Entry{
			OrganizationID: org.ID,
			ActorUserID:    0,
			Action:         "audit.retention.archive",
			TargetType:     "audit_log",
			Detail: map[string]any{
				"rows":      len(rows),
				"path":      path,
				"sha256":    sum,
				"threshold": cutoff,
			},
		}); err != nil {
			return err
		}
		return s.recorder.RecordTx(tx, Entry{
			OrganizationID: org.ID,
			ActorUserID:    0,
			Action:         "audit.retention.purge",
			TargetType:     "audit_log",
			Detail: map[string]any{
				"rows":      purged,
				"threshold": cutoff,
			},
		})
	})
	if err != nil {
		return 0, 0, err
	}
	return int64(len(rows)), purged, nil
}

// writeArchive streams the rows to a JSONL temp file, computes its SHA-256, and
// atomically renames both the data and checksum files into place.
func (s *RetentionService) writeArchive(orgID uint, rows []model.AuditLog) (path, sum string, err error) {
	dir := filepath.Join(s.dir, fmt.Sprintf("org-%d", orgID))
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", "", fmt.Errorf("create audit archive directory: %w", err)
	}
	stamp := s.now().UTC().Format("20060102T150405.000000000Z")
	path = filepath.Join(dir, "audit-"+stamp+".jsonl")
	tmp := path + ".tmp"
	shaTmp := path + ".sha256.tmp"

	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		return "", "", fmt.Errorf("create audit archive: %w", err)
	}
	hash := sha256.New()
	enc := json.NewEncoder(io.MultiWriter(f, hash))
	writeErr := func() error {
		for _, row := range rows {
			if err := enc.Encode(row); err != nil {
				return err
			}
		}
		return f.Sync()
	}()
	closeErr := f.Close()
	if writeErr != nil {
		_ = os.Remove(tmp)
		return "", "", fmt.Errorf("write audit archive: %w", writeErr)
	}
	if closeErr != nil {
		_ = os.Remove(tmp)
		return "", "", fmt.Errorf("close audit archive: %w", closeErr)
	}
	sum = hex.EncodeToString(hash.Sum(nil))

	line := sum + "  " + filepath.Base(path) + "\n"
	if err := os.WriteFile(shaTmp, []byte(line), 0o640); err != nil {
		_ = os.Remove(tmp)
		return "", "", fmt.Errorf("write audit archive checksum: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		_ = os.Remove(shaTmp)
		return "", "", fmt.Errorf("publish audit archive: %w", err)
	}
	if err := os.Rename(shaTmp, path+".sha256"); err != nil {
		_ = os.Remove(path)
		_ = os.Remove(shaTmp)
		return "", "", fmt.Errorf("publish audit archive checksum: %w", err)
	}
	return path, sum, nil
}

// verifyArchive re-reads the archive and confirms both its line count and its
// digest before any row is deleted.
func verifyArchive(path, expectedSum string, expectedLines int) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("verify audit archive: %w", err)
	}
	defer func() { _ = f.Close() }()
	hash := sha256.New()
	scanner := bufio.NewScanner(io.TeeReader(f, hash))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lines := 0
	for scanner.Scan() {
		lines++
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("verify audit archive: %w", err)
	}
	if lines != expectedLines {
		return fmt.Errorf("verify audit archive: expected %d rows, file has %d", expectedLines, lines)
	}
	if sum := hex.EncodeToString(hash.Sum(nil)); sum != expectedSum {
		return fmt.Errorf("verify audit archive: checksum mismatch")
	}
	return nil
}

// LatestArchive describes the most recent successful archive of an
// organization (for the retention status response).
type LatestArchive struct {
	At    time.Time
	Rows  int
	Path  string
	Found bool
}

// Latest returns the newest audit.retention.archive entry of the organization.
func (s *RetentionService) Latest(ctx context.Context, orgID uint) (LatestArchive, error) {
	var row model.AuditLog
	err := store.ScopedByOrg(s.db.WithContext(ctx), orgID).
		Where("action = ?", "audit.retention.archive").
		Order("id DESC").
		First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return LatestArchive{}, nil
	}
	if err != nil {
		return LatestArchive{}, err
	}
	detail := struct {
		Rows int    `json:"rows"`
		Path string `json:"path"`
	}{}
	if row.Detail != "" {
		_ = json.Unmarshal([]byte(row.Detail), &detail)
	}
	return LatestArchive{At: row.CreatedAt, Rows: detail.Rows, Path: detail.Path, Found: true}, nil
}
