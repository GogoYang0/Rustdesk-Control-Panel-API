// Package logquery ingests the audit records RustDesk clients push and serves
// them back to the console.
//
// The client posts to /api/audit/{conn,file,alarm} without any Authorization
// header (src/common.rs builds the URL, src/server/connection.rs posts the
// body), so authenticity rests on the (rustdesk id, uuid) pair matching the
// device's stored binding — the same trust level as the credential-free
// heartbeat. Every record carries a nonce and the upstream API server
// deduplicates retries for five minutes; we do the same.
package logquery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/audit"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// Ingest bounds. The client truncates file lists to ten entries upstream; the
// note bound mirrors the column size.
const (
	maxNoteLen = 512
)

// Domain errors. Handlers map them onto 400/403.
var (
	ErrMalformed        = errors.New("malformed audit payload")
	ErrUnknownDevice    = errors.New("unknown device")
	ErrIdentityMismatch = errors.New("device identity mismatch")
	// ErrAmbiguousDevice reports a rustdesk id that exists in more than one
	// organization with the same binding: writing to either would be a guess.
	ErrAmbiguousDevice = errors.New("device identity is ambiguous across organizations")
	// ErrUnaudited reports an alarm that cannot be persisted with its sequence:
	// dropping a security event silently is worse than returning an error.
	ErrUnaudited = errors.New("audit recorder does not support transactional writes")
)

// ConnPayload mirrors the client's connection audit body
// (src/server/connection.rs post_conn_audit).
type ConnPayload struct {
	ID           string `json:"id"`
	UUID         string `json:"uuid"`
	Action       string `json:"action"`
	IP           string `json:"ip"`
	ConnID       int64  `json:"conn_id"`
	SessionID    int64  `json:"session_id"`
	Nonce        string `json:"nonce"`
	ConnAuditRef string `json:"conn_audit_ref"`
	Note         string `json:"note"`
}

// FilePayload mirrors post_file_audit. Type is 0 (send) or 1 (receive) and Info
// is a JSON *string* containing ip/name/num/files.
type FilePayload struct {
	ID     string `json:"id"`
	UUID   string `json:"uuid"`
	PeerID string `json:"peer_id"`
	ConnID int64  `json:"conn_id"`
	Type   int    `json:"type"`
	Path   string `json:"path"`
	IsFile bool   `json:"is_file"`
	Info   string `json:"info"`
	Nonce  string `json:"nonce"`
}

// AlarmPayload mirrors post_alarm_audit. Typ is the client's AlarmAuditType.
type AlarmPayload struct {
	ID           string `json:"id"`
	UUID         string `json:"uuid"`
	Typ          int    `json:"typ"`
	Info         string `json:"info"`
	ConnID       int64  `json:"conn_id"`
	Nonce        string `json:"nonce"`
	ConnAuditRef string `json:"conn_audit_ref"`
}

// Ingest writes client-reported audit records.
type Ingest struct {
	db      *gorm.DB
	auditor audit.Auditor
	now     func() time.Time
}

// New builds the ingest service. A nil auditor makes alarm ingestion fail
// closed; conn and file rows do not go through the auditor.
func New(db *gorm.DB, auditor audit.Auditor, now func() time.Time) *Ingest {
	if now == nil {
		now = time.Now
	}
	return &Ingest{db: db, auditor: auditor, now: now}
}

// Conn handles both connection lifecycle reports and the note-only body the
// client's "send note" action posts (no uuid, no action, no nonce).
func (i *Ingest) Conn(ctx context.Context, p ConnPayload) (bool, error) {
	if p.ID == "" {
		return false, ErrMalformed
	}
	if err := validateConnPayload(p); err != nil {
		return false, err
	}
	if p.Action == "" && p.Note != "" {
		return false, i.appendNote(ctx, p)
	}
	if p.Action != "new" && p.Action != "close" {
		return false, ErrMalformed
	}
	if p.Nonce == "" {
		return false, ErrMalformed
	}
	dev, err := i.resolveDevice(ctx, p.ID, p.UUID)
	if err != nil {
		return false, err
	}
	return i.withNonce(ctx, dev.OrganizationID, p.Nonce, func(tx *gorm.DB) error {
		now := i.now().UTC()
		switch p.Action {
		case "new":
			row := model.ConnectionLog{
				OrganizationID: dev.OrganizationID,
				DeviceID:       dev.ID,
				RustdeskID:     p.ID,
				ConnID:         p.ConnID,
				SessionID:      p.SessionID,
				IP:             p.IP,
				Status:         model.ConnectionLogStatusOpen,
				StartedAt:      now,
				ConnAuditRef:   p.ConnAuditRef,
				CreatedAt:      now,
				UpdatedAt:      now,
			}
			// A retry with a fresh nonce must not create a second row for the
			// same connection: the identity index is the dedupe of last resort.
			return store.WithoutTenantScope(tx).
				Clauses(clause.OnConflict{DoNothing: true}).Create(&row).Error
		default: // close
			res := store.WithoutTenantScope(tx).Model(&model.ConnectionLog{}).
				Where("organization_id = ? AND rustdesk_id = ? AND conn_id = ? AND session_id = ? AND status = ?",
					dev.OrganizationID, p.ID, p.ConnID, p.SessionID, model.ConnectionLogStatusOpen).
				Updates(map[string]any{
					"status":     model.ConnectionLogStatusClosed,
					"ended_at":   now,
					"updated_at": now,
				})
			if res.Error != nil {
				return res.Error
			}
			if res.RowsAffected > 0 {
				return nil
			}
			// The close arrived without its new (out-of-order retry or a lost
			// report). Keep the evidence as an already-closed row instead of
			// dropping it.
			row := model.ConnectionLog{
				OrganizationID: dev.OrganizationID,
				DeviceID:       dev.ID,
				RustdeskID:     p.ID,
				ConnID:         p.ConnID,
				SessionID:      p.SessionID,
				IP:             p.IP,
				Status:         model.ConnectionLogStatusClosed,
				StartedAt:      now,
				EndedAt:        &now,
				ConnAuditRef:   p.ConnAuditRef,
				CreatedAt:      now,
				UpdatedAt:      now,
			}
			// Two concurrent closes both see zero open rows; the unique
			// identity index turns the loser into a no-op instead of a 500.
			return store.WithoutTenantScope(tx).
				Clauses(clause.OnConflict{DoNothing: true}).Create(&row).Error
		}
	})
}

// appendNote attaches the controller's note to the most recent open connection
// of that session. The client sends no uuid here, so the session identity is
// all we have; an unmatched note is dropped rather than guessed onto a row.
func (i *Ingest) appendNote(ctx context.Context, p ConnPayload) error {
	note := strings.TrimSpace(p.Note)
	if note == "" {
		return nil
	}
	// Resolve the device first: without it there is no organization to scope
	// the update to, and an unscoped write by (rustdesk_id, session_id) would
	// let an unauthenticated caller append text to another tenant's evidence.
	var candidates []model.Device
	if err := store.WithoutTenantScope(i.db.WithContext(ctx)).
		Where("rustdesk_id = ?", p.ID).Find(&candidates).Error; err != nil {
		return err
	}
	switch len(candidates) {
	case 0:
		return ErrUnknownDevice
	case 1:
	default:
		// The same id bound in two organizations is not a guess we are willing
		// to make: fail closed instead of picking a tenant.
		return ErrAmbiguousDevice
	}
	dev := candidates[0]
	scope := store.ScopedByOrg(i.db.WithContext(ctx), dev.OrganizationID)

	var row model.ConnectionLog
	err := scope.Where("device_id = ? AND session_id = ? AND status = ?",
		dev.ID, p.SessionID, model.ConnectionLogStatusOpen).
		Order("id DESC").First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	combined := note
	if row.Note != "" {
		combined = row.Note + "; " + note
	}
	combined = truncateRunes(combined, maxNoteLen)
	return scope.Model(&model.ConnectionLog{}).
		Where("id = ?", row.ID).
		Updates(map[string]any{"note": combined, "updated_at": i.now().UTC()}).Error
}

// truncateRunes cuts on a rune boundary: a byte cut can split a multi-byte
// character, which PostgreSQL rejects outright and SQLite stores as garbage.
func truncateRunes(v string, limit int) string {
	if len(v) <= limit {
		return v
	}
	runes := []rune(v)
	if len(runes) <= limit {
		return v
	}
	return string(runes[:limit])
}

// Field bounds mirror the column widths; an over-long value would otherwise
// surface as a 500 from the database instead of a 400 to the client.
func validateConnPayload(p ConnPayload) error {
	if len(p.ID) > 64 || len(p.UUID) > 128 || len(p.Nonce) > 64 ||
		len(p.IP) > 64 || len(p.ConnAuditRef) > 128 ||
		utf8.RuneCountInString(p.Note) > maxNoteLen {
		return ErrMalformed
	}
	return nil
}

func validateFilePayload(p FilePayload) error {
	if len(p.ID) > 64 || len(p.UUID) > 128 || len(p.Nonce) > 64 ||
		len(p.PeerID) > 64 {
		return ErrMalformed
	}
	return nil
}

func validateAlarmPayload(p AlarmPayload) error {
	if len(p.ID) > 64 || len(p.UUID) > 128 || len(p.Nonce) > 64 || len(p.ConnAuditRef) > 128 {
		return ErrMalformed
	}
	return nil
}

// File stores one transfer report. The info blob is kept verbatim and only read
// for the fields the console lists; unparsable info is still stored.
func (i *Ingest) File(ctx context.Context, p FilePayload) (bool, error) {
	if p.ID == "" || p.Nonce == "" {
		return false, ErrMalformed
	}
	if err := validateFilePayload(p); err != nil {
		return false, err
	}
	dev, err := i.resolveDevice(ctx, p.ID, p.UUID)
	if err != nil {
		return false, err
	}
	return i.withNonce(ctx, dev.OrganizationID, p.Nonce, func(tx *gorm.DB) error {
		direction := "send"
		if p.Type == 1 {
			direction = "receive"
		}
		var meta struct {
			IP    string          `json:"ip"`
			Name  string          `json:"name"`
			Num   int             `json:"num"`
			Files json.RawMessage `json:"files"`
		}
		_ = json.Unmarshal([]byte(p.Info), &meta)
		if len(meta.Name) > 128 || len(meta.IP) > 64 {
			return ErrMalformed
		}
		filesJSON := "[]"
		if len(meta.Files) > 0 {
			filesJSON = string(meta.Files)
		}
		row := model.FileLog{
			OrganizationID: dev.OrganizationID,
			DeviceID:       dev.ID,
			RustdeskID:     p.ID,
			PeerID:         p.PeerID,
			ConnID:         p.ConnID,
			Direction:      direction,
			Path:           p.Path,
			IsFile:         p.IsFile,
			FileCount:      meta.Num,
			FilesJSON:      filesJSON,
			InfoJSON:       p.Info,
			IP:             meta.IP,
			Name:           meta.Name,
			CreatedAt:      i.now().UTC(),
		}
		return store.WithoutTenantScope(tx).Create(&row).Error
	})
}

// Alarm records a client security alarm as an audit entry. It uses the
// transactional recorder so the nonce and the audit row commit together: a
// half-applied alarm would be deduplicated away on the client's retry.
func (i *Ingest) Alarm(ctx context.Context, p AlarmPayload) (bool, error) {
	if p.ID == "" || p.Nonce == "" {
		return false, ErrMalformed
	}
	if err := validateAlarmPayload(p); err != nil {
		return false, err
	}
	dev, err := i.resolveDevice(ctx, p.ID, p.UUID)
	if err != nil {
		return false, err
	}
	recorder, ok := i.auditor.(audit.TxRecorder)
	if !ok || recorder == nil {
		return false, ErrUnaudited
	}
	return i.withNonce(ctx, dev.OrganizationID, p.Nonce, func(tx *gorm.DB) error {
		return recorder.RecordTx(tx, audit.Entry{
			OrganizationID: dev.OrganizationID,
			Action:         alarmAction(p.Typ),
			TargetType:     "device",
			TargetID:       dev.RustdeskID,
			Detail: map[string]any{
				"typ":            p.Typ,
				"conn_id":        p.ConnID,
				"info":           p.Info,
				"conn_audit_ref": p.ConnAuditRef,
			},
		})
	})
}

// withNonce inserts the dedupe marker and the record in one transaction. A
// duplicate nonce means the client retried a request that already landed, so
// the call is an idempotent success.
func (i *Ingest) withNonce(ctx context.Context, orgID uint, nonce string, write func(tx *gorm.DB) error) (bool, error) {
	dedup := false
	err := i.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		marker := model.AuditNonce{OrganizationID: orgID, Nonce: nonce, CreatedAt: i.now().UTC()}
		res := store.WithoutTenantScope(tx).
			Clauses(clause.OnConflict{DoNothing: true}).Create(&marker)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			dedup = true
			return nil
		}
		return write(tx)
	})
	return dedup, err
}

// resolveDevice finds the device the report claims to come from. The rustdesk
// id is unique per organization, not globally, so every candidate row is
// compared against the presented uuid; no match means the report is either
// about an unknown device or an identity mismatch.
func (i *Ingest) resolveDevice(ctx context.Context, rustdeskID, uuid string) (model.Device, error) {
	var candidates []model.Device
	if err := store.WithoutTenantScope(i.db.WithContext(ctx)).
		Where("rustdesk_id = ?", rustdeskID).Find(&candidates).Error; err != nil {
		return model.Device{}, err
	}
	if len(candidates) == 0 {
		return model.Device{}, ErrUnknownDevice
	}
	if uuid == "" {
		return model.Device{}, ErrIdentityMismatch
	}
	var matched []model.Device
	for _, dev := range candidates {
		if dev.BoundUUID != "" && dev.BoundUUID == uuid {
			matched = append(matched, dev)
		}
	}
	switch len(matched) {
	case 0:
		return model.Device{}, ErrIdentityMismatch
	case 1:
		return matched[0], nil
	default:
		// Cloned images or restored backups can produce the same (id, uuid) in
		// two organizations; choosing one would be a cross-tenant write.
		return model.Device{}, ErrAmbiguousDevice
	}
}

// alarmTypes maps the client's AlarmAuditType enum to readable action suffixes.
// Unknown values keep their number instead of being dropped.
var alarmTypes = map[int]string{
	0:  "ip_whitelist",
	1:  "exceed_thirty_attempts",
	2:  "six_attempts_within_one_minute",
	6:  "exceed_ipv6_prefix_attempts",
	7:  "terminal_os_login_backoff",
	8:  "terminal_os_login_concurrency",
	9:  "session_scope_violation",
	10: "id_whitelist",
}

func alarmAction(typ int) string {
	if name, ok := alarmTypes[typ]; ok {
		return "client.alarm." + name
	}
	return fmt.Sprintf("client.alarm.type_%d", typ)
}

// SweepNonces deletes dedupe markers older than the retention window. The
// upstream API server remembers a nonce for five minutes and the client retries
// for at most two, so a ten-minute window never drops a live marker while
// keeping the table bounded.
func (i *Ingest) SweepNonces(ctx context.Context, now time.Time, olderThan time.Duration) (int64, error) {
	cutoff := now.UTC().Add(-olderThan)
	res := store.WithoutTenantScope(i.db.WithContext(ctx)).
		Where("created_at < ?", cutoff).Delete(&model.AuditNonce{})
	return res.RowsAffected, res.Error
}

// SweepChallenges deletes expired second-factor challenges. They are minted on
// every password step of an account with TOTP, so without a sweep the table
// grows with login attempts.
func SweepChallenges(db *gorm.DB, now time.Time) (int64, error) {
	res := store.WithoutTenantScope(db).Where("expires_at < ?", now.Add(-time.Hour)).
		Delete(&model.CompatLoginChallenge{})
	return res.RowsAffected, res.Error
}
