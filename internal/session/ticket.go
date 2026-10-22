package session

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/audit"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// Domain errors. Every ticket state that prevents redemption collapses into
// ErrConflict on purpose: the contract returns one 409 so a caller cannot probe
// which condition failed (expired? already used? revoked?).
var (
	ErrInvalidInput   = errors.New("invalid ticket input")
	ErrDeviceNotFound = errors.New("device not found")
	ErrTicketNotFound = errors.New("ticket not found")
	ErrOutsideWindow  = errors.New("outside the allowed connection window")
	ErrConflict       = errors.New("ticket cannot be redeemed")
)

// Ticket lifetime bounds from the contract.
const (
	defaultTTLSeconds = 300
	minTTLSeconds     = 30
	maxTTLSeconds     = 900
)

// approvalTTL bounds how long a pending approval stays actionable. The contract
// fixes it at "request time + 15 minutes": an approval is a short-lived gateway
// ("may I connect now?"), not a standing permission.
const approvalTTL = 15 * time.Minute

// ErrApprovalRequired reports that policy demands prior approval; the client
// routes the user to the inbox and retries issuance afterwards.
type ErrApprovalRequired struct {
	ApprovalID uint
}

func (e *ErrApprovalRequired) Error() string {
	return "approval required before issuing a ticket"
}

// IssueInput carries the contract's issuance request.
type IssueInput struct {
	OrganizationID uint
	ActorUserID    uint
	DeviceID       uint
	// TTLSeconds overrides the default lifetime; nil means defaultTTLSeconds.
	TTLSeconds *int64
}

// Service owns tickets and panel sessions.
type Service struct {
	db       *gorm.DB
	recorder audit.TxRecorder
	now      func() time.Time
}

// NewService wires the service. recorder may be nil in tests that do not audit;
// production always injects one, because an unaudited ticket or session is worse
// than a refused request.
func NewService(db *gorm.DB, recorder audit.TxRecorder, now func() time.Time) *Service {
	return &Service{db: db, recorder: recorder, now: now}
}

// errNeedsApproval is an internal sentinel: the approval has to be created (and
// committed) outside the ticket transaction, otherwise rolling that transaction
// back would discard the very approval the user is asked to act on.
var errNeedsApproval = errors.New("issue: approval required")

// Issue creates a one-shot connection ticket.
//
// Only the window and the approval requirement are evaluated here. Concurrency
// and duration cannot be: issuance creates no session, so a concurrency count
// would always read zero, and duration is a post-hoc close (the panel is not in
// the signalling path).
func (s *Service) Issue(ctx context.Context, in IssueInput) (model.Ticket, string, error) {
	if in.OrganizationID == 0 || in.ActorUserID == 0 || in.DeviceID == 0 {
		return model.Ticket{}, "", fmt.Errorf("%w: organization, actor and device are required", ErrInvalidInput)
	}
	ttl := int64(defaultTTLSeconds)
	if in.TTLSeconds != nil {
		ttl = *in.TTLSeconds
		if ttl < minTTLSeconds || ttl > maxTTLSeconds {
			return model.Ticket{}, "", fmt.Errorf("%w: ttl_seconds must be between %d and %d", ErrInvalidInput, minTTLSeconds, maxTTLSeconds)
		}
	}

	var (
		ticket model.Ticket
		token  string
		// outcome carries a domain refusal out of the transaction. Returning it
		// from inside would roll back the denied session we just recorded, and a
		// refused attempt is exactly the record an auditor wants.
		outcome error
	)
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		dev, err := s.loadDevice(tx, in.OrganizationID, in.DeviceID)
		if err != nil {
			return err
		}
		limits, err := s.limits(tx, in.OrganizationID)
		if err != nil {
			return err
		}

		now := s.now().UTC()
		if !limits.WithinWindow(now) {
			// A denied attempt is exactly what an auditor wants to see, so it is
			// recorded — but as a closed row, so it occupies no concurrency slot.
			if err := s.recordDenied(tx, in, dev, now); err != nil {
				return err
			}
			outcome = ErrOutsideWindow
			return nil
		}

		var approvalID *uint
		if limits.RequireApproval {
			approved, ok, err := s.usableApproval(tx, in, now)
			if err != nil {
				return err
			}
			if !ok {
				return errNeedsApproval
			}
			approvalID = &approved
		}

		token, err = newToken()
		if err != nil {
			return err
		}
		snapshot, err := json.Marshal(limits.Snapshot())
		if err != nil {
			return fmt.Errorf("marshal policy snapshot: %w", err)
		}

		ticket = model.Ticket{
			OrganizationID:     in.OrganizationID,
			DeviceID:           in.DeviceID,
			ActorUserID:        in.ActorUserID,
			ApprovalID:         approvalID,
			TokenHash:          hashToken(token),
			PolicySnapshotJSON: string(snapshot),
			ExpiresAt:          now.Add(time.Duration(ttl) * time.Second),
			CreatedAt:          now,
		}
		if err := tx.Create(&ticket).Error; err != nil {
			return fmt.Errorf("create ticket: %w", err)
		}

		if approvalID != nil {
			// Consuming the approval is the one-to-one binding; the conditional
			// update means two concurrent issuances cannot both use it. The
			// status and expiry are re-checked here because the approval could
			// have been denied or have expired between the read and this write.
			res := store.ScopedByOrg(tx, in.OrganizationID).
				Model(&model.Approval{}).
				Where("id = ? AND ticket_id IS NULL AND status = ? AND expires_at > ?",
					*approvalID, model.ApprovalStatusApproved, now).
				Update("ticket_id", ticket.ID)
			if res.Error != nil {
				return fmt.Errorf("consume approval: %w", res.Error)
			}
			if res.RowsAffected != 1 {
				return fmt.Errorf("%w: the approval is no longer usable, request a new one", ErrConflict)
			}
		}

		return s.record(tx, audit.Entry{
			OrganizationID: in.OrganizationID,
			ActorUserID:    in.ActorUserID,
			Action:         "session.ticket.issue",
			TargetType:     "ticket",
			TargetID:       fmt.Sprint(ticket.ID),
			Detail: map[string]any{
				"device_id":   in.DeviceID,
				"expires_at":  ticket.ExpiresAt,
				"approval_id": approvalID,
			},
		})
	})

	if errors.Is(err, errNeedsApproval) {
		// Separate transaction: the pending approval must survive the rejected
		// issuance, because it is what the user is being asked to act on.
		id, err := s.ensurePendingApproval(ctx, in)
		if err != nil {
			return model.Ticket{}, "", err
		}
		return model.Ticket{}, "", &ErrApprovalRequired{ApprovalID: id}
	}
	if err != nil {
		return model.Ticket{}, "", err
	}
	if outcome != nil {
		return model.Ticket{}, "", outcome
	}
	return ticket, token, nil
}

// Redeem consumes a ticket and creates the panel session it authorises.
//
// This is the only creator of open panel sessions and therefore the real
// concurrency gate: issuance cannot enforce a limit it cannot observe.
func (s *Service) Redeem(ctx context.Context, orgID, actorID, ticketID uint, token string) (*model.Session, error) {
	if orgID == 0 || actorID == 0 || ticketID == 0 || token == "" {
		return nil, fmt.Errorf("%w: organization, actor, ticket and token are required", ErrInvalidInput)
	}

	var (
		sess *model.Session
		// outcome carries a refusal out of the transaction: returning it
		// directly would roll back the alert the refusal just wrote.
		outcome error
	)
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Serialise redemptions per organization. One transaction is not enough:
		// under READ COMMITTED two redemptions each read the old count, each
		// pass, and each insert, so the quota would be decorative.
		//
		// SELECT ... FOR UPDATE is portable here because the SQLite dialect
		// simply omits the clause (it serialises writers anyway) while MySQL and
		// PostgreSQL take the row lock. The previous no-op UPDATE was not
		// portable: MySQL reports 0 affected rows when the value does not change,
		// which turned every redemption into a 404 there.
		//
		// The count below is safe because its snapshot is established *after* the
		// lock is granted: MySQL's locking read sees the latest committed rows
		// even inside an older REPEATABLE READ snapshot, and PostgreSQL's default
		// READ COMMITTED sees them per statement. This holds as long as neither
		// database is switched to a stricter isolation level (PostgreSQL
		// REPEATABLE READ would let a second transaction's plain count miss the
		// first one's insert, since the organization row itself is never
		// updated) — the store does not set one.
		var org model.Organization
		err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("id = ?", orgID).
			First(&org).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrTicketNotFound
		}
		if err != nil {
			return fmt.Errorf("lock organization: %w", err)
		}

		var ticket model.Ticket
		if err := store.ScopedByOrg(tx, orgID).Where("id = ?", ticketID).First(&ticket).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrTicketNotFound
			}
			return err
		}

		// Constant-time comparison: a timing oracle here would let a caller
		// recover the digest byte by byte.
		if subtle.ConstantTimeCompare([]byte(hashToken(token)), []byte(ticket.TokenHash)) != 1 {
			return ErrConflict
		}
		now := s.now().UTC()
		if ticket.UsedAt != nil || ticket.RevokedAt != nil || !ticket.ExpiresAt.After(now) {
			return ErrConflict
		}

		limits, err := s.limits(tx, orgID)
		if err != nil {
			return err
		}
		// The window can close between issuance and redemption, so it is
		// re-checked instead of trusted from the ticket.
		if !limits.WithinWindow(now) {
			return fmt.Errorf("%w: outside the allowed connection window", ErrConflict)
		}
		if limits.MaxConcurrent != nil {
			var open int64
			if err := store.ScopedByOrg(tx, orgID).Model(&model.Session{}).
				Where("status = ? AND origin = ?", model.SessionStatusOpen, model.SessionOriginPanel).
				Count(&open).Error; err != nil {
				return err
			}
			if open >= *limits.MaxConcurrent {
				// The contract lists the refused redemption as a
				// concurrency_exceeded alert source. It must be written here,
				// inside the transaction that is about to commit, with the
				// refusal carried out via outcome — returning it directly
				// would roll back the very alert the operator should see.
				if err := s.recordAlert(tx, orgID, nil, &ticket.DeviceID,
					model.AlertKindConcurrencyExceeded, model.AlertSeverityWarning, map[string]any{
						"limit":     *limits.MaxConcurrent,
						"open":      open,
						"ticket_id": ticketID,
					}); err != nil {
					return err
				}
				outcome = fmt.Errorf("%w: concurrent session limit reached", ErrConflict)
				return nil
			}
		}

		// Atomic claim: this conditional update is what makes the ticket
		// one-shot even when two requests arrive together.
		claim := store.ScopedByOrg(tx, orgID).Model(&model.Ticket{}).
			Where("id = ? AND used_at IS NULL AND revoked_at IS NULL AND expires_at > ?", ticketID, now).
			Update("used_at", now)
		if claim.Error != nil {
			return fmt.Errorf("claim ticket: %w", claim.Error)
		}
		if claim.RowsAffected != 1 {
			return ErrConflict
		}

		dev, err := s.loadDevice(tx, orgID, ticket.DeviceID)
		if err != nil {
			return err
		}
		policyID, err := s.attributedPolicyID(tx, orgID)
		if err != nil {
			return err
		}

		// The session is attributed to the actor the ticket was issued to, not
		// to whoever redeemed it. Otherwise a colleague redeeming someone else's
		// token would appear as the session's initiator and the chain
		// policy → ticket → session would no longer line up; the redeemer is
		// recorded in the audit entry instead.
		issuer := ticket.ActorUserID
		row := model.Session{
			OrganizationID: orgID,
			DeviceID:       ticket.DeviceID,
			RustdeskID:     dev.RustdeskID,
			ActorUserID:    &issuer,
			Origin:         model.SessionOriginPanel,
			Status:         model.SessionStatusOpen,
			TicketID:       &ticketID,
			PolicyID:       policyID,
			StartedAt:      now,
			// Without an activity clock the idle sweeper would close every panel
			// session one idle window after redemption.
			LastActivityAt: &now,
		}
		if err := tx.Create(&row).Error; err != nil {
			return fmt.Errorf("create session: %w", err)
		}

		if err := s.record(tx, audit.Entry{
			OrganizationID: orgID,
			ActorUserID:    actorID,
			Action:         "session.ticket.redeem",
			TargetType:     "session",
			TargetID:       fmt.Sprint(row.ID),
			Detail: map[string]any{
				"ticket_id":         ticketID,
				"device_id":         ticket.DeviceID,
				"issued_to_user_id": ticket.ActorUserID,
				"redeemed_by":       actorID,
			},
		}); err != nil {
			return err
		}
		sess = &row
		return nil
	})
	if err != nil {
		return nil, err
	}
	if outcome != nil {
		return nil, outcome
	}
	return sess, nil
}

// Ticket returns the bookkeeping view of one ticket. The plaintext token is not
// recoverable: only its digest was ever stored.
func (s *Service) Ticket(ctx context.Context, orgID, ticketID uint) (*model.Ticket, error) {
	if orgID == 0 || ticketID == 0 {
		return nil, fmt.Errorf("%w: organization and ticket are required", ErrInvalidInput)
	}
	var ticket model.Ticket
	err := store.ScopedByOrg(s.db.WithContext(ctx), orgID).Where("id = ?", ticketID).First(&ticket).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrTicketNotFound
	}
	if err != nil {
		return nil, err
	}
	return &ticket, nil
}

// limits folds the organization's enabled policies into one effective policy.
func (s *Service) limits(tx *gorm.DB, orgID uint) (Limits, error) {
	policies, err := s.enabledPolicies(tx, orgID)
	if err != nil {
		return Limits{}, err
	}
	return Effective(policies), nil
}

func (s *Service) enabledPolicies(tx *gorm.DB, orgID uint) ([]model.Policy, error) {
	var policies []model.Policy
	if err := store.ScopedByOrg(tx, orgID).Where("enabled = ?", true).Find(&policies).Error; err != nil {
		return nil, fmt.Errorf("load policies: %w", err)
	}
	return policies, nil
}

// attributedPolicyID returns the policy id recorded on a session: the enabled
// policy with the smallest id, or nil when the organization has none.
//
// The contract specifies exactly that. With several policies the effective
// limit is a fold, so no single row fully explains it — the smallest id is the
// stable attribution, and the ticket's snapshot carries the details.
func (s *Service) attributedPolicyID(tx *gorm.DB, orgID uint) (*uint, error) {
	var policies []model.Policy
	if err := store.ScopedByOrg(tx, orgID).
		Where("enabled = ?", true).
		Order("id").
		Limit(1).
		Find(&policies).Error; err != nil {
		return nil, fmt.Errorf("load policies: %w", err)
	}
	if len(policies) == 0 {
		return nil, nil
	}
	id := policies[0].ID
	return &id, nil
}

func (s *Service) loadDevice(tx *gorm.DB, orgID, deviceID uint) (*model.Device, error) {
	var dev model.Device
	err := store.ScopedByOrg(tx, orgID).Where("id = ?", deviceID).First(&dev).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrDeviceNotFound
	}
	if err != nil {
		return nil, err
	}
	return &dev, nil
}

// usableApproval finds an approved, unconsumed, unexpired pre-approval for this
// actor and device.
func (s *Service) usableApproval(tx *gorm.DB, in IssueInput, now time.Time) (uint, bool, error) {
	var approval model.Approval
	err := store.ScopedByOrg(tx, in.OrganizationID).
		Where("actor_user_id = ? AND device_id = ? AND kind = ? AND status = ? AND ticket_id IS NULL AND expires_at > ?",
			in.ActorUserID, in.DeviceID, model.ApprovalKindPre, model.ApprovalStatusApproved, now).
		Order("id").
		First(&approval).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("load approval: %w", err)
	}
	return approval.ID, true, nil
}

// ensurePendingApproval creates the approval request the user must act on, or
// reuses the pending one so retries do not fill the inbox with duplicates.
func (s *Service) ensurePendingApproval(ctx context.Context, in IssueInput) (uint, error) {
	var id uint
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Serialise on the organization: two concurrent issuances would
		// otherwise both miss the pending row and create two, filling the
		// approval inbox with duplicates of the same request.
		var org model.Organization
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("id = ?", in.OrganizationID).First(&org).Error; err != nil {
			return fmt.Errorf("lock organization: %w", err)
		}

		now := s.now().UTC()
		var existing model.Approval
		// An expired pending row must not be reused: approving it is impossible,
		// so every retry would hand back the same dead id and the client would
		// loop between "approval required" and "approval expired".
		err := store.ScopedByOrg(tx, in.OrganizationID).
			Where("actor_user_id = ? AND device_id = ? AND kind = ? AND status = ? AND expires_at > ?",
				in.ActorUserID, in.DeviceID, model.ApprovalKindPre, model.ApprovalStatusPending, now).
			Order("id").
			First(&existing).Error
		if err == nil {
			id = existing.ID
			return nil
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("load pending approval: %w", err)
		}

		row := model.Approval{
			OrganizationID: in.OrganizationID,
			DeviceID:       in.DeviceID,
			Kind:           model.ApprovalKindPre,
			ActorUserID:    in.ActorUserID,
			Status:         model.ApprovalStatusPending,
			RequestedAt:    now,
			ExpiresAt:      now.Add(approvalTTL),
			CreatedAt:      now,
		}
		if err := tx.Create(&row).Error; err != nil {
			return fmt.Errorf("create approval: %w", err)
		}
		id = row.ID
		// Creating the approval is a domain mutation, so it is audited in its
		// transaction. The refusal that triggered it is a normal controlled
		// path (api-spec 3.6: blocks are not alerts) — but "not an alert" is not
		// "not recorded".
		return s.record(tx, audit.Entry{
			OrganizationID: in.OrganizationID,
			ActorUserID:    in.ActorUserID,
			Action:         "session.approval.request",
			TargetType:     "approval",
			TargetID:       fmt.Sprint(row.ID),
			Detail:         map[string]any{"device_id": in.DeviceID, "kind": row.Kind},
		})
	})
	if err != nil {
		return 0, err
	}
	return id, nil
}

// recordDenied writes the trail for a policy refusal: a closed session row with
// no ticket, which the contract defines as the denied state.
func (s *Service) recordDenied(tx *gorm.DB, in IssueInput, dev *model.Device, now time.Time) error {
	reason := model.SessionEndPolicyDenied
	actor := in.ActorUserID
	row := model.Session{
		OrganizationID: in.OrganizationID,
		DeviceID:       in.DeviceID,
		RustdeskID:     dev.RustdeskID,
		ActorUserID:    &actor,
		Origin:         model.SessionOriginPanel,
		Status:         model.SessionStatusDenied,
		StartedAt:      now,
		EndedAt:        &now,
		EndReason:      &reason,
	}
	if err := tx.Create(&row).Error; err != nil {
		return fmt.Errorf("record denied session: %w", err)
	}
	// The contract lists the refused issuance as an outside_window alert
	// source. Severity is info: the attempt was blocked, no connection
	// happened — unlike the native variant, which is a warning because that
	// connection is already running.
	if err := s.recordAlert(tx, in.OrganizationID, &row.ID, &in.DeviceID,
		model.AlertKindOutsideWindow, model.AlertSeverityInfo, map[string]any{
			"occurred_at": now,
			"actor":       actor,
		}); err != nil {
		return err
	}
	return s.record(tx, audit.Entry{
		OrganizationID: in.OrganizationID,
		ActorUserID:    in.ActorUserID,
		Action:         "session.ticket.denied",
		TargetType:     "device",
		TargetID:       fmt.Sprint(in.DeviceID),
		Detail:         map[string]any{"reason": model.SessionEndPolicyDenied},
	})
}

func (s *Service) record(tx *gorm.DB, entry audit.Entry) error {
	if s.recorder == nil {
		// Fail closed. A ticket or session that committed without an audit entry
		// cannot be reconstructed later, so a missing recorder is a wiring bug
		// that must surface at the first write rather than degrade quietly.
		return errors.New("session: no audit recorder configured")
	}
	if err := s.recorder.RecordTx(tx, entry); err != nil {
		return fmt.Errorf("record audit: %w", err)
	}
	return nil
}

// newToken returns a 256-bit URL-safe token. It is returned to the caller once
// and never stored: only hashToken(token) reaches the database.
func newToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate ticket token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// hashToken is the at-rest form of a ticket token.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
