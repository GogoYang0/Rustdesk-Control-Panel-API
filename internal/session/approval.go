package session

import (
	"context"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/audit"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// ErrApprovalNotFound reports an approval id that does not exist in this
// organization. A decision or lookup across tenants gets the same error: 404,
// never a leak.
var ErrApprovalNotFound = errors.New("approval not found")

// The contract caps a request or decision reason at 500 characters.
const maxApprovalReasonLen = 500

// Decision values from the contract. They are deliberately distinct from the
// stored statuses ("approved"/"denied"): the client sends approve/deny, the
// row keeps approved/denied.
const (
	DecisionApprove = "approve"
	DecisionDeny    = "deny"
)

// decisionToStatus maps a wire decision onto the stored status.
func decisionToStatus(decision string) string {
	if decision == DecisionApprove {
		return model.ApprovalStatusApproved
	}
	return model.ApprovalStatusDenied
}

// ApprovalCreateInput carries the contract's creation request. Exactly one of
// DeviceID (pre_approval) or SessionID (ratification) is allowed, matching the
// kind — anything else is rejected before the database is touched.
type ApprovalCreateInput struct {
	Kind      string
	DeviceID  uint
	SessionID *uint
	Reason    *string
}

func (in ApprovalCreateInput) validate() error {
	if in.Reason != nil && utf8.RuneCountInString(*in.Reason) > maxApprovalReasonLen {
		return fmt.Errorf("%w: reason must be at most %d characters", ErrInvalidInput, maxApprovalReasonLen)
	}
	switch in.Kind {
	case model.ApprovalKindPre:
		if in.DeviceID == 0 {
			return fmt.Errorf("%w: device_id is required for a pre-approval", ErrInvalidInput)
		}
		if in.SessionID != nil {
			return fmt.Errorf("%w: a pre-approval must not carry session_id", ErrInvalidInput)
		}
	case model.ApprovalKindRatification:
		if in.SessionID == nil || *in.SessionID == 0 {
			return fmt.Errorf("%w: session_id is required for a ratification", ErrInvalidInput)
		}
		if in.DeviceID != 0 {
			// The device comes from the session row server-side; a
			// client-supplied one could point the acknowledgement at another
			// device than the one the session actually touched.
			return fmt.Errorf("%w: device_id is derived from the session and must not be supplied", ErrInvalidInput)
		}
	default:
		return fmt.Errorf("%w: unknown approval kind %q", ErrInvalidInput, in.Kind)
	}
	return nil
}

// ApprovalFilter narrows the approval inbox. All fields are optional.
type ApprovalFilter struct {
	Status   *string
	DeviceID *uint
	Page     int
	PageSize int
}

// NormalisedPagination applies the same clamping rules as the session listing.
func (f ApprovalFilter) NormalisedPagination() (page, pageSize int) {
	return normalisePage(f.Page, f.PageSize)
}

// CreateApproval submits an approval request.
//
// Reuse is the contract's deduplication rule, evaluated per kind:
//
//   - pre_approval: the same actor+device still has a pending, unexpired
//     request → that row is returned (200 at the HTTP layer). An expired
//     pending row is dead — no one can approve it — so a fresh one is created.
//   - ratification: the same session already has a pending or approved
//     acknowledgement → that row is returned. The session must belong to this
//     organization and be origin=native (panel sessions are policy-governed
//     already), and the device is derived from the session row.
//
// Both paths serialise on the organization row, so two concurrent submissions
// cannot both miss the existing row and create duplicates.
func (s *Service) CreateApproval(ctx context.Context, orgID, actorID uint, in ApprovalCreateInput) (*model.Approval, bool, error) {
	if orgID == 0 || actorID == 0 {
		return nil, false, fmt.Errorf("%w: organization and actor are required", ErrInvalidInput)
	}
	if err := in.validate(); err != nil {
		return nil, false, err
	}

	var (
		created model.Approval
		reused  bool
	)
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Same serialisation as the pending-approval creation inside Issue:
		// without the lock two concurrent submissions both miss the existing
		// row and both insert.
		if err := lockOrganization(tx, orgID); err != nil {
			return err
		}

		now := s.now().UTC()
		deviceID := in.DeviceID
		var sessionID *uint

		if in.Kind == model.ApprovalKindPre {
			// The device must exist in this organization: an approval for a
			// phantom or foreign device could never be consumed (issuance
			// verifies the device first) and would pollute the inbox.
			if _, err := s.loadDevice(tx, orgID, in.DeviceID); err != nil {
				return err
			}

			var existing model.Approval
			err := store.ScopedByOrg(tx, orgID).
				Where("actor_user_id = ? AND device_id = ? AND kind = ? AND status = ? AND expires_at > ?",
					actorID, in.DeviceID, model.ApprovalKindPre, model.ApprovalStatusPending, now).
				Order("id").
				First(&existing).Error
			if err == nil {
				created = existing
				reused = true
				return nil
			}
			if !errors.Is(err, gorm.ErrRecordNotFound) {
				return fmt.Errorf("load pending pre-approval: %w", err)
			}
		} else {
			// Ratification: the session is the source of truth for the device,
			// and only native sessions are ratifiable at all.
			sessID := *in.SessionID
			var sess model.Session
			err := store.ScopedByOrg(tx, orgID).Where("id = ?", sessID).First(&sess).Error
			if err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					// Same error for missing and foreign sessions: a 404 here
					// would let a caller probe which session ids exist.
					return fmt.Errorf("%w: session %d is not a native session of this organization", ErrInvalidInput, sessID)
				}
				return fmt.Errorf("load session: %w", err)
			}
			if sess.Origin != model.SessionOriginNative {
				return fmt.Errorf("%w: only native sessions can be ratified (session %d is a panel session)", ErrInvalidInput, sessID)
			}
			deviceID = sess.DeviceID
			sessionID = &sessID

			// An approved acknowledgement is reused unconditionally: the fact
			// is acknowledged and stays so. A pending one is only reused while
			// it is still actionable — same reasoning as the pre-approval path,
			// an expired pending row is dead and reusing it would loop the
			// client between this 200 and the decision's 409.
			var existing model.Approval
			err = store.ScopedByOrg(tx, orgID).
				Where("session_id = ? AND kind = ? AND status = ?",
					sessID, model.ApprovalKindRatification, model.ApprovalStatusApproved).
				Order("id").
				First(&existing).Error
			if err == nil {
				created = existing
				reused = true
				return nil
			}
			if !errors.Is(err, gorm.ErrRecordNotFound) {
				return fmt.Errorf("load approved ratification: %w", err)
			}
			err = store.ScopedByOrg(tx, orgID).
				Where("session_id = ? AND kind = ? AND status = ? AND expires_at > ?",
					sessID, model.ApprovalKindRatification, model.ApprovalStatusPending, now).
				Order("id").
				First(&existing).Error
			if err == nil {
				created = existing
				reused = true
				return nil
			}
			if !errors.Is(err, gorm.ErrRecordNotFound) {
				return fmt.Errorf("load existing ratification: %w", err)
			}
		}

		row := model.Approval{
			OrganizationID: orgID,
			DeviceID:       deviceID,
			Kind:           in.Kind,
			SessionID:      sessionID,
			ActorUserID:    actorID,
			Status:         model.ApprovalStatusPending,
			RequestedAt:    now,
			ExpiresAt:      now.Add(approvalTTL),
			Reason:         in.Reason,
			CreatedAt:      now,
		}
		if err := tx.Create(&row).Error; err != nil {
			return fmt.Errorf("create approval: %w", err)
		}
		created = row
		// A new request is a domain mutation an approver must act on, so it is
		// audited. A reuse is not a new fact and is not audited twice.
		return s.record(tx, audit.Entry{
			OrganizationID: orgID,
			ActorUserID:    actorID,
			Action:         "session.approval.request",
			TargetType:     "approval",
			TargetID:       fmt.Sprint(row.ID),
			Detail: map[string]any{
				"kind":       row.Kind,
				"device_id":  row.DeviceID,
				"session_id": sessionID,
			},
		})
	})
	if err != nil {
		return nil, false, err
	}
	return &created, reused, nil
}

// DecideApproval records an approver's decision on a pending request.
//
// Only pending requests are actionable: an expired one must not be approved
// even before the background sweep marks it, so the deadline is checked here.
// The conditional update makes the decision one-shot under concurrency — two
// approvers clicking together cannot both win.
//
// Approving never issues anything: the contract makes approval a permission to
// issue one ticket (consumed at issuance), and a ratification approval only
// acknowledges a fact. The reason, when the decision carries one, overwrites
// the request's reason — the contract has a single field and names it
// "request reason or rejection reason".
func (s *Service) DecideApproval(ctx context.Context, orgID, approvalID, approverID uint, decision string, reason *string) (*model.Approval, error) {
	if orgID == 0 || approvalID == 0 || approverID == 0 {
		return nil, fmt.Errorf("%w: organization, approval and approver are required", ErrInvalidInput)
	}
	if decision != DecisionApprove && decision != DecisionDeny {
		return nil, fmt.Errorf("%w: decision must be approve or deny", ErrInvalidInput)
	}
	if reason != nil && utf8.RuneCountInString(*reason) > maxApprovalReasonLen {
		return nil, fmt.Errorf("%w: reason must be at most %d characters", ErrInvalidInput, maxApprovalReasonLen)
	}

	var decided model.Approval
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := lockOrganization(tx, orgID); err != nil {
			return err
		}

		var approval model.Approval
		if err := store.ScopedByOrg(tx, orgID).Where("id = ?", approvalID).First(&approval).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrApprovalNotFound
			}
			return fmt.Errorf("load approval: %w", err)
		}
		now := s.now().UTC()
		if approval.Status != model.ApprovalStatusPending {
			return fmt.Errorf("%w: the approval has already been decided (status %s)", ErrConflict, approval.Status)
		}
		if !approval.ExpiresAt.After(now) {
			return fmt.Errorf("%w: the approval has expired", ErrConflict)
		}

		updates := map[string]any{
			"status":     decisionToStatus(decision),
			"decided_by": approverID,
			"decided_at": now,
			// The sweep marks expired rows; until it runs the row above still
			// reads pending, so the write must re-check it to stay one-shot.
			"updated_at": now,
		}
		if reason != nil {
			updates["reason"] = *reason
		}
		res := store.ScopedByOrg(tx, orgID).
			Model(&model.Approval{}).
			Where("id = ? AND status = ?", approvalID, model.ApprovalStatusPending).
			Updates(updates)
		if res.Error != nil {
			return fmt.Errorf("record decision: %w", res.Error)
		}
		if res.RowsAffected != 1 {
			return fmt.Errorf("%w: the approval is no longer pending", ErrConflict)
		}

		// Re-read inside the transaction so the response shows the row as
		// committed. A second read after the commit could hit a cancelled
		// context and turn a successful decision into a 500, which the client
		// would retry into a 409.
		if err := store.ScopedByOrg(tx, orgID).Where("id = ?", approvalID).First(&decided).Error; err != nil {
			return fmt.Errorf("reload decided approval: %w", err)
		}

		return s.record(tx, audit.Entry{
			OrganizationID: orgID,
			ActorUserID:    approverID,
			Action:         "session.approval.decide",
			TargetType:     "approval",
			TargetID:       fmt.Sprint(approvalID),
			Detail: map[string]any{
				"decision":   decision,
				"kind":       approval.Kind,
				"device_id":  approval.DeviceID,
				"session_id": approval.SessionID,
			},
		})
	})
	if err != nil {
		return nil, err
	}
	return &decided, nil
}

// Approval returns one approval. The plaintext-free bookkeeping view, like
// tickets and policies.
func (s *Service) Approval(ctx context.Context, orgID, approvalID uint) (*model.Approval, error) {
	if orgID == 0 || approvalID == 0 {
		return nil, fmt.Errorf("%w: organization and approval are required", ErrInvalidInput)
	}
	var approval model.Approval
	err := store.ScopedByOrg(s.db.WithContext(ctx), orgID).Where("id = ?", approvalID).First(&approval).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrApprovalNotFound
	}
	if err != nil {
		return nil, err
	}
	return &approval, nil
}

// ListApprovals returns one page of the organization's approval requests plus
// the total under the current filter. Ordering is requested_at descending with
// id as the tiebreaker, so the newest request is first and ties do not reorder
// between pages.
func (s *Service) ListApprovals(ctx context.Context, orgID uint, f ApprovalFilter) ([]model.Approval, int64, error) {
	if orgID == 0 {
		return nil, 0, fmt.Errorf("%w: organization is required", ErrInvalidInput)
	}
	page, pageSize := f.NormalisedPagination()

	query := store.ScopedByOrg(s.db.WithContext(ctx), orgID).Model(&model.Approval{})
	if f.Status != nil {
		query = query.Where("status = ?", *f.Status)
	}
	if f.DeviceID != nil {
		query = query.Where("device_id = ?", *f.DeviceID)
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("count approvals: %w", err)
	}

	var items []model.Approval
	if err := query.
		Order("requested_at DESC").
		Order("id DESC").
		Offset((page - 1) * pageSize).
		Limit(pageSize).
		Find(&items).Error; err != nil {
		return nil, 0, fmt.Errorf("list approvals: %w", err)
	}
	return items, total, nil
}

// ExpirePendingApprovals flips overdue pending requests to expired and returns
// how many rows changed. It runs on the background scheduler, so it is always
// cross-tenant: the caller's handle is wrapped in WithoutTenantScope by design.
//
// The sweep writes no audit rows: a status flip to expired is system
// bookkeeping (the request was simply not answered in time), it is visible in
// the row itself, and the scheduler logs the changed count — auditing one row
// per expiry would bury the decision audit trail under scheduler noise.
func (s *Service) ExpirePendingApprovals(ctx context.Context, now time.Time) (int64, error) {
	res := store.WithoutTenantScope(s.db.WithContext(ctx)).
		Model(&model.Approval{}).
		Where("status = ? AND expires_at <= ?", model.ApprovalStatusPending, now.UTC()).
		Update("status", model.ApprovalStatusExpired)
	if res.Error != nil {
		return 0, fmt.Errorf("expire approvals: %w", res.Error)
	}
	return res.RowsAffected, nil
}
