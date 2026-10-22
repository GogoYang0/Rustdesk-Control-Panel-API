package session

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/audit"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// ErrPolicyNotFound reports a policy id that does not exist in this organization.
var ErrPolicyNotFound = errors.New("policy not found")

// ErrDuplicatePolicy is the contract's 409 for a name that already exists in the
// organization. It deliberately does not reuse ErrConflict: that sentinel reads
// "ticket cannot be redeemed", and a policy error must not borrow a ticket's
// wording.
var ErrDuplicatePolicy = errors.New("a policy with this name already exists in this organization")

// Field bounds from the contract and the column sizes.
const (
	maxPolicyNameLen = 128
	maxMinuteOfDay   = 1439
)

// PolicyInput carries a policy write.
//
// The two booleans are pointers on purpose. The generated contract type uses
// plain `bool`, which cannot tell "omitted" from `false` — and treating an
// omitted field as false would silently disable a policy or drop its approval
// requirement. The HTTP layer therefore reads presence from the raw payload and
// hands the service pointers; a nil here is a 400.
type PolicyInput struct {
	Name                  string
	Enabled               *bool
	RequireApproval       *bool
	MaxConcurrentSessions *int64
	MaxSessionMinutes     *int64
	AllowedStartMinute    *int64
	AllowedEndMinute      *int64
}

// validate applies the contract's write rules. Everything that is not a
// well-formed policy fails closed with ErrInvalidInput rather than being
// coerced, because a coerced value is a policy nobody configured.
func (in PolicyInput) validate() error {
	if strings.TrimSpace(in.Name) == "" {
		return fmt.Errorf("%w: name is required", ErrInvalidInput)
	}
	if len(in.Name) > maxPolicyNameLen {
		return fmt.Errorf("%w: name must be at most %d characters", ErrInvalidInput, maxPolicyNameLen)
	}
	if in.Enabled == nil || in.RequireApproval == nil {
		return fmt.Errorf("%w: enabled and require_approval are required", ErrInvalidInput)
	}
	for _, bound := range []struct {
		name  string
		value *int64
	}{
		{"max_concurrent_sessions", in.MaxConcurrentSessions},
		{"max_session_minutes", in.MaxSessionMinutes},
	} {
		if bound.value != nil && *bound.value < 1 {
			// Zero is not "unlimited": null is unlimited. Zero would mean "no
			// session may ever start", which the contract's minimum forbids.
			return fmt.Errorf("%w: %s must be at least 1", ErrInvalidInput, bound.name)
		}
	}

	start, end := in.AllowedStartMinute, in.AllowedEndMinute
	if (start == nil) != (end == nil) {
		return fmt.Errorf("%w: allowed_start_minute and allowed_end_minute must be provided together", ErrInvalidInput)
	}
	if start == nil {
		return nil // all day
	}
	for _, m := range []struct {
		name  string
		value int64
	}{
		{"allowed_start_minute", *start},
		{"allowed_end_minute", *end},
	} {
		if m.value < 0 || m.value > maxMinuteOfDay {
			return fmt.Errorf("%w: %s must be between 0 and %d", ErrInvalidInput, m.name, maxMinuteOfDay)
		}
	}
	if *start == *end {
		return fmt.Errorf("%w: start and end must differ; use null for all day", ErrInvalidInput)
	}
	return nil
}

// ListPolicies returns the organization's policies, oldest first.
func (s *Service) ListPolicies(ctx context.Context, orgID uint) ([]model.Policy, error) {
	var policies []model.Policy
	if err := store.ScopedByOrg(s.db.WithContext(ctx), orgID).
		Order("id").
		Find(&policies).Error; err != nil {
		return nil, fmt.Errorf("list policies: %w", err)
	}
	return policies, nil
}

// CreatePolicy writes a new policy. A duplicate name inside the organization is
// the contract's 409.
func (s *Service) CreatePolicy(ctx context.Context, orgID uint, in PolicyInput) (*model.Policy, error) {
	if orgID == 0 {
		return nil, fmt.Errorf("%w: organization is required", ErrInvalidInput)
	}
	if err := in.validate(); err != nil {
		return nil, err
	}

	var created model.Policy
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := policyNameTaken(tx, orgID, in.Name, 0); err != nil {
			return err
		}
		now := s.now().UTC()
		created = model.Policy{
			OrganizationID:        orgID,
			Name:                  in.Name,
			Enabled:               *in.Enabled,
			MaxConcurrentSessions: in.MaxConcurrentSessions,
			MaxSessionMinutes:     in.MaxSessionMinutes,
			AllowedStartMinute:    in.AllowedStartMinute,
			AllowedEndMinute:      in.AllowedEndMinute,
			RequireApproval:       *in.RequireApproval,
			CreatedAt:             now,
			UpdatedAt:             now,
		}
		if err := tx.Create(&created).Error; err != nil {
			return fmt.Errorf("create policy: %w", err)
		}
		return s.record(tx, audit.Entry{
			OrganizationID: orgID,
			Action:         "session.policy.create",
			TargetType:     "policy",
			TargetID:       fmt.Sprint(created.ID),
			Detail:         map[string]any{"name": created.Name},
		})
	})
	if err != nil {
		return nil, err
	}
	return &created, nil
}

// UpdatePolicy replaces a policy wholesale: the contract defines PUT as a full
// replacement, so a field left out is cleared rather than merged. A merge
// semantic would let a client disable a limit it can no longer see.
func (s *Service) UpdatePolicy(ctx context.Context, orgID, policyID uint, in PolicyInput) (*model.Policy, error) {
	if orgID == 0 || policyID == 0 {
		return nil, fmt.Errorf("%w: organization and policy are required", ErrInvalidInput)
	}
	if err := in.validate(); err != nil {
		return nil, err
	}

	var updated model.Policy
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var existing model.Policy
		if err := store.ScopedByOrg(tx, orgID).Where("id = ?", policyID).First(&existing).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrPolicyNotFound
			}
			return err
		}
		if !strings.EqualFold(existing.Name, in.Name) {
			if err := policyNameTaken(tx, orgID, in.Name, policyID); err != nil {
				return err
			}
		}

		// An explicit column list rather than Save: the tenant-column guard
		// rejects any write that carries organization_id, and a full replacement
		// must not include it anyway.
		updates := map[string]any{
			"name":                    in.Name,
			"enabled":                 *in.Enabled,
			"require_approval":        *in.RequireApproval,
			"max_concurrent_sessions": in.MaxConcurrentSessions,
			"max_session_minutes":     in.MaxSessionMinutes,
			"allowed_start_minute":    in.AllowedStartMinute,
			"allowed_end_minute":      in.AllowedEndMinute,
		}
		res := store.ScopedByOrg(tx, orgID).
			Model(&model.Policy{}).
			Where("id = ?", policyID).
			Updates(updates)
		if res.Error != nil {
			return fmt.Errorf("update policy: %w", res.Error)
		}
		if res.RowsAffected == 0 {
			return ErrPolicyNotFound
		}

		updated = existing
		updated.Name = in.Name
		updated.Enabled = *in.Enabled
		updated.RequireApproval = *in.RequireApproval
		updated.MaxConcurrentSessions = in.MaxConcurrentSessions
		updated.MaxSessionMinutes = in.MaxSessionMinutes
		updated.AllowedStartMinute = in.AllowedStartMinute
		updated.AllowedEndMinute = in.AllowedEndMinute

		return s.record(tx, audit.Entry{
			OrganizationID: orgID,
			Action:         "session.policy.update",
			TargetType:     "policy",
			TargetID:       fmt.Sprint(policyID),
			Detail:         map[string]any{"name": in.Name},
		})
	})
	if err != nil {
		return nil, err
	}
	return &updated, nil
}

// DeletePolicy removes a policy. Deleting a policy is not an emergency stop:
// the remaining enabled policies keep applying, and an organization with none
// is unrestricted by design.
func (s *Service) DeletePolicy(ctx context.Context, orgID, policyID uint) error {
	if orgID == 0 || policyID == 0 {
		return fmt.Errorf("%w: organization and policy are required", ErrInvalidInput)
	}
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		res := store.ScopedByOrg(tx, orgID).Where("id = ?", policyID).Delete(&model.Policy{})
		if res.Error != nil {
			return fmt.Errorf("delete policy: %w", res.Error)
		}
		if res.RowsAffected == 0 {
			return ErrPolicyNotFound
		}
		return s.record(tx, audit.Entry{
			OrganizationID: orgID,
			Action:         "session.policy.delete",
			TargetType:     "policy",
			TargetID:       fmt.Sprint(policyID),
		})
	})
}

// policyNameTaken reports the contract's duplicate-name conflict, ignoring the
// policy being updated (excludeID == 0 on create).
func policyNameTaken(tx *gorm.DB, orgID uint, name string, excludeID uint) error {
	var count int64
	q := store.ScopedByOrg(tx, orgID).Model(&model.Policy{}).Where("name = ?", name)
	if excludeID != 0 {
		q = q.Where("id <> ?", excludeID)
	}
	if err := q.Count(&count).Error; err != nil {
		return fmt.Errorf("check policy name: %w", err)
	}
	if count > 0 {
		return fmt.Errorf("%w: %q", ErrDuplicatePolicy, name)
	}
	return nil
}
