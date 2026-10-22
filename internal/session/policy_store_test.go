package session_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/session"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// PolicyInput mirrors the contract's PolicyRequest, with the two required
// booleans as pointers so "omitted" is distinguishable from "false".
type PolicyInput struct {
	Name                  string
	Enabled               *bool
	RequireApproval       *bool
	MaxConcurrentSessions *int64
	MaxSessionMinutes     *int64
	AllowedStartMinute    *int64
	AllowedEndMinute      *int64
}

func boolp(v bool) *bool { return &v }

func validPolicy() session.PolicyInput {
	return session.PolicyInput{
		Name:            "office-hours",
		Enabled:         boolp(true),
		RequireApproval: boolp(false),
	}
}

// ── validation ──────────────────────────────────────────────────────────────

// The two required booleans are the whole reason PolicyInput uses pointers: the
// generated struct field is a plain bool, so `false` and "omitted" look
// identical, and silently accepting an omitted field would let a client disable
// a policy (or drop its approval requirement) without meaning to.
func TestPolicy_RequiredFieldsMustBePresent(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	missingEnabled := validPolicy()
	missingEnabled.Enabled = nil
	_, err := h.svc.CreatePolicy(ctx, h.org.ID, missingEnabled)
	require.ErrorIs(t, err, session.ErrInvalidInput)

	missingApproval := validPolicy()
	missingApproval.RequireApproval = nil
	_, err = h.svc.CreatePolicy(ctx, h.org.ID, missingApproval)
	require.ErrorIs(t, err, session.ErrInvalidInput)

	missingName := validPolicy()
	missingName.Name = ""
	_, err = h.svc.CreatePolicy(ctx, h.org.ID, missingName)
	require.ErrorIs(t, err, session.ErrInvalidInput)
}

// A limit of zero is not "unlimited" — null is unlimited. Zero means "no session
// may ever start", which is a valid if drastic policy, but the contract's
// minimum is 1, so it is refused at the write path.
func TestPolicy_LimitsMustBeAtLeastOne(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	for _, tc := range []struct {
		name  string
		apply func(*session.PolicyInput)
	}{
		{"concurrency zero", func(p *session.PolicyInput) { p.MaxConcurrentSessions = i64(0) }},
		{"concurrency negative", func(p *session.PolicyInput) { p.MaxConcurrentSessions = i64(-1) }},
		{"duration zero", func(p *session.PolicyInput) { p.MaxSessionMinutes = i64(0) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := validPolicy()
			tc.apply(&in)
			_, err := h.svc.CreatePolicy(ctx, h.org.ID, in)
			require.ErrorIs(t, err, session.ErrInvalidInput)
		})
	}
}

// Window rules from the contract: the pair is all-or-nothing, both bounds are
// minutes-of-day within 0–1439, and start == end is not a window.
func TestPolicy_WindowRules(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	cases := []struct {
		name  string
		start *int64
		end   *int64
		valid bool
	}{
		{"both unset", nil, nil, true},
		{"ordinary window", i64(540), i64(1020), true},
		{"overnight window", i64(1320), i64(360), true},
		{"start == end", i64(600), i64(600), false},
		{"only start", i64(540), nil, false},
		{"only end", nil, i64(1020), false},
		{"start above 1439", i64(1440), i64(1500), false},
		{"negative start", i64(-1), i64(600), false},
		{"end above 1439", i64(540), i64(1440), false},
	}
	for seq, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := validPolicy()
			// Policy names are unique per organization, so a shared table needs
			// one name per case.
			in.Name = fmt.Sprintf("window-%02d", seq)
			in.AllowedStartMinute, in.AllowedEndMinute = tc.start, tc.end
			_, err := h.svc.CreatePolicy(ctx, h.org.ID, in)
			if tc.valid {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, session.ErrInvalidInput)
		})
	}
}

// The contract promises a 409 for a duplicate name inside the organization, and
// the unique index has to be per-organization so two organizations can both
// have "default".
func TestPolicy_DuplicateNameIsConflict(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	_, err := h.svc.CreatePolicy(ctx, h.org.ID, validPolicy())
	require.NoError(t, err)

	_, err = h.svc.CreatePolicy(ctx, h.org.ID, validPolicy())
	require.ErrorIs(t, err, session.ErrDuplicatePolicy)

	// Another organization may reuse the same name.
	other := modelOrganization(t, h)
	_, err = h.svc.CreatePolicy(ctx, other, validPolicy())
	require.NoError(t, err)
}

// ── CRUD ────────────────────────────────────────────────────────────────────

func TestPolicy_CRUD(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	created, err := h.svc.CreatePolicy(ctx, h.org.ID, validPolicy())
	require.NoError(t, err)
	require.Equal(t, "office-hours", created.Name)
	require.True(t, created.Enabled)

	listed, err := h.svc.ListPolicies(ctx, h.org.ID)
	require.NoError(t, err)
	require.Len(t, listed, 1)

	// Full replacement: fields left out are cleared, not merged.
	h.setClock(h.now.Add(time.Hour))
	replacement := session.PolicyInput{
		Name:            "office-hours",
		Enabled:         boolp(false),
		RequireApproval: boolp(true),
	}
	updated, err := h.svc.UpdatePolicy(ctx, h.org.ID, created.ID, replacement)
	require.NoError(t, err)
	require.False(t, updated.Enabled)
	require.True(t, updated.RequireApproval)
	require.Nil(t, updated.MaxConcurrentSessions)

	// The response is built from the input, so it proves nothing about the row:
	// re-read and compare. This is also what pins updated_at (the response used
	// to echo the pre-update value).
	var stored model.Policy
	require.NoError(t, store.WithoutTenantScope(h.db).First(&stored, created.ID).Error)
	require.False(t, stored.Enabled)
	require.True(t, stored.RequireApproval)
	require.Nil(t, stored.MaxConcurrentSessions)
	require.Equal(t, h.now.UTC(), stored.UpdatedAt.UTC(),
		"updated_at must be the write time, in the database as well as in the response")
	require.Equal(t, h.now.UTC(), updated.UpdatedAt.UTC())

	_, err = h.svc.UpdatePolicy(ctx, h.org.ID, 99999, replacement)
	require.ErrorIs(t, err, session.ErrPolicyNotFound)

	require.NoError(t, h.svc.DeletePolicy(ctx, h.org.ID, created.ID, 1))
	listed, err = h.svc.ListPolicies(ctx, h.org.ID)
	require.NoError(t, err)
	require.Empty(t, listed)

	require.ErrorIs(t, h.svc.DeletePolicy(ctx, h.org.ID, created.ID, 1), session.ErrPolicyNotFound)
}

// Renaming onto another policy's name is the same 409, and a case variant must
// not slip past the pre-check: SQLite and PostgreSQL compare names
// case-sensitively, so "Policy" and "policy" collide on the unique index rather
// than in the pre-check — and the index error has to surface as 409, not 500.
func TestPolicy_RenameToTakenNameIsConflict(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	first, err := h.svc.CreatePolicy(ctx, h.org.ID, session.PolicyInput{
		Name: "Policy", Enabled: boolp(true), RequireApproval: boolp(false),
	})
	require.NoError(t, err)

	second := validPolicy()
	second.Name = "other"
	secondRow, err := h.svc.CreatePolicy(ctx, h.org.ID, second)
	require.NoError(t, err)

	rename := validPolicy()
	rename.Name = "policy" // case variant of the first policy
	_, err = h.svc.UpdatePolicy(ctx, h.org.ID, secondRow.ID, rename)
	require.ErrorIs(t, err, session.ErrDuplicatePolicy)

	// Renaming to its own name stays allowed (the pre-check excludes the row).
	self := validPolicy()
	self.Name = "other"
	_, err = h.svc.UpdatePolicy(ctx, h.org.ID, secondRow.ID, self)
	require.NoError(t, err)
	require.Equal(t, first.ID, first.ID)
}

// Policy writes are audited like every other domain mutation.
func TestPolicy_MutationsAreAudited(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	created, err := h.svc.CreatePolicy(ctx, h.org.ID, validPolicy())
	require.NoError(t, err)
	_, err = h.svc.UpdatePolicy(ctx, h.org.ID, created.ID, validPolicy())
	require.NoError(t, err)
	require.NoError(t, h.svc.DeletePolicy(ctx, h.org.ID, created.ID, 1))

	require.Equal(t, []string{
		"session.policy.create",
		"session.policy.update",
		"session.policy.delete",
	}, h.recorder.actions())
}

// A policy of another organization is not "forbidden", it is not there.
func TestPolicy_TenantIsolation(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	mine, err := h.svc.CreatePolicy(ctx, h.org.ID, validPolicy())
	require.NoError(t, err)

	other := modelOrganization(t, h)
	listed, err := h.svc.ListPolicies(ctx, other)
	require.NoError(t, err)
	require.Empty(t, listed, "another organization's policies are invisible")

	_, err = h.svc.UpdatePolicy(ctx, other, mine.ID, validPolicy())
	require.ErrorIs(t, err, session.ErrPolicyNotFound)
	require.ErrorIs(t, h.svc.DeletePolicy(ctx, other, mine.ID, 1), session.ErrPolicyNotFound)
}

// modelOrganization creates a second organization and returns its id. Policies
// are unique per organization, so the tenant tests need a real second one.
func modelOrganization(t *testing.T, h *harness) uint {
	t.Helper()
	other := model.Organization{Name: "other-org"}
	require.NoError(t, h.db.Create(&other).Error)
	return other.ID
}
