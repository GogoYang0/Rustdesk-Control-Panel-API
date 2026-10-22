package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/api"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/audit"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
)

// countingAuditor counts audit entries so the tests can assert that polled reads
// stay silent while mutations are recorded.
type countingAuditor struct {
	entries int
}

func (c *countingAuditor) Record(_ context.Context, _ audit.Entry) error {
	c.entries++
	return nil
}

// reset drops the entries produced by test seeding.
func (c *countingAuditor) reset() { c.entries = 0 }

// seedOrgMember adds a plain member to an existing organization and returns a
// token for them.
func seedOrgMember(t *testing.T, h *harness, orgID int64, email string) string {
	t.Helper()
	user := h.seedUser(t, email, "password123")
	require.NoError(t, h.db.DB.Create(&model.Membership{
		OrganizationID: uint(orgID), UserID: user.ID, Role: model.RoleMember,
	}).Error)
	return h.login(t, email, "password123")
}

func policyPath(orgID int64) string {
	return "/api/v1/orgs/" + strconv.FormatInt(orgID, 10) + "/policies"
}

func policyItemPath(orgID, policyID int64) string {
	return policyPath(orgID) + "/" + strconv.FormatInt(policyID, 10)
}

func validPolicyBody() map[string]any {
	return map[string]any{
		"name":                "office-hours",
		"enabled":             true,
		"require_approval":    false,
		"max_session_minutes": 120,
	}
}

// ── permission matrix ───────────────────────────────────────────────────────

// Reading is member-level (the effective policy decides what a member can do),
// writing is owner/admin only.
func TestPolicy_PermissionMatrix(t *testing.T) {
	h := newHarness(t)
	owner, orgID := seedOrgOwner(t, h, "policy-owner@example.com")
	member := seedOrgMember(t, h, orgID, "policy-member@example.com")

	// A member may read.
	w := h.do(t, http.MethodGet, policyPath(orgID), nil, member)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	// …but not write.
	for _, tc := range []struct {
		method string
		path   string
		body   any
	}{
		{http.MethodPost, policyPath(orgID), validPolicyBody()},
		{http.MethodPut, policyItemPath(orgID, 1), validPolicyBody()},
		{http.MethodDelete, policyItemPath(orgID, 1), nil},
	} {
		w = h.do(t, tc.method, tc.path, tc.body, member)
		require.Equal(t, http.StatusForbidden, w.Code, tc.method+" "+tc.path)
	}

	// The owner can.
	w = h.do(t, http.MethodPost, policyPath(orgID), validPolicyBody(), owner)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
}

// An omitted or null required boolean is a 400 — not a silent false, which would
// disable the policy (or drop its approval requirement) without the caller
// meaning to.
func TestPolicy_RequiredBooleansMustBePresent(t *testing.T) {
	h := newHarness(t)
	token, orgID := seedOrgOwner(t, h, "policy-presence@example.com")

	missing := validPolicyBody()
	delete(missing, "enabled")
	w := h.do(t, http.MethodPost, policyPath(orgID), missing, token)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())

	explicitNull := validPolicyBody()
	explicitNull["require_approval"] = nil
	w = h.do(t, http.MethodPost, policyPath(orgID), explicitNull, token)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())

	// Both present is accepted.
	w = h.do(t, http.MethodPost, policyPath(orgID), validPolicyBody(), token)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
}

func TestPolicy_CreateUpdateDelete(t *testing.T) {
	h := newHarness(t)
	token, orgID := seedOrgOwner(t, h, "policy-crud@example.com")

	w := h.do(t, http.MethodPost, policyPath(orgID), validPolicyBody(), token)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var created struct {
		Data struct {
			Id                int64  `json:"id"`
			MaxSessionMinutes *int64 `json:"max_session_minutes"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &created))
	require.NotZero(t, created.Data.Id)

	// Duplicate name inside the organization is the contract's 409.
	w = h.do(t, http.MethodPost, policyPath(orgID), validPolicyBody(), token)
	require.Equal(t, http.StatusConflict, w.Code, w.Body.String())

	// PUT is a full replacement: the limit left out is cleared, not merged.
	replacement := map[string]any{"name": "office-hours", "enabled": true, "require_approval": true}
	w = h.do(t, http.MethodPut, policyItemPath(orgID, created.Data.Id), replacement, token)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var updated struct {
		Data struct {
			RequireApproval   bool   `json:"require_approval"`
			MaxSessionMinutes *int64 `json:"max_session_minutes"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &updated))
	require.True(t, updated.Data.RequireApproval)
	require.Nil(t, updated.Data.MaxSessionMinutes, "an omitted field is cleared by a full replacement")

	w = h.do(t, http.MethodDelete, policyItemPath(orgID, created.Data.Id), nil, token)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	w = h.do(t, http.MethodDelete, policyItemPath(orgID, created.Data.Id), nil, token)
	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())
}

// A policy that belongs to another organization is not "forbidden", it is not
// there: a caller inside this organization addressing that id must get 404, so
// the response cannot be used to probe which ids exist.
func TestPolicy_CrossOrganizationIsNotFound(t *testing.T) {
	h := newHarness(t)
	ownerA, orgA := seedOrgOwner(t, h, "policy-cross-a@example.com")
	ownerB, orgB := seedOrgOwner(t, h, "policy-cross-b@example.com")

	// orgB owns a policy whose id is known.
	w := h.do(t, http.MethodPost, policyPath(orgB), validPolicyBody(), ownerB)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var created struct {
		Data struct {
			Id int64 `json:"id"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &created))

	// orgA is a member of its own organization, so the membership check passes
	// and the store answers 404 — never 200, never 403.
	w = h.do(t, http.MethodPut, policyItemPath(orgA, created.Data.Id), validPolicyBody(), ownerA)
	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())

	w = h.do(t, http.MethodDelete, policyItemPath(orgA, created.Data.Id), nil, ownerA)
	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())

	// The row itself is untouched.
	w = h.do(t, http.MethodGet, policyPath(orgB), nil, ownerB)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var listed struct {
		Data []struct {
			Id int64 `json:"id"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &listed))
	require.Len(t, listed.Data, 1, "the other organization's policy survives")
}

// ── session records ─────────────────────────────────────────────────────────

func seedSessionRow(t *testing.T, h *harness, orgID int64, startedAt time.Time, origin, status string) model.Session {
	t.Helper()
	row := model.Session{
		OrganizationID: uint(orgID),
		DeviceID:       1,
		RustdeskID:     "777000111",
		Origin:         origin,
		Status:         status,
		StartedAt:      startedAt,
	}
	require.NoError(t, h.db.DB.Create(&row).Error)
	return row
}

// The list carries the unpaginated total, and a member may read it.
func TestSessions_List(t *testing.T) {
	h := newHarness(t)
	token, orgID := seedOrgOwner(t, h, "sessions-list@example.com")
	seedOrgMember(t, h, orgID, "sessions-list-member@example.com")
	member := h.login(t, "sessions-list-member@example.com", "password123")

	base := time.Date(2026, 10, 22, 8, 0, 0, 0, time.UTC)
	seedSessionRow(t, h, orgID, base.Add(-time.Hour), model.SessionOriginPanel, model.SessionStatusClosed)
	newest := seedSessionRow(t, h, orgID, base, model.SessionOriginNative, model.SessionStatusOpen)

	w := h.do(t, http.MethodGet, "/api/v1/orgs/"+strconv.FormatInt(orgID, 10)+"/sessions", nil, member)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var body struct {
		Data struct {
			Items []struct {
				Id     int64  `json:"id"`
				Origin string `json:"origin"`
				Status string `json:"status"`
			} `json:"items"`
			Page     int   `json:"page"`
			PageSize int64 `json:"page_size"`
			Total    int64 `json:"total"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	require.Equal(t, int64(2), body.Data.Total)
	require.Len(t, body.Data.Items, 2)
	require.Equal(t, 1, body.Data.Page)
	require.Equal(t, int64(50), body.Data.PageSize, "the contract's default page size is echoed")
	require.Equal(t, newest.ID, uint(body.Data.Items[0].Id), "newest first")

	// Filters and pagination are honoured as query parameters.
	w = h.do(t, http.MethodGet,
		"/api/v1/orgs/"+strconv.FormatInt(orgID, 10)+"/sessions?origin=native&pageSize=1&page=1",
		nil, token)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	require.Len(t, body.Data.Items, 1)
	require.Equal(t, int64(1), body.Data.Total,
		"total counts the rows matching the filter, so the pager can render '1-1 of 1'")
	require.Equal(t, int64(1), body.Data.PageSize)
}

// The detail view carries the session and its timeline.
func TestSessions_Detail(t *testing.T) {
	h := newHarness(t)
	token, orgID := seedOrgOwner(t, h, "sessions-detail@example.com")

	base := time.Date(2026, 10, 22, 8, 0, 0, 0, time.UTC)
	sess := seedSessionRow(t, h, orgID, base, model.SessionOriginPanel, model.SessionStatusOpen)
	require.NoError(t, h.db.DB.Create(&model.SessionEvent{
		OrganizationID: uint(orgID), SessionID: sess.ID, Kind: "started",
		At: base, DetailJSON: `{"via":"ticket"}`,
	}).Error)

	w := h.do(t, http.MethodGet,
		"/api/v1/orgs/"+strconv.FormatInt(orgID, 10)+"/sessions/"+strconv.FormatUint(uint64(sess.ID), 10),
		nil, token)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var body struct {
		Data struct {
			Session struct {
				Id     int64  `json:"id"`
				Origin string `json:"origin"`
			} `json:"session"`
			Events []struct {
				Kind string `json:"kind"`
			} `json:"events"`
			Truncated bool `json:"truncated"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	require.Equal(t, sess.ID, uint(body.Data.Session.Id))
	require.Len(t, body.Data.Events, 1)
	require.False(t, body.Data.Truncated)

	w = h.do(t, http.MethodGet,
		"/api/v1/orgs/"+strconv.FormatInt(orgID, 10)+"/sessions/99999", nil, token)
	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())
}

// Another organization's session id is 404: the caller must not learn that the
// id exists.
func TestSessions_CrossOrganizationIsNotFound(t *testing.T) {
	h := newHarness(t)
	_, orgID := seedOrgOwner(t, h, "sessions-cross@example.com")
	outsider, _ := seedOrgOwner(t, h, "sessions-cross-other@example.com")

	sess := seedSessionRow(t, h, orgID, time.Date(2026, 10, 22, 8, 0, 0, 0, time.UTC),
		model.SessionOriginPanel, model.SessionStatusOpen)

	path := "/api/v1/orgs/" + strconv.FormatInt(orgID, 10) + "/sessions/" + strconv.FormatUint(uint64(sess.ID), 10)
	w := h.do(t, http.MethodGet, path, nil, outsider)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String(), "a non-member cannot address the organization at all")
}

// Polled reads must not write an audit row per poll (#19). Mutations still do.
func TestSessions_ReadsAreNotAuditedButMutationsAre(t *testing.T) {
	auditor := &countingAuditor{}
	h := newHarnessWith(t, func(d *api.Deps) { d.Auditor = auditor })
	token, orgID := seedOrgOwner(t, h, "sessions-audit@example.com")

	// Seeding created an organization, which is itself an audited mutation.
	auditor.reset()

	sessionsPath := "/api/v1/orgs/" + strconv.FormatInt(orgID, 10) + "/sessions"
	for i := 0; i < 5; i++ {
		w := h.do(t, http.MethodGet, sessionsPath, nil, token)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	}
	require.Zero(t, auditor.entries, "a dashboard polling the session list must not write audit rows")

	w := h.do(t, http.MethodGet, policyPath(orgID), nil, token)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Zero(t, auditor.entries, "policy reads are polled too")

	w = h.do(t, http.MethodPost, policyPath(orgID), validPolicyBody(), token)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	require.NotZero(t, auditor.entries, "a policy mutation must still be audited")
}
