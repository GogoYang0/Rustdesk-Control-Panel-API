package api_test

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type auditView struct {
	Id          int64     `json:"id"`
	Seq         int64     `json:"seq"`
	ActorUserId int64     `json:"actor_user_id"`
	Action      string    `json:"action"`
	TargetType  string    `json:"target_type"`
	TargetId    string    `json:"target_id"`
	Detail      any       `json:"detail"`
	CreatedAt   time.Time `json:"created_at"`
}

type auditPageView struct {
	Items    []auditView `json:"items"`
	Page     int         `json:"page"`
	PageSize int64       `json:"page_size"`
	Total    int64       `json:"total"`
}

func listAudit(t *testing.T, h *harness, orgID int64, query, token string) auditPageView {
	t.Helper()
	w := h.do(t, http.MethodGet, "/api/v1/orgs/"+itoa(orgID)+"/audit-logs"+query, nil, token)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var page auditPageView
	decodeData(t, w, &page)
	return page
}

// createRoleAPI creates a custom role and returns its id.
func createRoleAPI(t *testing.T, h *harness, orgID int64, token, name string, perms []string, scope string) int64 {
	t.Helper()
	w := h.do(t, http.MethodPost, "/api/v1/orgs/"+itoa(orgID)+"/roles", map[string]any{
		"name": name, "permissions": perms, "audit_scope": scope,
	}, token)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var role m4RoleView
	decodeData(t, w, &role)
	return role.Id
}

func TestAudit_IndividualScopeSeesOwnAndTargetedEntries(t *testing.T) {
	h, orgID, _, _, member, ownerToken, _, memberToken := m4Org(t)
	roleID := createRoleAPI(t, h, orgID, ownerToken, "auditor", []string{"audit.read"}, "individual")

	// The role grant produces a user-targeted audit row for the member.
	w := h.do(t, http.MethodPatch, "/api/v1/orgs/"+itoa(orgID)+"/members/"+itoa(int64(member.ID)),
		map[string]any{"role_id": roleID}, ownerToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	// The member (individual scope) sees the entry that targets them.
	page := listAudit(t, h, orgID, "?action=organization.member.role", memberToken)
	require.NotEmpty(t, page.Items)
	require.Equal(t, "user", page.Items[0].TargetType)
	require.Equal(t, fmt.Sprint(member.ID), page.Items[0].TargetId)

	// Entries created by others with non-user targets stay invisible.
	invisible := listAudit(t, h, orgID, "?action=role.create", memberToken)
	require.Zero(t, invisible.Total)
	require.Empty(t, invisible.Items)

	// A global-scope owner sees that same entry.
	visible := listAudit(t, h, orgID, "?action=role.create", ownerToken)
	require.NotZero(t, visible.Total)

	// A member without audit.read cannot read the trail at all.
	plain := h.seedUser(t, "m4-plain@example.com", "password123")
	seedMember(t, h, orgID, plain.ID, "member")
	plainToken := h.login(t, "m4-plain@example.com", "password123")
	w = h.do(t, http.MethodGet, "/api/v1/orgs/"+itoa(orgID)+"/audit-logs", nil, plainToken)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

	// Another tenant cannot read this organization's trail.
	h.seedUser(t, "m4-audit-other@example.com", "password123")
	otherToken := h.login(t, "m4-audit-other@example.com", "password123")
	createOrg(t, h, otherToken, "audit-other-org")
	w = h.do(t, http.MethodGet, "/api/v1/orgs/"+itoa(orgID)+"/audit-logs", nil, otherToken)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
}

func TestAudit_GlobalScopeFiltersAndPagination(t *testing.T) {
	h, orgID, owner, _, _, ownerToken, _, _ := m4Org(t)

	// Produce a few distinct actions with distinct targets.
	createRoleAPI(t, h, orgID, ownerToken, "role-a", []string{"audit.read"}, "global")
	createRoleAPI(t, h, orgID, ownerToken, "role-b", []string{"device.read"}, "individual")

	all := listAudit(t, h, orgID, "?pageSize=2", ownerToken)
	require.EqualValues(t, 1, all.Page)
	require.EqualValues(t, 2, all.PageSize)
	require.Len(t, all.Items, 2)
	require.GreaterOrEqual(t, all.Total, int64(3), "organization.create + two role.create")
	require.Greater(t, all.Items[0].Seq, all.Items[1].Seq, "newest first")

	second := listAudit(t, h, orgID, "?page=2&pageSize=2", ownerToken)
	require.EqualValues(t, 2, second.Page)
	require.NotEmpty(t, second.Items)

	byAction := listAudit(t, h, orgID, "?action=role.create", ownerToken)
	require.EqualValues(t, 2, byAction.Total)
	for _, item := range byAction.Items {
		require.Equal(t, "role", item.TargetType)
	}

	byActor := listAudit(t, h, orgID, "?actorUserId="+itoa(int64(owner.ID)), ownerToken)
	require.NotZero(t, byActor.Total)
	for _, item := range byActor.Items {
		require.EqualValues(t, owner.ID, item.ActorUserId)
	}

	future := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
	futureOnly := listAudit(t, h, orgID, "?from="+future, ownerToken)
	require.Zero(t, futureOnly.Total)
	require.Empty(t, futureOnly.Items)

	// Invalid parameters are rejected instead of silently ignored.
	w := h.do(t, http.MethodGet, "/api/v1/orgs/"+itoa(orgID)+"/audit-logs?actorUserId=-1", nil, ownerToken)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	w = h.do(t, http.MethodGet, "/api/v1/orgs/"+itoa(orgID)+"/audit-logs?action="+repeatRunes('a', 129), nil, ownerToken)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
}

func TestAudit_QueryDoesNotAuditItself(t *testing.T) {
	h, orgID, _, _, _, ownerToken, _, _ := m4Org(t)
	before := listAudit(t, h, orgID, "", ownerToken).Total
	_ = listAudit(t, h, orgID, "", ownerToken)
	_ = listAudit(t, h, orgID, "", ownerToken)
	after := listAudit(t, h, orgID, "", ownerToken).Total
	require.Equal(t, before, after, "a polled audit list must not add audit rows")
}

func repeatRunes(r rune, n int) string {
	out := make([]rune, n)
	for i := range out {
		out[i] = r
	}
	return string(out)
}
