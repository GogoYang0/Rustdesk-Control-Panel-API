package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
)

// m4RoleView mirrors the Role schema of contract 0.8.0.
type m4RoleView struct {
	Id          int64    `json:"id"`
	Name        string   `json:"name"`
	Kind        string   `json:"kind"`
	Permissions []string `json:"permissions"`
	AuditScope  string   `json:"audit_scope"`
	Builtin     bool     `json:"builtin"`
}

// m4MemberView mirrors the Member schema of contract 0.8.0.
type m4MemberView struct {
	Id       int64  `json:"id"`
	UserId   int64  `json:"user_id"`
	Email    string `json:"email"`
	Role     string `json:"role"`
	RoleId   int64  `json:"role_id"`
	RoleName string `json:"role_name"`
	Disabled bool   `json:"disabled"`
}

// m4Org seeds an organization with one owner, one admin, and one member.
func m4Org(t *testing.T) (h *harness, orgID int64, owner, admin, member model.User, ownerToken, adminToken, memberToken string) {
	t.Helper()
	h = newHarness(t)
	owner = h.seedUser(t, "m4-owner@example.com", "password123")
	ownerToken = h.login(t, "m4-owner@example.com", "password123")
	orgID = createOrg(t, h, ownerToken, "m4-org")

	admin = h.seedUser(t, "m4-admin@example.com", "password123")
	seedMember(t, h, orgID, admin.ID, model.RoleAdmin)
	adminToken = h.login(t, "m4-admin@example.com", "password123")

	member = h.seedUser(t, "m4-member@example.com", "password123")
	seedMember(t, h, orgID, member.ID, model.RoleMember)
	memberToken = h.login(t, "m4-member@example.com", "password123")
	return h, orgID, owner, admin, member, ownerToken, adminToken, memberToken
}

func decodeData[T any](t *testing.T, w *httptest.ResponseRecorder, out *T) {
	t.Helper()
	var resp struct {
		Data T `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	*out = resp.Data
}

func TestPermissions_CatalogAndRoleList(t *testing.T) {
	h, orgID, _, _, _, ownerToken, _, memberToken := m4Org(t)

	w := h.do(t, http.MethodGet, "/api/v1/permissions", nil, ownerToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var perms []struct {
		Code      string `json:"code"`
		Delegable bool   `json:"delegable"`
	}
	decodeData(t, w, &perms)
	byCode := map[string]bool{}
	for _, p := range perms {
		byCode[p.Code] = p.Delegable
	}
	require.Contains(t, byCode, "org.admin")
	require.False(t, byCode["org.admin"], "org.admin must stay owner-only")
	require.Contains(t, byCode, "role.manage")
	require.False(t, byCode["role.manage"], "role.manage must stay owner-only")
	require.True(t, byCode["audit.read"])
	require.True(t, byCode["member.manage"])

	// Any member may read the catalog; unauthenticated callers may not.
	w = h.do(t, http.MethodGet, "/api/v1/permissions", nil, memberToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	w = h.do(t, http.MethodGet, "/api/v1/permissions", nil, "")
	require.Equal(t, http.StatusUnauthorized, w.Code)

	w = h.do(t, http.MethodGet, "/api/v1/orgs/"+itoa(orgID)+"/roles", nil, memberToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var roles []m4RoleView
	decodeData(t, w, &roles)
	require.Len(t, roles, 3)
	byName := map[string]m4RoleView{}
	for _, r := range roles {
		byName[r.Name] = r
		require.True(t, r.Builtin)
	}
	require.Equal(t, model.RoleKindOwner, byName["owner"].Kind)
	require.Contains(t, byName["owner"].Permissions, "org.admin")
	require.Equal(t, []string{"device.read"}, byName["member"].Permissions)
	require.Equal(t, model.AuditScopeIndividual, byName["member"].AuditScope)
}

func TestRole_CreateValidationAndGuards(t *testing.T) {
	h, orgID, _, _, _, ownerToken, adminToken, _ := m4Org(t)
	base := "/api/v1/orgs/" + itoa(orgID) + "/roles"

	// Unknown permission code -> 400.
	w := h.do(t, http.MethodPost, base, map[string]any{
		"name": "x", "permissions": []string{"org.nuke"},
	}, ownerToken)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())

	// Owner-only permission is not delegable -> 403.
	w = h.do(t, http.MethodPost, base, map[string]any{
		"name": "x", "permissions": []string{"org.admin"},
	}, ownerToken)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

	// Builtin names are reserved -> 409.
	w = h.do(t, http.MethodPost, base, map[string]any{
		"name": "admin", "permissions": []string{"audit.read"},
	}, ownerToken)
	require.Equal(t, http.StatusConflict, w.Code, w.Body.String())

	// Missing name -> 400.
	w = h.do(t, http.MethodPost, base, map[string]any{
		"name": "", "permissions": []string{"audit.read"},
	}, ownerToken)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())

	// Unknown audit scope -> 400.
	w = h.do(t, http.MethodPost, base, map[string]any{
		"name": "x", "permissions": []string{}, "audit_scope": "everything",
	}, ownerToken)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())

	// Admin lacks role.manage -> 403.
	w = h.do(t, http.MethodPost, base, map[string]any{
		"name": "auditor", "permissions": []string{"audit.read"},
	}, adminToken)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

	w = h.do(t, http.MethodPost, base, map[string]any{
		"name": "auditor", "permissions": []string{"audit.read", "device.read"},
		"audit_scope": "global",
	}, ownerToken)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var created m4RoleView
	decodeData(t, w, &created)
	require.NotZero(t, created.Id)
	require.Equal(t, "auditor", created.Name)
	require.Equal(t, model.RoleKindCustom, created.Kind)
	require.False(t, created.Builtin)
	require.Equal(t, model.AuditScopeGlobal, created.AuditScope)
	require.ElementsMatch(t, []string{"audit.read", "device.read"}, created.Permissions)

	// Duplicate name -> 409.
	w = h.do(t, http.MethodPost, base, map[string]any{
		"name": "auditor", "permissions": []string{},
	}, ownerToken)
	require.Equal(t, http.StatusConflict, w.Code, w.Body.String())

	// Duplicate names are case-sensitive exact matches only; a different name
	// with the same permissions is allowed.
	w = h.do(t, http.MethodPost, base, map[string]any{
		"name": "auditor-two", "permissions": []string{"audit.read"},
	}, ownerToken)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
}

func TestRole_UpdateDeleteAndAssignment(t *testing.T) {
	h, orgID, _, _, member, ownerToken, adminToken, _ := m4Org(t)
	base := "/api/v1/orgs/" + itoa(orgID)
	rolesPath := base + "/roles"
	memberRoleID := int64(h.roleID(t, uint(orgID), model.RoleMember))
	ownerRoleID := int64(h.roleID(t, uint(orgID), model.RoleOwner))

	w := h.do(t, http.MethodPost, rolesPath, map[string]any{
		"name": "auditor", "permissions": []string{"audit.read"},
	}, ownerToken)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var created m4RoleView
	decodeData(t, w, &created)
	rolePath := rolesPath + "/" + itoa(created.Id)

	// Detail read is member-level; admin may not mutate.
	w = h.do(t, http.MethodGet, rolePath, nil, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	w = h.do(t, http.MethodPut, rolePath, map[string]any{
		"name": "auditor2", "permissions": []string{"audit.read"},
	}, adminToken)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	w = h.do(t, http.MethodDelete, rolePath, nil, adminToken)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

	// Builtin roles are immutable.
	w = h.do(t, http.MethodPut, rolesPath+"/"+itoa(ownerRoleID), map[string]any{
		"name": "owner", "permissions": []string{}, "audit_scope": "global",
	}, ownerToken)
	require.Equal(t, http.StatusConflict, w.Code, w.Body.String())
	w = h.do(t, http.MethodDelete, rolesPath+"/"+itoa(ownerRoleID), nil, ownerToken)
	require.Equal(t, http.StatusConflict, w.Code, w.Body.String())

	// Renaming a custom role onto a builtin name is a conflict.
	w = h.do(t, http.MethodPut, rolePath, map[string]any{
		"name": "member", "permissions": []string{"audit.read"},
	}, ownerToken)
	require.Equal(t, http.StatusConflict, w.Code, w.Body.String())

	// Renaming onto another custom role's name is a conflict too.
	w = h.do(t, http.MethodPost, rolesPath, map[string]any{
		"name": "sibling", "permissions": []string{},
	}, ownerToken)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	w = h.do(t, http.MethodPut, rolePath, map[string]any{
		"name": "sibling", "permissions": []string{"audit.read"},
	}, ownerToken)
	require.Equal(t, http.StatusConflict, w.Code, w.Body.String())

	// Update replaces the whole permission set and audit scope.
	w = h.do(t, http.MethodPut, rolePath, map[string]any{
		"name": "auditor2", "permissions": []string{"audit.read", "device.read"},
		"audit_scope": "individual",
	}, ownerToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var updated m4RoleView
	decodeData(t, w, &updated)
	require.Equal(t, "auditor2", updated.Name)
	require.ElementsMatch(t, []string{"audit.read", "device.read"}, updated.Permissions)
	require.Equal(t, model.AuditScopeIndividual, updated.AuditScope)

	// Assign the custom role to the member.
	memberPath := base + "/members/" + itoa(int64(member.ID))
	w = h.do(t, http.MethodPatch, memberPath, map[string]any{"role_id": created.Id}, ownerToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var assigned m4MemberView
	decodeData(t, w, &assigned)
	require.Equal(t, created.Id, assigned.RoleId)
	require.Equal(t, "auditor2", assigned.RoleName)
	require.Equal(t, "auditor2", assigned.Role)
	require.False(t, assigned.Disabled)

	// A custom role is not a way to grant owner.
	w = h.do(t, http.MethodPatch, memberPath, map[string]any{"role_id": ownerRoleID}, ownerToken)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

	// Unknown role id -> 404; unknown member -> 404.
	w = h.do(t, http.MethodPatch, memberPath, map[string]any{"role_id": 999999}, ownerToken)
	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())
	w = h.do(t, http.MethodPatch, base+"/members/999999", map[string]any{"role_id": memberRoleID}, ownerToken)
	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())

	// Only an owner may assign roles.
	w = h.do(t, http.MethodPatch, memberPath, map[string]any{"role_id": memberRoleID}, adminToken)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

	// A referenced role cannot be deleted.
	w = h.do(t, http.MethodDelete, rolePath, nil, ownerToken)
	require.Equal(t, http.StatusConflict, w.Code, w.Body.String())

	// Reassign the member back to the builtin, then delete.
	w = h.do(t, http.MethodPatch, memberPath, map[string]any{"role_id": memberRoleID}, ownerToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	w = h.do(t, http.MethodDelete, rolePath, nil, ownerToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	w = h.do(t, http.MethodGet, rolePath, nil, ownerToken)
	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())

	require.NotZero(t, countAudit(t, h, "action = ?", "role.create"))
	require.NotZero(t, countAudit(t, h, "action = ?", "role.update"))
	require.NotZero(t, countAudit(t, h, "action = ?", "role.delete"))
	require.NotZero(t, countAudit(t, h, "action = ?", "organization.member.role"))
}

func TestRole_TenantIsolation(t *testing.T) {
	h, orgA, _, _, _, ownerAToken, _, _ := m4Org(t)
	h.seedUser(t, "m4-other-owner@example.com", "password123")
	otherToken := h.login(t, "m4-other-owner@example.com", "password123")
	orgB := createOrg(t, h, otherToken, "m4-org-b")

	// A role of another organization is invisible: the path org decides scope.
	w := h.do(t, http.MethodPost, "/api/v1/orgs/"+itoa(orgA)+"/roles", map[string]any{
		"name": "auditor", "permissions": []string{"audit.read"},
	}, ownerAToken)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var created m4RoleView
	decodeData(t, w, &created)

	w = h.do(t, http.MethodGet, "/api/v1/orgs/"+itoa(orgA)+"/roles/"+itoa(created.Id), nil, otherToken)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	w = h.do(t, http.MethodGet, "/api/v1/orgs/"+itoa(orgB)+"/roles/"+itoa(created.Id), nil, otherToken)
	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())
}
