package api_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
)

// m5UserGroupView mirrors the UserGroup schema of contract 0.9.0.
type m5UserGroupView struct {
	Id        int64   `json:"id"`
	Name      string  `json:"name"`
	Kind      string  `json:"kind"`
	MemberIds []int64 `json:"member_ids"`
}

// TestAccess_UserGroupAdminFlow covers the management path end to end: an admin
// creates a group, adds a member, and the list reports the stored member ids;
// the reserved everyone group can be neither renamed nor deleted.
func TestAccess_UserGroupAdminFlow(t *testing.T) {
	h, orgID, _, _, member, _, adminToken, _ := m4Org(t)
	base := "/api/v1/orgs/" + itoa(orgID) + "/user-groups"

	w := h.do(t, http.MethodPost, base, map[string]string{"name": "Ops"}, adminToken)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var created m5UserGroupView
	decodeData(t, w, &created)
	require.NotZero(t, created.Id)
	require.Equal(t, "Ops", created.Name)
	require.Equal(t, model.UserGroupKindCustom, created.Kind)

	w = h.do(t, http.MethodPut, base+"/"+itoa(int64(created.Id))+"/members",
		map[string][]int64{"user_ids": {int64(member.ID)}}, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var mutation struct {
		Added   int `json:"added"`
		Removed int `json:"removed"`
	}
	decodeData(t, w, &mutation)
	require.Equal(t, 1, mutation.Added)
	require.Zero(t, mutation.Removed)

	w = h.do(t, http.MethodGet, base, nil, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var groups []m5UserGroupView
	decodeData(t, w, &groups)
	require.Len(t, groups, 2)

	byKind := map[string]m5UserGroupView{}
	for _, g := range groups {
		byKind[g.Kind] = g
	}
	everyone := byKind[model.UserGroupKindEveryone]
	require.Equal(t, "everyone", everyone.Name)
	require.Empty(t, everyone.MemberIds)
	require.Equal(t, []int64{int64(member.ID)}, byKind[model.UserGroupKindCustom].MemberIds)

	// A rename response carries the real member set: clients round-trip it into
	// PUT, so an empty list here would silently drop every member.
	w = h.do(t, http.MethodPatch, base+"/"+itoa(int64(created.Id)),
		map[string]string{"name": "Ops 2"}, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var renamed m5UserGroupView
	decodeData(t, w, &renamed)
	require.Equal(t, "Ops 2", renamed.Name)
	require.Equal(t, []int64{int64(member.ID)}, renamed.MemberIds)

	// A missing user_ids field is a malformed request, never "clear all members".
	w = h.do(t, http.MethodPut, base+"/"+itoa(int64(created.Id))+"/members",
		map[string]any{}, adminToken)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())

	w = h.do(t, http.MethodGet, base, nil, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	groups = nil
	decodeData(t, w, &groups)
	for _, g := range groups {
		if g.Id == created.Id {
			require.Equal(t, []int64{int64(member.ID)}, g.MemberIds, "a rejected request must not clear members")
		}
	}

	// Reserved name and reserved group are refused with a conflict.
	w = h.do(t, http.MethodPost, base, map[string]string{"name": "Everyone"}, adminToken)
	require.Equal(t, http.StatusConflict, w.Code, w.Body.String())

	w = h.do(t, http.MethodPatch, base+"/"+itoa(int64(everyone.Id)),
		map[string]string{"name": "staff"}, adminToken)
	require.Equal(t, http.StatusConflict, w.Code, w.Body.String())

	w = h.do(t, http.MethodDelete, base+"/"+itoa(int64(everyone.Id)), nil, adminToken)
	require.Equal(t, http.StatusConflict, w.Code, w.Body.String())
}

// TestAccess_UserGroupDeniedWithoutPermission pins the gate: a plain member and
// a custom role that lacks access.manage both get 403.
func TestAccess_UserGroupDeniedWithoutPermission(t *testing.T) {
	h, orgID, _, _, member, ownerToken, _, memberToken := m4Org(t)
	base := "/api/v1/orgs/" + itoa(orgID) + "/user-groups"

	w := h.do(t, http.MethodGet, base, nil, memberToken)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

	// Owner builds a custom role without access.manage and assigns it.
	w = h.do(t, http.MethodPost, "/api/v1/orgs/"+itoa(orgID)+"/roles", map[string]any{
		"name": "viewer", "permissions": []string{"device.read"}, "audit_scope": "individual",
	}, ownerToken)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var role struct {
		Id int64 `json:"id"`
	}
	decodeData(t, w, &role)

	w = h.do(t, http.MethodPatch, "/api/v1/orgs/"+itoa(orgID)+"/members/"+itoa(int64(member.ID)),
		map[string]any{"role_id": role.Id}, ownerToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	w = h.do(t, http.MethodGet, base, nil, memberToken)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

	// The owner keeps the permission and can read the list.
	w = h.do(t, http.MethodGet, base, nil, ownerToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
}

// TestAccess_RemoveMemberCleansGroups pins offboarding: removing a membership
// must also drop that user's group rows, otherwise the stale rows would hand
// the old groups' access back to the user the moment they are invited again.
func TestAccess_RemoveMemberCleansGroups(t *testing.T) {
	h, orgID, _, _, member, ownerToken, adminToken, _ := m4Org(t)
	base := "/api/v1/orgs/" + itoa(orgID) + "/user-groups"

	w := h.do(t, http.MethodPost, base, map[string]string{"name": "Oncall"}, adminToken)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var group m5UserGroupView
	decodeData(t, w, &group)

	w = h.do(t, http.MethodPut, base+"/"+itoa(group.Id)+"/members",
		map[string][]int64{"user_ids": {int64(member.ID)}}, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	w = h.do(t, http.MethodDelete, "/api/v1/orgs/"+itoa(orgID)+"/members/"+itoa(int64(member.ID)), nil, ownerToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	w = h.do(t, http.MethodGet, base, nil, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var groups []m5UserGroupView
	decodeData(t, w, &groups)
	for _, g := range groups {
		if g.Id == group.Id {
			require.Empty(t, g.MemberIds, "a removed member must not linger in any group")
		}
	}
}
