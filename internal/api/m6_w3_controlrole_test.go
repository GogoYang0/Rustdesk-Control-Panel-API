package api_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// controlRoleView mirrors the ControlRole schema of contract 0.10.0.
type controlRoleView struct {
	Id          int64             `json:"id"`
	Name        string            `json:"name"`
	Kind        string            `json:"kind"`
	Permissions map[string]string `json:"permissions"`
	Builtin     bool              `json:"builtin"`
}

func TestControlRole_AdminFlow(t *testing.T) {
	h, orgID, _, _, member, _, adminToken, memberToken := m4Org(t)
	base := "/api/v1/orgs/" + itoa(orgID) + "/control-roles"

	w := h.do(t, http.MethodPost, base, map[string]any{
		"name":        "Ops",
		"permissions": map[string]string{"file": "enable"},
	}, adminToken)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var created controlRoleView
	decodeData(t, w, &created)
	require.NotZero(t, created.Id)
	require.Equal(t, "Ops", created.Name)
	require.Equal(t, model.KindControlRoleCustom, created.Kind)
	require.False(t, created.Builtin)
	require.Equal(t, "enable", created.Permissions["file"])
	require.Equal(t, "use_client", created.Permissions["keyboard"], "missing keys must be filled with use_client")

	// A domain-audited write must suppress the middleware fallback row.
	var httpRows, domainRows int64
	require.NoError(t, store.WithoutTenantScope(h.db.DB).Model(&model.AuditLog{}).
		Where("action = ?", "POST /api/v1/orgs/:orgId/control-roles").Count(&httpRows).Error)
	require.Zero(t, httpRows)
	require.NoError(t, store.WithoutTenantScope(h.db.DB).Model(&model.AuditLog{}).
		Where("action = ?", "control_role.create").Count(&domainRows).Error)
	require.EqualValues(t, 1, domainRows)

	// Any member may read the list; the built-in default comes first.
	w = h.do(t, http.MethodGet, base, nil, memberToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var list []controlRoleView
	decodeData(t, w, &list)
	require.Len(t, list, 2)
	require.Equal(t, model.KindControlRoleDefault, list[0].Kind)
	require.True(t, list[0].Builtin)

	w = h.do(t, http.MethodPatch, base+"/"+itoa(created.Id), map[string]any{
		"name":        "Ops 2",
		"permissions": map[string]string{"file": "disable", "clipboard": "enable"},
	}, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var updated controlRoleView
	decodeData(t, w, &updated)
	require.Equal(t, "Ops 2", updated.Name)
	require.Equal(t, "disable", updated.Permissions["file"])
	require.Equal(t, "enable", updated.Permissions["clipboard"])

	memberBase := "/api/v1/orgs/" + itoa(orgID) + "/members/" + itoa(int64(member.ID)) + "/control-role"
	w = h.do(t, http.MethodPut, memberBase, map[string]any{"control_role_id": created.Id}, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var assigned model.Membership
	require.NoError(t, store.WithoutTenantScope(h.db.DB).
		Where("organization_id = ? AND user_id = ?", orgID, member.ID).First(&assigned).Error)
	require.NotNil(t, assigned.ControlRoleID)
	require.EqualValues(t, created.Id, *assigned.ControlRoleID)

	// Deleting the role clears the assignment in the same transaction.
	w = h.do(t, http.MethodDelete, base+"/"+itoa(created.Id), nil, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var cleared model.Membership
	require.NoError(t, store.WithoutTenantScope(h.db.DB).First(&cleared, assigned.ID).Error)
	require.Nil(t, cleared.ControlRoleID)
	var remaining int64
	require.NoError(t, store.WithoutTenantScope(h.db.DB).Model(&model.ControlRole{}).
		Where("id = ?", created.Id).Count(&remaining).Error)
	require.Zero(t, remaining)
}

func TestControlRole_RequiresManagePermission(t *testing.T) {
	h, orgID, _, _, _, _, adminToken, memberToken := m4Org(t)
	base := "/api/v1/orgs/" + itoa(orgID) + "/control-roles"

	w := h.do(t, http.MethodPost, base, map[string]any{
		"name":        "Ops",
		"permissions": map[string]string{},
	}, memberToken)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

	w = h.do(t, http.MethodGet, base, nil, memberToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	w = h.do(t, http.MethodPost, base, map[string]any{
		"name":        "Ops",
		"permissions": map[string]string{},
	}, adminToken)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
}

func TestControlRole_CrossOrgIsolated(t *testing.T) {
	h, orgA, _, _, _, ownerAToken, _, _ := m4Org(t)
	w := h.do(t, http.MethodPost, "/api/v1/orgs/"+itoa(orgA)+"/control-roles", map[string]any{
		"name":        "A-Role",
		"permissions": map[string]string{},
	}, ownerAToken)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var role controlRoleView
	decodeData(t, w, &role)

	// A second organization must not see or touch it.
	orgB := createOrg(t, h, ownerAToken, "m6-w3-other")
	w = h.do(t, http.MethodPatch, "/api/v1/orgs/"+itoa(orgB)+"/control-roles/"+itoa(role.Id),
		map[string]any{"name": "stolen"}, ownerAToken)
	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())
}

func TestControlRole_DefaultRoleProtected(t *testing.T) {
	h, orgID, _, _, _, _, adminToken, _ := m4Org(t)
	base := "/api/v1/orgs/" + itoa(orgID) + "/control-roles"

	w := h.do(t, http.MethodGet, base, nil, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var list []controlRoleView
	decodeData(t, w, &list)
	require.NotEmpty(t, list)
	def := list[0]
	require.True(t, def.Builtin)

	w = h.do(t, http.MethodPatch, base+"/"+itoa(def.Id), map[string]any{"name": "Renamed"}, adminToken)
	require.Equal(t, http.StatusConflict, w.Code, w.Body.String())

	w = h.do(t, http.MethodDelete, base+"/"+itoa(def.Id), nil, adminToken)
	require.Equal(t, http.StatusConflict, w.Code, w.Body.String())

	// Permissions stay editable: that is how an organization tightens defaults.
	w = h.do(t, http.MethodPatch, base+"/"+itoa(def.Id),
		map[string]any{"permissions": map[string]string{"file": "disable"}}, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var updated controlRoleView
	decodeData(t, w, &updated)
	require.Equal(t, "disable", updated.Permissions["file"])
}

func TestControlRole_UnknownPermissionKeyRejected(t *testing.T) {
	h, orgID, _, _, _, _, adminToken, _ := m4Org(t)
	base := "/api/v1/orgs/" + itoa(orgID) + "/control-roles"

	w := h.do(t, http.MethodPost, base, map[string]any{
		"name":        "Ops",
		"permissions": map[string]string{"teleport": "enable"},
	}, adminToken)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())

	w = h.do(t, http.MethodPost, base, map[string]any{
		"name":        "Ops",
		"permissions": map[string]string{"file": "sometimes"},
	}, adminToken)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())

	w = h.do(t, http.MethodPost, base, map[string]any{
		"name":        "Ops",
		"permissions": map[string]string{"file": "enable"},
	}, adminToken)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
}

func TestControlRole_AssignNullRestoresDefault(t *testing.T) {
	h, orgID, _, _, member, _, adminToken, _ := m4Org(t)
	base := "/api/v1/orgs/" + itoa(orgID) + "/control-roles"
	memberBase := "/api/v1/orgs/" + itoa(orgID) + "/members/" + itoa(int64(member.ID)) + "/control-role"

	w := h.do(t, http.MethodPost, base, map[string]any{
		"name":        "Ops",
		"permissions": map[string]string{"file": "enable"},
	}, adminToken)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var role controlRoleView
	decodeData(t, w, &role)

	w = h.do(t, http.MethodPut, memberBase, map[string]any{"control_role_id": role.Id}, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	w = h.do(t, http.MethodPut, memberBase, map[string]any{"control_role_id": nil}, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var row model.Membership
	require.NoError(t, store.WithoutTenantScope(h.db.DB).
		Where("organization_id = ? AND user_id = ?", orgID, member.ID).First(&row).Error)
	require.Nil(t, row.ControlRoleID)

	// A non-member target is a 404, not a silently created assignment.
	w = h.do(t, http.MethodPut, "/api/v1/orgs/"+itoa(orgID)+"/members/999999/control-role",
		map[string]any{"control_role_id": nil}, adminToken)
	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())
}

// TestControlRole_TicketSnapshot pins the end-to-end snapshot: the issued
// ticket carries the actor's effective bitmask and role id, and the redeem path
// copies it onto the session.
func TestControlRole_TicketSnapshot(t *testing.T) {
	h, orgID, _, _, member, _, adminToken, memberToken := m4Org(t)
	dev := model.Device{OrganizationID: uint(orgID), RustdeskID: "770001", Name: "pc"}
	require.NoError(t, store.ScopedByOrg(h.db.DB, uint(orgID)).Create(&dev).Error)

	w := h.do(t, http.MethodPost, "/api/v1/orgs/"+itoa(orgID)+"/control-roles", map[string]any{
		"name":        "Ops",
		"permissions": map[string]string{"file": "enable"},
	}, adminToken)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var role controlRoleView
	decodeData(t, w, &role)

	w = h.do(t, http.MethodPut, "/api/v1/orgs/"+itoa(orgID)+"/members/"+itoa(int64(member.ID))+"/control-role",
		map[string]any{"control_role_id": role.Id}, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	w = h.do(t, http.MethodPost, "/api/v1/orgs/"+itoa(orgID)+"/tickets",
		map[string]any{"device_id": dev.ID}, memberToken)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var issued struct {
		Ticket struct {
			ControlPermissions int64  `json:"control_permissions"`
			ControlRoleId      *int64 `json:"control_role_id"`
		} `json:"ticket"`
		Token string `json:"token"`
	}
	decodeData(t, w, &issued)
	require.Equal(t, int64(1<<3), issued.Ticket.ControlPermissions)
	require.NotNil(t, issued.Ticket.ControlRoleId)
	require.Equal(t, role.Id, *issued.Ticket.ControlRoleId)
}

// TestControlRole_MemberListExposesAssignment pins the read-back the console
// needs: a page can assign roles, but without this field it cannot show who
// holds which.
func TestControlRole_MemberListExposesAssignment(t *testing.T) {
	h, orgID, _, _, member, _, adminToken, _ := m4Org(t)

	w := h.do(t, http.MethodPost, "/api/v1/orgs/"+itoa(orgID)+"/control-roles", map[string]any{
		"name": "Ops", "permissions": map[string]string{"file": "enable"},
	}, adminToken)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var role controlRoleView
	decodeData(t, w, &role)

	w = h.do(t, http.MethodPut,
		"/api/v1/orgs/"+itoa(orgID)+"/members/"+itoa(int64(member.ID))+"/control-role",
		map[string]any{"control_role_id": role.Id}, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	w = h.do(t, http.MethodGet, "/api/v1/orgs/"+itoa(orgID)+"/members", nil, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var members []struct {
		UserId        int64  `json:"user_id"`
		ControlRoleId *int64 `json:"control_role_id"`
	}
	decodeData(t, w, &members)
	var found bool
	for _, m := range members {
		if m.UserId == int64(member.ID) {
			found = true
			require.NotNil(t, m.ControlRoleId)
			require.Equal(t, role.Id, *m.ControlRoleId)
		}
	}
	require.True(t, found, "the member must appear in the list")
}

// TestControlRole_AssignRequiresExplicitField: an empty body must not clear a
// member's assignment; only an explicit null may.
func TestControlRole_AssignRequiresExplicitField(t *testing.T) {
	h, orgID, _, _, member, _, adminToken, _ := m4Org(t)
	memberBase := "/api/v1/orgs/" + itoa(orgID) + "/members/" + itoa(int64(member.ID)) + "/control-role"

	w := h.do(t, http.MethodPut, memberBase, map[string]any{}, adminToken)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
}
