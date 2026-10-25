package api_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

type m5AccessRuleView struct {
	Id              int64  `json:"id"`
	SourceGroupId   int64  `json:"source_group_id"`
	SourceGroupName string `json:"source_group_name"`
	TargetKind      string `json:"target_kind"`
	TargetGroupId   *int64 `json:"target_group_id"`
	TargetGroupName string `json:"target_group_name"`
}

// TestAccess_AccessRuleEndpoints covers the rule management path: create a
// device-group rule, list it with resolved names, reject a duplicate and a
// kind/id mismatch, and delete it.
func TestAccess_AccessRuleEndpoints(t *testing.T) {
	h, orgID, _, _, _, _, adminToken, memberToken := m4Org(t)
	base := "/api/v1/orgs/" + itoa(orgID)
	rulesURL := base + "/access-rules"

	w := h.do(t, http.MethodPost, base+"/user-groups", map[string]string{"name": "Ops"}, adminToken)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var userGroup m5UserGroupView
	decodeData(t, w, &userGroup)

	w = h.do(t, http.MethodPost, base+"/device-groups", map[string]string{"name": "Servers"}, adminToken)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var deviceGroup m5DeviceGroupView
	decodeData(t, w, &deviceGroup)

	w = h.do(t, http.MethodPost, rulesURL, map[string]any{
		"source_group_id": userGroup.Id,
		"target_kind":     model.AccessTargetKindDeviceGroup,
		"target_group_id": deviceGroup.Id,
	}, adminToken)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var created m5AccessRuleView
	decodeData(t, w, &created)
	require.Equal(t, "Ops", created.SourceGroupName)
	require.Equal(t, model.AccessTargetKindDeviceGroup, created.TargetKind)
	require.NotNil(t, created.TargetGroupId)
	require.Equal(t, deviceGroup.Id, *created.TargetGroupId)
	require.Equal(t, "Servers", created.TargetGroupName)

	// The domain audit replaces the http fallback row.
	var httpRows int64
	require.NoError(t, store.WithoutTenantScope(h.db.DB).Model(&model.AuditLog{}).
		Where("action = ?", "POST /api/v1/orgs/:orgId/access-rules").Count(&httpRows).Error)
	require.Zero(t, httpRows)

	// Duplicate tuple conflicts; a kind/id mismatch is a bad request.
	w = h.do(t, http.MethodPost, rulesURL, map[string]any{
		"source_group_id": userGroup.Id,
		"target_kind":     model.AccessTargetKindDeviceGroup,
		"target_group_id": deviceGroup.Id,
	}, adminToken)
	require.Equal(t, http.StatusConflict, w.Code, w.Body.String())

	w = h.do(t, http.MethodPost, rulesURL, map[string]any{
		"source_group_id": userGroup.Id,
		"target_kind":     model.AccessTargetKindAllDevices,
		"target_group_id": deviceGroup.Id,
	}, adminToken)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())

	w = h.do(t, http.MethodGet, rulesURL, nil, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var rules []m5AccessRuleView
	decodeData(t, w, &rules)
	require.Len(t, rules, 2, "the seeded everyone rule plus the new one")
	var defaultRule *m5AccessRuleView
	for i := range rules {
		if rules[i].Id != created.Id {
			defaultRule = &rules[i]
		}
	}
	require.NotNil(t, defaultRule)
	require.Equal(t, model.EveryoneGroupName, defaultRule.SourceGroupName)
	require.Equal(t, model.AccessTargetKindAllDevices, defaultRule.TargetKind)
	require.Nil(t, defaultRule.TargetGroupId, "all_devices carries a null target id")
	require.Empty(t, defaultRule.TargetGroupName)

	w = h.do(t, http.MethodDelete, rulesURL+"/"+itoa(created.Id), nil, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	w = h.do(t, http.MethodDelete, rulesURL+"/"+itoa(created.Id), nil, adminToken)
	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())

	w = h.do(t, http.MethodGet, rulesURL, nil, memberToken)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
}
