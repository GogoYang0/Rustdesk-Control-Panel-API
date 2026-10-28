package api_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// m6RuleView mirrors the contract's AccessRule shape for the wave-2 target kind.
type m6RuleView struct {
	Id              int64  `json:"id"`
	SourceGroupId   int64  `json:"source_group_id"`
	SourceGroupName string `json:"source_group_name"`
	TargetKind      string `json:"target_kind"`
	TargetGroupId   *int64 `json:"target_group_id"`
	TargetGroupName string `json:"target_group_name"`
}

// TestAccessRule_UserGroupTargetRoundTrip pins Review Focus: a rule whose target
// is a user group must report the target id and name back, or the console can
// neither edit nor re-create the rule it just listed.
func TestAccessRule_UserGroupTargetRoundTrip(t *testing.T) {
	h, orgID, _, _, _, _, adminToken, _ := m4Org(t)
	base := "/api/v1/orgs/" + itoa(orgID)
	rulesPath := base + "/access-rules"

	newGroup := func(name string) int64 {
		w := h.do(t, http.MethodPost, base+"/user-groups", map[string]string{"name": name}, adminToken)
		require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
		var group struct {
			Id int64 `json:"id"`
		}
		decodeData(t, w, &group)
		return group.Id
	}
	source := newGroup("team-a")
	target := newGroup("team-b")

	w := h.do(t, http.MethodPost, rulesPath, map[string]any{
		"source_group_id": source, "target_kind": "user_group", "target_group_id": target,
	}, adminToken)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var created m6RuleView
	decodeData(t, w, &created)
	require.Equal(t, "user_group", created.TargetKind)
	require.NotNil(t, created.TargetGroupId, "the target group id must round-trip")
	require.EqualValues(t, target, *created.TargetGroupId)
	require.Equal(t, "team-b", created.TargetGroupName)
	require.Equal(t, "team-a", created.SourceGroupName)

	// The list must report the same shape as the create response.
	w = h.do(t, http.MethodGet, rulesPath, nil, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var rules []m6RuleView
	decodeData(t, w, &rules)
	var listed *m6RuleView
	for i := range rules {
		if rules[i].Id == created.Id {
			listed = &rules[i]
		}
	}
	require.NotNil(t, listed)
	require.Equal(t, "user_group", listed.TargetKind)
	require.NotNil(t, listed.TargetGroupId)
	require.EqualValues(t, target, *listed.TargetGroupId)
	require.Equal(t, "team-b", listed.TargetGroupName)

	// A user_group target needs its id, and only user groups of this tenant are
	// accepted; both are refused as invalid requests.
	w = h.do(t, http.MethodPost, rulesPath, map[string]any{
		"source_group_id": source, "target_kind": "user_group",
	}, adminToken)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	w = h.do(t, http.MethodPost, rulesPath, map[string]any{
		"source_group_id": source, "target_kind": "user_group", "target_group_id": 999999,
	}, adminToken)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())

	// The all_devices rule keeps reporting a null target.
	w = h.do(t, http.MethodPost, rulesPath, map[string]any{
		"source_group_id": source, "target_kind": "all_devices",
	}, adminToken)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var allDevices m6RuleView
	decodeData(t, w, &allDevices)
	require.Nil(t, allDevices.TargetGroupId)
	require.Empty(t, allDevices.TargetGroupName)
}
