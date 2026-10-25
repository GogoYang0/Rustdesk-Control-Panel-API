package api_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

type auditRetentionView struct {
	AuditRetentionDays int             `json:"audit_retention_days"`
	LastArchive        *map[string]any `json:"last_archive"`
}

func TestAuditRetention_OwnerOnlyAndValidation(t *testing.T) {
	h, orgID, _, _, _, ownerToken, adminToken, memberToken := m4Org(t)
	path := "/api/v1/orgs/" + itoa(orgID) + "/audit-retention"

	w := h.do(t, http.MethodGet, path, nil, ownerToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var initial auditRetentionView
	decodeData(t, w, &initial)
	require.Zero(t, initial.AuditRetentionDays)
	require.Nil(t, initial.LastArchive)

	// Only the owner holds org.admin.
	for _, token := range []string{adminToken, memberToken} {
		w = h.do(t, http.MethodPut, path, map[string]any{"days": 30}, token)
		require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	}

	w = h.do(t, http.MethodPut, path, map[string]any{"days": 30}, ownerToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var updated auditRetentionView
	decodeData(t, w, &updated)
	require.Equal(t, 30, updated.AuditRetentionDays)

	w = h.do(t, http.MethodGet, path, nil, ownerToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var read auditRetentionView
	decodeData(t, w, &read)
	require.Equal(t, 30, read.AuditRetentionDays)

	for _, days := range []int{-1, 3651} {
		w = h.do(t, http.MethodPut, path, map[string]any{"days": days}, ownerToken)
		require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	}

	// A body without days must not silently mean "keep forever".
	w = h.do(t, http.MethodPut, path, map[string]any{}, ownerToken)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())

	// Zero is a valid setting (keep forever).
	w = h.do(t, http.MethodPut, path, map[string]any{"days": 0}, ownerToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	require.NotZero(t, countAudit(t, h, "action = ?", "organization.audit_retention.set"))

	// Another tenant cannot read or write this setting.
	h.seedUser(t, "retention-other@example.com", "password123")
	otherToken := h.login(t, "retention-other@example.com", "password123")
	createOrg(t, h, otherToken, "retention-other-org")
	w = h.do(t, http.MethodGet, path, nil, otherToken)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	w = h.do(t, http.MethodPut, path, map[string]any{"days": 7}, otherToken)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
}
