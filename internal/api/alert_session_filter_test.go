package api_test

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

func seedSessionAlert(t *testing.T, h *harness, orgID int64, sessionID *uint, createdAt time.Time) {
	t.Helper()
	row := model.Alert{
		OrganizationID: uint(orgID),
		SessionID:      sessionID,
		Kind:           model.AlertKindDurationExceeded,
		Severity:       model.AlertSeverityCritical,
		DetailJSON:     `{"limit":30}`,
		CreatedAt:      createdAt,
	}
	require.NoError(t, store.WithoutTenantScope(h.db.DB).Create(&row).Error)
}

// Decodes into a fresh value: reusing one struct across responses keeps stale
// values for fields the next JSON body omits (`session_id` is omitempty).
func getAlertList(t *testing.T, h *harness, token, path string) alertListBody {
	t.Helper()
	w := h.do(t, http.MethodGet, path, nil, token)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var list alertListBody
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &list))
	return list
}

// The session side sheet asks for the alerts of one session. Filtering the
// time-ordered page in the client would silently miss rows in a busy inbox.
func TestAlert_ListFiltersBySession(t *testing.T) {
	h := newTicketHarness(t)
	owner, orgID := seedOrgOwner(t, h, "alert-session@example.com")

	first, second := uint(11), uint(22)
	seedSessionAlert(t, h, orgID, &first, fixedNow)
	seedSessionAlert(t, h, orgID, &first, fixedNow.Add(time.Minute))
	seedSessionAlert(t, h, orgID, &second, fixedNow.Add(2*time.Minute))
	seedSessionAlert(t, h, orgID, nil, fixedNow.Add(3*time.Minute))

	list := getAlertList(t, h, owner, alertsPath(orgID)+"?sessionId=11")
	require.Equal(t, int64(2), list.Data.Total)
	require.Len(t, list.Data.Items, 2)
	for _, item := range list.Data.Items {
		require.NotNil(t, item.SessionId)
		require.Equal(t, int64(11), *item.SessionId)
	}

	// Non-positive ids are a bad parameter, not an empty page: an empty page
	// would read as "this session caused no alerts".
	for _, query := range []string{"?sessionId=0", "?sessionId=-1"} {
		w := h.do(t, http.MethodGet, alertsPath(orgID)+query, nil, owner)
		require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	}

	// Pagination counts every matching row; the page only carries its slice.
	list = getAlertList(t, h, owner, alertsPath(orgID)+"?sessionId=11&page=2&pageSize=1")
	require.Equal(t, int64(2), list.Data.Total)
	require.Len(t, list.Data.Items, 1)

	// Unknown ids are a legitimate empty page.
	list = getAlertList(t, h, owner, alertsPath(orgID)+"?sessionId=999")
	require.Equal(t, int64(0), list.Data.Total)

	// Without the filter the organization-level alert (session_id = NULL) is
	// still part of the inbox; only the session filter hides it.
	list = getAlertList(t, h, owner, alertsPath(orgID))
	require.Equal(t, int64(4), list.Data.Total)
	var orphan int
	for _, item := range list.Data.Items {
		if item.SessionId == nil {
			orphan++
		}
	}
	require.Equal(t, 1, orphan)
}
