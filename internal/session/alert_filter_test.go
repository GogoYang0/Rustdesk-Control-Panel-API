package session_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/session"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// The session detail view links a session to the alerts it caused. Without a
// session filter the client can only scan a time-ordered window of the inbox,
// so a busy organization silently shows "no alerts" for a session whose rows
// are merely off-page.
func TestListAlerts_FiltersBySession(t *testing.T) {
	h := newHarness(t)
	target := h.seedPanelSession(t, h.device.ID, h.now.Add(-time.Hour))
	other := h.seedPanelSession(t, h.device.ID, h.now.Add(-2*time.Hour))

	seed := func(sessionID *uint, at time.Time) {
		t.Helper()
		row := model.Alert{
			OrganizationID: h.org.ID,
			SessionID:      sessionID,
			DeviceID:       &h.device.ID,
			Kind:           model.AlertKindDurationExceeded,
			Severity:       model.AlertSeverityCritical,
			DetailJSON:     `{"limit":30}`,
			CreatedAt:      at,
		}
		require.NoError(t, store.WithoutTenantScope(h.db).Create(&row).Error)
	}
	seed(&target.ID, h.now.Add(-59*time.Minute))
	seed(&target.ID, h.now.Add(-58*time.Minute))
	seed(&other.ID, h.now.Add(-57*time.Minute))
	seed(nil, h.now.Add(-56*time.Minute)) // organization-level alert, no session

	// Baseline: the unfiltered list still sees every row.
	_, total, err := h.svc.ListAlerts(context.Background(), h.org.ID, session.AlertFilter{})
	require.NoError(t, err)
	require.Equal(t, int64(4), total)

	items, total, err := h.svc.ListAlerts(context.Background(), h.org.ID, session.AlertFilter{
		SessionID: &target.ID,
	})
	require.NoError(t, err)
	require.Equal(t, int64(2), total)
	require.Len(t, items, 2)
	for _, item := range items {
		require.NotNil(t, item.SessionID)
		require.Equal(t, target.ID, *item.SessionID)
	}

	// The filter must not widen the tenant scope: another organization sees
	// nothing even though it asks for a session id of this one.
	otherOrg := model.Organization{Name: "other-org"}
	require.NoError(t, h.db.Create(&otherOrg).Error)
	_, total, err = h.svc.ListAlerts(context.Background(), otherOrg.ID, session.AlertFilter{
		SessionID: &target.ID,
	})
	require.NoError(t, err)
	require.Equal(t, int64(0), total)

	// An unknown session id is an empty page, not an error.
	missing := uint(999999)
	items, total, err = h.svc.ListAlerts(context.Background(), h.org.ID, session.AlertFilter{
		SessionID: &missing,
	})
	require.NoError(t, err)
	require.Equal(t, int64(0), total)
	require.Empty(t, items)
}
