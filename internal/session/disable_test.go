package session_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/session"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// A ticket issued before a device was disabled must not open a panel session
// afterwards: the redemption is the access decision, not the issuance.
func TestRedeem_RejectsDisabledDevice(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	ticket, token, err := h.svc.Issue(ctx, session.IssueInput{
		OrganizationID: h.org.ID, ActorUserID: 1, DeviceID: h.device.ID,
	})
	require.NoError(t, err)

	require.NoError(t, store.ScopedByOrg(h.db, h.org.ID).Model(&model.Device{}).
		Where("id = ?", h.device.ID).Update("disabled", true).Error)

	_, err = h.svc.Redeem(ctx, h.org.ID, 1, ticket.ID, token)
	require.ErrorIs(t, err, session.ErrDeviceDisabled)

	var stored model.Ticket
	require.NoError(t, store.WithoutTenantScope(h.db).First(&stored, ticket.ID).Error)
	require.Nil(t, stored.UsedAt, "a refused redemption must not consume the ticket")

	var sessions int64
	require.NoError(t, store.ScopedByOrg(h.db, h.org.ID).Model(&model.Session{}).Count(&sessions).Error)
	require.Zero(t, sessions, "no panel session may exist for a disabled device")
}
