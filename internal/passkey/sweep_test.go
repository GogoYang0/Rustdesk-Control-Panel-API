package passkey

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
)

func TestSweep_RemovesExpiredCeremoniesOnly(t *testing.T) {
	svc, clock := newCeremonyService(t)
	db := svc.db
	ctx := context.Background()

	// Expired row.
	require.NoError(t, db.Create(&model.WebAuthnCeremony{
		Handle: "expired", Purpose: model.CeremonyLogin, SessionJSON: "{}",
		ExpiresAt: clock.at.Add(-time.Minute),
	}).Error)
	// Live row.
	require.NoError(t, db.Create(&model.WebAuthnCeremony{
		Handle: "live", Purpose: model.CeremonyLogin, SessionJSON: "{}",
		ExpiresAt: clock.at.Add(time.Minute),
	}).Error)
	// Consumed but not yet expired: still live enough to keep the row until TTL.
	consumedAt := clock.at.Add(-time.Second)
	require.NoError(t, db.Create(&model.WebAuthnCeremony{
		Handle: "consumed", Purpose: model.CeremonyRegister, SessionJSON: "{}",
		ExpiresAt: clock.at.Add(time.Minute), ConsumedAt: &consumedAt,
	}).Error)

	removed, err := svc.Sweep(ctx, clock.at)
	require.NoError(t, err)
	require.EqualValues(t, 1, removed)

	var handles []string
	require.NoError(t, db.Model(&model.WebAuthnCeremony{}).Pluck("handle", &handles).Error)
	require.ElementsMatch(t, []string{"live", "consumed"}, handles)
}
