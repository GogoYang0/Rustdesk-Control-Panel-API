package api_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/api"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/audit"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/auth"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/config"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/device"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/session"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// newBoundaryDeps builds a minimal, otherwise valid dependency set.
func newBoundaryDeps(t *testing.T) api.Deps {
	t.Helper()
	dsn := "file:depsboundary_" + sanitize(t.Name()) + "?mode=memory&cache=shared"
	st, err := store.Open(config.DatabaseConfig{Driver: "sqlite", DSN: dsn})
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	require.NoError(t, st.DB.AutoMigrate(
		&model.Organization{}, &model.User{}, &model.Membership{}, &model.Invitation{},
		&model.AuditLog{},
		&model.Device{}, &model.DeviceHeartbeat{},
		&model.CompatSession{},
		&model.Session{}, &model.SessionEvent{}, &model.Policy{}, &model.Ticket{},
		&model.Approval{}, &model.Alert{},
		&model.AddressBook{}, &model.AddressBookPeer{}, &model.AddressBookTag{},
	))
	return api.Deps{
		DB:            st.DB,
		Auth:          auth.NewService(st.DB, auth.NewIssuer("boundary-secret", time.Minute, time.Hour), nil),
		Devices:       device.NewService(st.DB, nil, nil),
		Issuer:        auth.NewIssuer("boundary-secret", time.Minute, time.Hour),
		AccessTTL:     time.Minute,
		RefreshTTL:    time.Hour,
		InvitationTTL: time.Hour,
	}
}

// Without Tickets the API derives the session service from a transactional
// auditor; a non-transactional auditor must refuse to start rather than run
// governance mutations whose audit entries are silently discarded (#58 review).
func TestNewAdminAPI_TicketsNilWithTxRecorderBuilds(t *testing.T) {
	d := newBoundaryDeps(t)
	d.Auditor = audit.NewGormAuditor(d.DB)

	require.NotPanics(t, func() { _ = api.NewAdminAPI(d) })
}

func TestNewAdminAPI_TicketsNilWithNonTxAuditorPanics(t *testing.T) {
	d := newBoundaryDeps(t)
	d.Auditor = audit.Nop{} // implements Auditor but not TxRecorder

	require.PanicsWithValue(t,
		"api: transactional auditor required when Tickets is nil",
		func() { _ = api.NewAdminAPI(d) })
}

// An explicitly injected session service bypasses the derivation entirely:
// the caller owns the wiring and the boundary does not second-guess it.
func TestNewAdminAPI_ExplicitTicketsIsAcceptedAsIs(t *testing.T) {
	d := newBoundaryDeps(t)
	d.Auditor = audit.Nop{} // deliberately non-transactional
	d.Tickets = session.NewService(d.DB, audit.NewGormAuditor(d.DB), nil)

	require.NotPanics(t, func() { _ = api.NewAdminAPI(d) })
}
