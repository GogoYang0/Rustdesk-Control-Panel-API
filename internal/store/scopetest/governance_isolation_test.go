package scopetest

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// TestGovernance_TenantIsolation seeds one row per governance table in org A and
// asserts org B can neither read it nor count it.
//
// Registration is covered by TestScopedModels_CoverSessionGovernanceTables; this
// test covers the other half — that a registered table actually filters, with the
// real column set (a model whose tenant column is misnamed still registers fine).
func TestGovernance_TenantIsolation(t *testing.T) {
	db, cleanup := newDB(t)
	defer cleanup()

	require.NoError(t, db.AutoMigrate(
		&model.Device{}, &model.Session{}, &model.SessionEvent{}, &model.Ticket{},
		&model.Policy{}, &model.Approval{}, &model.Alert{},
		&model.UserGroup{}, &model.UserGroupMember{}, &model.DeviceGroup{}, &model.AccessRule{},
	))

	orgA := model.Organization{Name: "gov-iso-a"}
	orgB := model.Organization{Name: "gov-iso-b"}
	require.NoError(t, db.Create(&orgA).Error)
	require.NoError(t, db.Create(&orgB).Error)

	now := time.Now().UTC().Truncate(time.Second)
	deviceA := model.Device{OrganizationID: orgA.ID, RustdeskID: "100000001", Name: "iso-device"}
	require.NoError(t, db.Create(&deviceA).Error)

	groupA := model.UserGroup{OrganizationID: orgA.ID, Name: "iso-group", Kind: model.UserGroupKindCustom}
	require.NoError(t, db.Create(&groupA).Error)

	sessionA := model.Session{
		OrganizationID: orgA.ID, DeviceID: deviceA.ID, RustdeskID: deviceA.RustdeskID,
		Origin: model.SessionOriginPanel, Status: model.SessionStatusOpen, StartedAt: now,
	}
	require.NoError(t, db.Create(&sessionA).Error)

	rows := []struct {
		name string
		// model is the GORM model used for counting.
		model any
		row   any
		// created marks a row that had to exist before the loop (the session
		// other rows point at), so it must not be inserted twice.
		created bool
	}{
		{"sessions", &model.Session{}, &sessionA, true},
		{"session_events", &model.SessionEvent{}, &model.SessionEvent{
			OrganizationID: orgA.ID, SessionID: sessionA.ID, Kind: "started", At: now,
		}, false},
		{"tickets", &model.Ticket{}, &model.Ticket{
			OrganizationID: orgA.ID, DeviceID: deviceA.ID, ActorUserID: 1,
			TokenHash: "hash-a", ExpiresAt: now.Add(5 * time.Minute),
		}, false},
		{"policies", &model.Policy{}, &model.Policy{
			OrganizationID: orgA.ID, Name: "default", Enabled: true, RequireApproval: false,
		}, false},
		{"approvals", &model.Approval{}, &model.Approval{
			OrganizationID: orgA.ID, DeviceID: deviceA.ID, Kind: model.ApprovalKindPre,
			ActorUserID: 1, Status: model.ApprovalStatusPending,
			RequestedAt: now, ExpiresAt: now.Add(15 * time.Minute),
		}, false},
		{"alerts", &model.Alert{}, &model.Alert{
			OrganizationID: orgA.ID, SessionID: &sessionA.ID, DeviceID: &deviceA.ID,
			Kind: model.AlertKindDurationExceeded, Severity: model.AlertSeverityWarning,
			CreatedAt: now,
		}, false},
		{"user_groups", &model.UserGroup{}, &groupA, true},
		{"user_group_members", &model.UserGroupMember{}, &model.UserGroupMember{
			OrganizationID: orgA.ID, GroupID: groupA.ID, UserID: 1,
		}, false},
		{"device_groups", &model.DeviceGroup{}, &model.DeviceGroup{
			OrganizationID: orgA.ID, Name: "iso-device-group",
		}, false},
		{"access_rules", &model.AccessRule{}, &model.AccessRule{
			OrganizationID: orgA.ID, SourceGroupID: groupA.ID,
			TargetKind: model.AccessTargetKindAllDevices, TargetGroupID: 0,
		}, false},
	}

	for _, tc := range rows {
		t.Run(tc.name, func(t *testing.T) {
			if !tc.created {
				require.NoError(t, db.Create(tc.row).Error)
			}

			// Org A sees its own row.
			var mine int64
			require.NoError(t, store.ScopedByOrg(db, orgA.ID).
				Model(tc.model).Count(&mine).Error)
			require.EqualValues(t, 1, mine, "org A must see its own row")

			// Org B sees nothing, and a caller-supplied filter does not help.
			var theirs int64
			require.NoError(t, store.ScopedByOrg(db, orgB.ID).
				Model(tc.model).Count(&theirs).Error)
			require.Zero(t, theirs, "org B must not see org A rows")

			// Zero org fails closed.
			var zero int64
			require.NoError(t, store.ScopedByOrg(db, 0).
				Model(tc.model).Count(&zero).Error)
			require.Zero(t, zero, "a missing tenant context must match nothing")
		})
	}
}

// The contract promises a 409 when a policy name repeats inside an
// organization, and allows the same name in another organization.
func TestPolicy_NameUniquePerOrganization(t *testing.T) {
	db, cleanup := newDB(t)
	defer cleanup()
	require.NoError(t, db.AutoMigrate(&model.Policy{}))

	orgA := model.Organization{Name: "policy-uniq-a"}
	orgB := model.Organization{Name: "policy-uniq-b"}
	require.NoError(t, db.Create(&orgA).Error)
	require.NoError(t, db.Create(&orgB).Error)

	require.NoError(t, db.Create(&model.Policy{
		OrganizationID: orgA.ID, Name: "default", Enabled: true,
	}).Error)

	err := db.Create(&model.Policy{OrganizationID: orgA.ID, Name: "default", Enabled: true}).Error
	require.ErrorIs(t, err, gorm.ErrDuplicatedKey, "duplicate policy name inside one organization must conflict")

	require.NoError(t, db.Create(&model.Policy{
		OrganizationID: orgB.ID, Name: "default", Enabled: true,
	}).Error, "the same name in another organization is a different policy")
}

// Only the digest of a ticket token is stored, and it is unique so a replayed
// token cannot resolve to two rows.
func TestTicket_TokenHashUnique(t *testing.T) {
	db, cleanup := newDB(t)
	defer cleanup()
	require.NoError(t, db.AutoMigrate(&model.Ticket{}))

	org := model.Organization{Name: "ticket-uniq"}
	require.NoError(t, db.Create(&org).Error)

	base := model.Ticket{
		OrganizationID: org.ID, DeviceID: 1, ActorUserID: 1,
		TokenHash: "same-digest", ExpiresAt: time.Now().Add(time.Minute),
	}
	require.NoError(t, db.Create(&base).Error)

	err := db.Create(&model.Ticket{
		OrganizationID: org.ID, DeviceID: 2, ActorUserID: 1,
		TokenHash: "same-digest", ExpiresAt: time.Now().Add(time.Minute),
	}).Error
	require.ErrorIs(t, err, gorm.ErrDuplicatedKey, "a duplicated token digest must be rejected")
}
