package controlrole_test

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/audit"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/controlrole"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// fakeRecorder collects the audit entries the service writes on its
// transaction; the project refuses unaudited domain writes, so every mutation
// test asserts on it.
type fakeRecorder struct {
	entries []audit.Entry
	fail    error
}

func (f *fakeRecorder) RecordTx(_ *gorm.DB, e audit.Entry) error {
	if f.fail != nil {
		return f.fail
	}
	f.entries = append(f.entries, e)
	return nil
}

func (f *fakeRecorder) actions() []string {
	out := make([]string, 0, len(f.entries))
	for _, e := range f.entries {
		out = append(out, e.Action)
	}
	return out
}

type fixture struct {
	svc      *controlrole.Service
	db       *gorm.DB
	recorder *fakeRecorder
	org      model.Organization
	otherOrg model.Organization
	user     model.User
	other    model.User
	member   model.Membership
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	s := openMigrateStore(t)
	t.Cleanup(func() { _ = s.Close() })
	require.NoError(t, s.DB.AutoMigrate(
		&model.Organization{}, &model.User{}, &model.Membership{}, &model.ControlRole{},
	))
	f := &fixture{db: s.DB, recorder: &fakeRecorder{}}

	f.org = model.Organization{Name: "acme"}
	f.otherOrg = model.Organization{Name: "globex"}
	require.NoError(t, f.db.Create(&f.org).Error)
	require.NoError(t, f.db.Create(&f.otherOrg).Error)

	// Emails are globally unique and CI's test-db job shares one PostgreSQL
	// database across tests, so a fixed address would collide on the second
	// fixture (idx_users_email).
	f.user = model.User{Email: fmt.Sprintf("alice-%d@example.com", userSeq.Add(1)), PasswordHash: "x", EmailVerified: true}
	f.other = model.User{Email: fmt.Sprintf("bob-%d@example.com", userSeq.Add(1)), PasswordHash: "x", EmailVerified: true}
	require.NoError(t, f.db.Create(&f.user).Error)
	require.NoError(t, f.db.Create(&f.other).Error)

	f.member = model.Membership{OrganizationID: f.org.ID, UserID: f.user.ID, RoleID: 1}
	require.NoError(t, f.db.Create(&f.member).Error)

	now := func() time.Time { return time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC) }
	require.NoError(t, controlrole.Migrate(f.db, now))
	f.svc = controlrole.NewService(f.db, f.recorder, now)
	return f
}

var userSeq atomic.Int64

func (f *fixture) defaultRole(t *testing.T) model.ControlRole {
	t.Helper()
	var role model.ControlRole
	require.NoError(t, store.ScopedByOrg(f.db, f.org.ID).
		Where("kind = ?", model.KindControlRoleDefault).First(&role).Error)
	return role
}

func TestNormalize_RejectsUnknownKey(t *testing.T) {
	_, err := controlrole.Permissions{"keyboard": controlrole.StateEnable, "teleport": controlrole.StateDisable}.Normalize()
	require.ErrorIs(t, err, controlrole.ErrUnknownPermissionKey)
}

func TestNormalize_RejectsUnknownState(t *testing.T) {
	_, err := controlrole.Permissions{"keyboard": controlrole.State("maybe")}.Normalize()
	require.ErrorIs(t, err, controlrole.ErrInvalidPermissionState)
}

func TestNormalize_FillsMissingWithUseClient(t *testing.T) {
	got, err := controlrole.Permissions{"file": controlrole.StateEnable}.Normalize()
	require.NoError(t, err)
	require.Len(t, got, len(controlrole.Keys()))
	require.Equal(t, controlrole.StateEnable, got["file"])
	require.Equal(t, controlrole.StateUseClient, got["keyboard"])
}

func TestMask_OnlyEnableBits(t *testing.T) {
	// keyboard is bit 0, file is bit 3, usb is bit 13; disable must not set a bit.
	p := controlrole.Permissions{
		"keyboard":  controlrole.StateEnable,
		"file":      controlrole.StateEnable,
		"usb":       controlrole.StateDisable,
		"clipboard": controlrole.StateUseClient,
	}
	require.Equal(t, uint64(1|1<<3), p.Mask())
}

func TestCreate_PersistsAndAudits(t *testing.T) {
	f := newFixture(t)
	role, err := f.svc.Create(context.Background(), f.org.ID, f.user.ID, "Ops",
		controlrole.Permissions{"file": controlrole.StateEnable})
	require.NoError(t, err)
	require.Equal(t, model.KindControlRoleCustom, role.Kind)
	require.Contains(t, f.recorder.actions(), "control_role.create")

	var stored model.ControlRole
	require.NoError(t, store.ScopedByOrg(f.db, f.org.ID).First(&stored, role.ID).Error)
	require.Contains(t, stored.PermissionsJSON, `"file":"enable"`)
}

func TestCreate_RejectsDuplicateName(t *testing.T) {
	f := newFixture(t)
	_, err := f.svc.Create(context.Background(), f.org.ID, f.user.ID, "Ops", nil)
	require.NoError(t, err)
	_, err = f.svc.Create(context.Background(), f.org.ID, f.user.ID, "Ops", nil)
	require.ErrorIs(t, err, controlrole.ErrDuplicateName)
}

func TestCreate_RejectsBlankName(t *testing.T) {
	f := newFixture(t)
	_, err := f.svc.Create(context.Background(), f.org.ID, f.user.ID, "   ", nil)
	require.ErrorIs(t, err, controlrole.ErrInvalidName)
}

func TestDelete_RejectsBuiltinDefault(t *testing.T) {
	f := newFixture(t)
	def := f.defaultRole(t)
	require.ErrorIs(t, f.svc.Delete(context.Background(), f.org.ID, f.user.ID, def.ID),
		controlrole.ErrBuiltinImmutable)
}

func TestDelete_ClearsMemberAssignments(t *testing.T) {
	f := newFixture(t)
	role, err := f.svc.Create(context.Background(), f.org.ID, f.user.ID, "Ops", nil)
	require.NoError(t, err)
	require.NoError(t, f.svc.Assign(context.Background(), f.org.ID, f.user.ID, f.user.ID, &role.ID))

	require.NoError(t, f.svc.Delete(context.Background(), f.org.ID, f.user.ID, role.ID))

	var m model.Membership
	require.NoError(t, store.ScopedByOrg(f.db, f.org.ID).First(&m, f.member.ID).Error)
	require.Nil(t, m.ControlRoleID)
	require.Contains(t, f.recorder.actions(), "control_role.delete")
}

func TestUpdate_DefaultRoleKeepsName(t *testing.T) {
	f := newFixture(t)
	def := f.defaultRole(t)
	newName := "Renamed"
	_, err := f.svc.Update(context.Background(), f.org.ID, f.user.ID, def.ID, &newName, nil)
	require.ErrorIs(t, err, controlrole.ErrBuiltinImmutable)

	perms := controlrole.Permissions{"file": controlrole.StateDisable}
	updated, err := f.svc.Update(context.Background(), f.org.ID, f.user.ID, def.ID, nil, &perms)
	require.NoError(t, err)
	require.Equal(t, controlrole.DefaultRoleName, updated.Name)
}

func TestAssign_NullRestoresDefault(t *testing.T) {
	f := newFixture(t)
	role, err := f.svc.Create(context.Background(), f.org.ID, f.user.ID, "Ops", nil)
	require.NoError(t, err)
	require.NoError(t, f.svc.Assign(context.Background(), f.org.ID, f.user.ID, f.user.ID, &role.ID))
	require.NoError(t, f.svc.Assign(context.Background(), f.org.ID, f.user.ID, f.user.ID, nil))

	var m model.Membership
	require.NoError(t, store.ScopedByOrg(f.db, f.org.ID).First(&m, f.member.ID).Error)
	require.Nil(t, m.ControlRoleID)
}

func TestAssign_RejectsRoleFromAnotherOrganization(t *testing.T) {
	f := newFixture(t)
	foreign := model.ControlRole{
		OrganizationID:  f.otherOrg.ID,
		Name:            "Foreign",
		Kind:            model.KindControlRoleCustom,
		PermissionsJSON: `{}`,
	}
	require.NoError(t, store.ScopedByOrg(f.db, f.otherOrg.ID).Create(&foreign).Error)
	require.ErrorIs(t,
		f.svc.Assign(context.Background(), f.org.ID, f.user.ID, f.user.ID, &foreign.ID),
		controlrole.ErrNotFound)
}

func TestEffectiveFor_FallsBackToDefault(t *testing.T) {
	f := newFixture(t)
	perms, mask, roleID, err := f.svc.EffectiveFor(context.Background(), f.org.ID, f.user.ID)
	require.NoError(t, err)
	require.Equal(t, uint64(0), mask)
	def := f.defaultRole(t)
	require.NotNil(t, roleID)
	require.Equal(t, def.ID, *roleID)
	require.Equal(t, controlrole.StateUseClient, perms["keyboard"])
}

func TestEffectiveFor_UsesAssignedRoleMask(t *testing.T) {
	f := newFixture(t)
	role, err := f.svc.Create(context.Background(), f.org.ID, f.user.ID, "Ops",
		controlrole.Permissions{"file": controlrole.StateEnable})
	require.NoError(t, err)
	require.NoError(t, f.svc.Assign(context.Background(), f.org.ID, f.user.ID, f.user.ID, &role.ID))

	_, mask, roleID, err := f.svc.EffectiveFor(context.Background(), f.org.ID, f.user.ID)
	require.NoError(t, err)
	require.Equal(t, uint64(1<<3), mask)
	require.Equal(t, role.ID, *roleID)
}

func TestService_RequiresRecorder(t *testing.T) {
	f := newFixture(t)
	svc := controlrole.NewService(f.db, nil, nil)
	_, err := svc.Create(context.Background(), f.org.ID, f.user.ID, "Ops", nil)
	require.Error(t, err)
}

func TestDelete_UnknownRoleIsNotFound(t *testing.T) {
	f := newFixture(t)
	err := f.svc.Delete(context.Background(), f.org.ID, f.user.ID, 9999)
	require.ErrorIs(t, err, controlrole.ErrNotFound)
	require.False(t, errors.Is(err, controlrole.ErrBuiltinImmutable))
}

// TestCreate_IsolatesOrganizations pins that two organizations may use the same
// role name: the unique index is per organization, not global.
func TestCreate_IsolatesOrganizations(t *testing.T) {
	f := newFixture(t)
	_, err := f.svc.Create(context.Background(), f.org.ID, f.user.ID, "Ops", nil)
	require.NoError(t, err)
	_, err = f.svc.Create(context.Background(), f.otherOrg.ID, f.user.ID, "Ops", nil)
	require.NoError(t, err)
}
