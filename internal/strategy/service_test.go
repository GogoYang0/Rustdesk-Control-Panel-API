package strategy_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/audit"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/config"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/strategy"
)

// fakeRecorder collects the audit entries written on the service transaction.
// Every mutation must leave exactly one, so the tests assert on this rather
// than on a log line.
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

var fixtureSeq atomic.Int64

type fixture struct {
	svc      *strategy.Service
	db       *gorm.DB
	recorder *fakeRecorder
	org      model.Organization
	otherOrg model.Organization
	user     model.User
	device   model.Device
	group    model.DeviceGroup
	now      time.Time
}

func openTestStore(t *testing.T) *store.Store {
	t.Helper()
	switch {
	case os.Getenv("TEST_POSTGRES_DSN") != "":
		s, err := store.Open(config.DatabaseConfig{Driver: "postgres", DSN: os.Getenv("TEST_POSTGRES_DSN")})
		require.NoError(t, err)
		return s
	case os.Getenv("TEST_MYSQL_DSN") != "":
		s, err := store.Open(config.DatabaseConfig{Driver: "mysql", DSN: os.Getenv("TEST_MYSQL_DSN")})
		require.NoError(t, err)
		return s
	}
	s, err := store.Open(config.DatabaseConfig{
		Driver: "sqlite",
		DSN:    fmt.Sprintf("file:strategy_%d?mode=memory&cache=shared", fixtureSeq.Add(1)),
	})
	require.NoError(t, err)
	return s
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	st := openTestStore(t)
	t.Cleanup(func() { _ = st.Close() })
	require.NoError(t, st.DB.AutoMigrate(
		&model.Organization{}, &model.User{}, &model.Membership{},
		&model.Device{}, &model.DeviceGroup{}, &model.Strategy{}, &model.DeviceDisconnect{},
		&model.DeviceHeartbeat{},
	))

	n := fixtureSeq.Add(1)
	f := &fixture{db: st.DB, recorder: &fakeRecorder{}, now: time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)}

	// CI's test-db job shares one PostgreSQL database across packages, so every
	// fixture identifier carries its own sequence (idx_org_name / idx_users_email).
	f.org = model.Organization{Name: fmt.Sprintf("acme-%d", n)}
	f.otherOrg = model.Organization{Name: fmt.Sprintf("globex-%d", n)}
	require.NoError(t, f.db.Create(&f.org).Error)
	require.NoError(t, f.db.Create(&f.otherOrg).Error)

	f.user = model.User{
		Email: fmt.Sprintf("alice-%d@example.com", n), PasswordHash: "x", EmailVerified: true,
	}
	require.NoError(t, f.db.Create(&f.user).Error)
	require.NoError(t, f.db.Create(&model.Membership{
		OrganizationID: f.org.ID, UserID: f.user.ID,
	}).Error)

	f.device = model.Device{
		OrganizationID: f.org.ID, RustdeskID: fmt.Sprintf("dev-%d", n), Name: "pc",
		OwnerUserID: &f.user.ID,
	}
	require.NoError(t, store.ScopedByOrg(f.db, f.org.ID).Create(&f.device).Error)
	f.group = model.DeviceGroup{OrganizationID: f.org.ID, Name: fmt.Sprintf("site-%d", n)}
	require.NoError(t, store.ScopedByOrg(f.db, f.org.ID).Create(&f.group).Error)

	f.svc = strategy.NewService(f.db, f.recorder, func() time.Time { return f.now })
	return f
}

func (f *fixture) create(t *testing.T, name string, opts map[string]string) *model.Strategy {
	t.Helper()
	s, err := f.svc.Create(context.Background(), f.org.ID, f.user.ID, name, opts)
	require.NoError(t, err)
	return s
}

func TestCreate_PersistsVersionOneAndAudits(t *testing.T) {
	f := newFixture(t)
	s := f.create(t, "Baseline", map[string]string{"enable-audio": "N"})

	require.EqualValues(t, 1, s.Version)
	require.True(t, s.Enabled)
	require.Equal(t, f.org.ID, s.OrganizationID)
	require.Contains(t, s.ConfigOptionsJSON, `"enable-audio":"N"`)
	require.Equal(t, []string{"strategy.create"}, f.recorder.actions())
	require.Equal(t, "strategy", f.recorder.entries[0].TargetType)
	require.Equal(t, fmt.Sprint(s.ID), f.recorder.entries[0].TargetID)
}

func TestCreate_RejectsDuplicateNameCaseInsensitive(t *testing.T) {
	f := newFixture(t)
	f.create(t, "Baseline", nil)

	// The CLI resolves strategy_name case-insensitively, so "baseline" and
	// "Baseline" must not coexist: the lookup would be ambiguous.
	_, err := f.svc.Create(context.Background(), f.org.ID, f.user.ID, "baseline", nil)
	require.ErrorIs(t, err, strategy.ErrDuplicateName)
}

func TestCreate_CrossOrgSameNameAllowed(t *testing.T) {
	f := newFixture(t)
	f.create(t, "Baseline", nil)
	_, err := f.svc.Create(context.Background(), f.otherOrg.ID, f.user.ID, "Baseline", nil)
	require.NoError(t, err)
}

func TestCreate_RejectsUnknownOption(t *testing.T) {
	f := newFixture(t)
	_, err := f.svc.Create(context.Background(), f.org.ID, f.user.ID, "Takeover",
		map[string]string{"api-server": "evil.example.com"})
	require.ErrorIs(t, err, strategy.ErrUnknownOption)

	var rows int64
	require.NoError(t, store.WithoutTenantScope(f.db).Model(&model.Strategy{}).Count(&rows).Error)
	require.Zero(t, rows, "a rejected option must not leave a row behind")
}

func TestCreate_RejectsInvalidName(t *testing.T) {
	f := newFixture(t)
	for _, name := range []string{"", "   ", string(make([]rune, 65))} {
		_, err := f.svc.Create(context.Background(), f.org.ID, f.user.ID, name, nil)
		require.ErrorIs(t, err, strategy.ErrInvalidName, "name %q must be rejected", name)
	}
}

func TestCreate_WithoutRecorderFailsClosed(t *testing.T) {
	f := newFixture(t)
	svc := strategy.NewService(f.db, nil, nil)
	_, err := svc.Create(context.Background(), f.org.ID, f.user.ID, "Baseline", nil)
	require.ErrorIs(t, err, strategy.ErrUnaudited)
}

func TestUpdate_OptionsChangeBumpsVersion(t *testing.T) {
	f := newFixture(t)
	s := f.create(t, "Baseline", map[string]string{"enable-audio": "N"})
	f.recorder.entries = nil

	opts := map[string]string{"enable-audio": "Y", "enable-clipboard": "N"}
	got, err := f.svc.Update(context.Background(), f.org.ID, f.user.ID, s.ID, strategy.UpdateInput{Options: &opts})
	require.NoError(t, err)
	require.EqualValues(t, 2, got.Version, "a real change must bump the delivery version")
	require.Contains(t, got.ConfigOptionsJSON, `"enable-clipboard":"N"`)
	require.Equal(t, []string{"strategy.update"}, f.recorder.actions())
}

// TestUpdate_UnchangedWritesNothing: a PUT that changes nothing must not bump
// the version (every bump costs a re-delivery on each client) and must not
// leave an audit row claiming an update happened.
func TestUpdate_UnchangedWritesNothing(t *testing.T) {
	f := newFixture(t)
	s := f.create(t, "Baseline", map[string]string{"enable-audio": "N"})
	f.recorder.entries = nil

	same := map[string]string{"enable-audio": "N"}
	name := "baseline" // same name, different case: not a change
	enabled := true
	got, err := f.svc.Update(context.Background(), f.org.ID, f.user.ID, s.ID, strategy.UpdateInput{
		Name: &name, Options: &same, Enabled: &enabled,
	})
	require.NoError(t, err)
	require.EqualValues(t, 1, got.Version)
	require.Empty(t, f.recorder.entries, "a no-op update must not be audited")
}

func TestUpdate_NameOnlyDoesNotBumpVersion(t *testing.T) {
	f := newFixture(t)
	s := f.create(t, "Baseline", map[string]string{"enable-audio": "N"})
	f.recorder.entries = nil

	name := "Renamed"
	got, err := f.svc.Update(context.Background(), f.org.ID, f.user.ID, s.ID, strategy.UpdateInput{Name: &name})
	require.NoError(t, err)
	require.Equal(t, "Renamed", got.Name)
	require.EqualValues(t, 1, got.Version,
		"the client applies config_options only; a rename delivers nothing new")
	require.Equal(t, []string{"strategy.update"}, f.recorder.actions())
}

func TestUpdate_DisableKeepsVersionAndAssignment(t *testing.T) {
	f := newFixture(t)
	s := f.create(t, "Baseline", map[string]string{"enable-audio": "N"})
	require.NoError(t, f.svc.AssignDevice(context.Background(), f.org.ID, f.user.ID, f.device.ID, &s.ID))
	f.recorder.entries = nil

	disabled := false
	got, err := f.svc.Update(context.Background(), f.org.ID, f.user.ID, s.ID, strategy.UpdateInput{Enabled: &disabled})
	require.NoError(t, err)
	require.False(t, got.Enabled)
	require.EqualValues(t, 1, got.Version)

	var dev model.Device
	require.NoError(t, store.ScopedByOrg(f.db, f.org.ID).First(&dev, f.device.ID).Error)
	require.NotNil(t, dev.StrategyID, "disabling is a kill switch, not an unassign")
}

func TestUpdate_RejectsUnknownOptionAndKeepsRow(t *testing.T) {
	f := newFixture(t)
	s := f.create(t, "Baseline", map[string]string{"enable-audio": "N"})

	bad := map[string]string{"custom-rendezvous-server": "evil.example.com"}
	_, err := f.svc.Update(context.Background(), f.org.ID, f.user.ID, s.ID, strategy.UpdateInput{Options: &bad})
	require.ErrorIs(t, err, strategy.ErrUnknownOption)

	var stored model.Strategy
	require.NoError(t, store.ScopedByOrg(f.db, f.org.ID).First(&stored, s.ID).Error)
	require.EqualValues(t, 1, stored.Version)
	require.NotContains(t, stored.ConfigOptionsJSON, "evil.example.com")
}

func TestUpdate_CrossOrgIsNotFound(t *testing.T) {
	f := newFixture(t)
	s := f.create(t, "Baseline", nil)

	name := "hijacked"
	_, err := f.svc.Update(context.Background(), f.otherOrg.ID, f.user.ID, s.ID, strategy.UpdateInput{Name: &name})
	require.ErrorIs(t, err, strategy.ErrNotFound)
}

func TestDelete_ClearsAssignmentsAndAudits(t *testing.T) {
	f := newFixture(t)
	s := f.create(t, "Baseline", nil)
	require.NoError(t, f.svc.AssignDevice(context.Background(), f.org.ID, f.user.ID, f.device.ID, &s.ID))
	require.NoError(t, f.svc.AssignGroup(context.Background(), f.org.ID, f.user.ID, f.group.ID, &s.ID))
	require.NoError(t, f.svc.AssignMember(context.Background(), f.org.ID, f.user.ID, f.user.ID, &s.ID))
	f.recorder.entries = nil

	require.NoError(t, f.svc.Delete(context.Background(), f.org.ID, f.user.ID, s.ID))

	var dev model.Device
	require.NoError(t, store.ScopedByOrg(f.db, f.org.ID).First(&dev, f.device.ID).Error)
	require.Nil(t, dev.StrategyID, "a dangling id would read as an assignment")
	var grp model.DeviceGroup
	require.NoError(t, store.ScopedByOrg(f.db, f.org.ID).First(&grp, f.group.ID).Error)
	require.Nil(t, grp.StrategyID)
	var mem model.Membership
	require.NoError(t, store.ScopedByOrg(f.db, f.org.ID).Where("user_id = ?", f.user.ID).First(&mem).Error)
	require.Nil(t, mem.StrategyID)

	require.Equal(t, []string{"strategy.delete"}, f.recorder.actions())
	var rows int64
	require.NoError(t, store.WithoutTenantScope(f.db).Model(&model.Strategy{}).
		Where("id = ?", s.ID).Count(&rows).Error)
	require.Zero(t, rows)
}

func TestDelete_CrossOrgIsNotFound(t *testing.T) {
	f := newFixture(t)
	s := f.create(t, "Baseline", nil)
	err := f.svc.Delete(context.Background(), f.otherOrg.ID, f.user.ID, s.ID)
	require.ErrorIs(t, err, strategy.ErrNotFound)
}

func TestList_ScopedToOrg(t *testing.T) {
	f := newFixture(t)
	f.create(t, "Baseline", nil)
	_, err := f.svc.Create(context.Background(), f.otherOrg.ID, f.user.ID, "Baseline", nil)
	require.NoError(t, err)

	got, err := f.svc.List(context.Background(), f.org.ID)
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, f.org.ID, got[0].OrganizationID)
}

// TestAssign_MovingBetweenLevelsKeepsOneRow guards the "one strategy per
// target" expectation: assigning twice overwrites instead of duplicating.
func TestAssign_OverwritesPreviousAssignment(t *testing.T) {
	f := newFixture(t)
	first := f.create(t, "First", nil)
	second := f.create(t, "Second", nil)
	f.recorder.entries = nil

	require.NoError(t, f.svc.AssignDevice(context.Background(), f.org.ID, f.user.ID, f.device.ID, &first.ID))
	require.NoError(t, f.svc.AssignDevice(context.Background(), f.org.ID, f.user.ID, f.device.ID, &second.ID))

	var dev model.Device
	require.NoError(t, store.ScopedByOrg(f.db, f.org.ID).First(&dev, f.device.ID).Error)
	require.NotNil(t, dev.StrategyID)
	require.Equal(t, second.ID, *dev.StrategyID)

	// Clearing with nil removes the assignment.
	require.NoError(t, f.svc.AssignDevice(context.Background(), f.org.ID, f.user.ID, f.device.ID, nil))
	require.NoError(t, store.ScopedByOrg(f.db, f.org.ID).First(&dev, f.device.ID).Error)
	require.Nil(t, dev.StrategyID)
	require.Equal(t, []string{"strategy.assign", "strategy.assign", "strategy.assign"}, f.recorder.actions())
}

func TestAssign_RejectsForeignTargets(t *testing.T) {
	f := newFixture(t)
	s := f.create(t, "Baseline", nil)
	foreign := f.create(t, "Foreign", nil)

	// A strategy from another organization must not be assignable here.
	_, err := f.svc.Create(context.Background(), f.otherOrg.ID, f.user.ID, "Other", nil)
	require.NoError(t, err)
	var other model.Strategy
	require.NoError(t, store.ScopedByOrg(f.db, f.otherOrg.ID).First(&other).Error)

	err = f.svc.AssignDevice(context.Background(), f.org.ID, f.user.ID, f.device.ID, &other.ID)
	require.ErrorIs(t, err, strategy.ErrNotFound)

	// A device from another organization must not be reachable by id.
	err = f.svc.AssignDevice(context.Background(), f.org.ID, f.user.ID, f.device.ID+9999, &s.ID)
	require.True(t, errors.Is(err, strategy.ErrNotFound))
	_ = foreign
}

func TestAssign_WithoutRecorderFailsClosed(t *testing.T) {
	f := newFixture(t)
	s := f.create(t, "Baseline", nil)
	svc := strategy.NewService(f.db, nil, nil)
	require.ErrorIs(t,
		svc.AssignDevice(context.Background(), f.org.ID, f.user.ID, f.device.ID, &s.ID),
		strategy.ErrUnaudited)
}
