package device_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/audit"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/device"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// assignFixture seeds one organization with two members and one device.
func assignFixture(t *testing.T) (*store.Store, *device.Service, model.Organization, model.User, model.User, model.Device) {
	t.Helper()
	st := openDeviceStore(t)
	t.Cleanup(func() { _ = st.Close() })
	require.NoError(t, st.DB.AutoMigrate(
		&model.User{}, &model.Organization{}, &model.Membership{},
		&model.Device{}, &model.AuditLog{},
	))
	org := model.Organization{Name: "assign-org"}
	require.NoError(t, st.DB.Create(&org).Error)
	// CI runs this suite against one shared PostgreSQL/MySQL database (see
	// openDeviceStore), so every fixture row behind a global unique index needs
	// a per-test value: the users.email index is unique across the whole
	// database, not per organization.
	suffix := strings.ReplaceAll(t.Name(), "/", "-")
	alice := model.User{Email: "alice+" + suffix + "@example.com", EmailVerified: true}
	bob := model.User{Email: "bob+" + suffix + "@example.com", EmailVerified: true}
	require.NoError(t, st.DB.Create(&alice).Error)
	require.NoError(t, st.DB.Create(&bob).Error)
	require.NoError(t, st.DB.Create(&model.Membership{OrganizationID: org.ID, UserID: alice.ID, RoleID: 1}).Error)
	require.NoError(t, st.DB.Create(&model.Membership{OrganizationID: org.ID, UserID: bob.ID, RoleID: 1}).Error)

	svc := device.NewService(st.DB, audit.NewGormAuditor(st.DB), nil)
	dev, err := svc.Register(context.Background(), org.ID, device.RegisterInput{Name: "pc", RustdeskID: "900"})
	require.NoError(t, err)
	return st, svc, org, alice, bob, *dev
}

// ptr is a tiny helper for the optional fields of AssignInput.
func ptr[T any](v T) *T { return &v }

func TestAssign_SetsOwnerAndAudits(t *testing.T) {
	st, svc, org, alice, _, dev := assignFixture(t)

	updated, err := svc.Assign(context.Background(), org.ID, dev.ID, alice.ID,
		device.AssignInput{OwnerUserID: ptr(alice.ID)})
	require.NoError(t, err)
	require.NotNil(t, updated.OwnerUserID)
	require.Equal(t, alice.ID, *updated.OwnerUserID)

	var entry model.AuditLog
	require.NoError(t, store.WithoutTenantScope(st.DB).
		Where("organization_id = ? AND action = ?", org.ID, "device.assign").First(&entry).Error)
	require.Contains(t, entry.Detail, `"from":null`)
	require.Contains(t, entry.Detail, fmt.Sprintf(`"to":%d`, alice.ID),
		"the new owner is the audit's subject")
}

func TestAssign_ClearsOwnerWithZero(t *testing.T) {
	st, svc, org, alice, _, dev := assignFixture(t)
	_, err := svc.Assign(context.Background(), org.ID, dev.ID, alice.ID,
		device.AssignInput{OwnerUserID: ptr(alice.ID)})
	require.NoError(t, err)

	cleared, err := svc.Assign(context.Background(), org.ID, dev.ID, alice.ID,
		device.AssignInput{OwnerUserID: ptr(uint(0))})
	require.NoError(t, err)
	require.Nil(t, cleared.OwnerUserID, "a zero owner clears the assignment")

	var count int64
	require.NoError(t, store.WithoutTenantScope(st.DB).Model(&model.AuditLog{}).
		Where("organization_id = ? AND action = ?", org.ID, "device.assign").Count(&count).Error)
	require.EqualValues(t, 2, count, "the clear is audited too")
}

func TestAssign_RejectsForeignOwner(t *testing.T) {
	st, svc, org, alice, _, dev := assignFixture(t)
	stranger := model.User{
		Email:         "stranger+" + strings.ReplaceAll(t.Name(), "/", "-") + "@example.com",
		EmailVerified: true,
	}
	require.NoError(t, st.DB.Create(&stranger).Error)

	_, err := svc.Assign(context.Background(), org.ID, dev.ID, alice.ID,
		device.AssignInput{OwnerUserID: ptr(stranger.ID)})
	require.ErrorIs(t, err, device.ErrOwnerNotMember)

	var reloaded model.Device
	require.NoError(t, store.ScopedByOrg(st.DB, org.ID).First(&reloaded, dev.ID).Error)
	require.Nil(t, reloaded.OwnerUserID, "a refused assignment changes nothing")
}

func TestAssign_RejectsDisabledMemberAsOwner(t *testing.T) {
	st, svc, org, alice, bob, dev := assignFixture(t)
	require.NoError(t, store.ScopedByOrg(st.DB, org.ID).Model(&model.Membership{}).
		Where("user_id = ?", bob.ID).Update("disabled", true).Error)

	_, err := svc.Assign(context.Background(), org.ID, dev.ID, alice.ID,
		device.AssignInput{OwnerUserID: ptr(bob.ID)})
	require.ErrorIs(t, err, device.ErrOwnerNotMember)
}

func TestAssign_WritesNoteAndAudits(t *testing.T) {
	st, svc, org, alice, _, dev := assignFixture(t)

	updated, err := svc.Assign(context.Background(), org.ID, dev.ID, alice.ID,
		device.AssignInput{Note: ptr("rack 3")})
	require.NoError(t, err)
	require.Equal(t, "rack 3", updated.Note)

	var entry model.AuditLog
	require.NoError(t, store.WithoutTenantScope(st.DB).
		Where("organization_id = ? AND action = ?", org.ID, "device.note").First(&entry).Error)
	require.Contains(t, entry.Detail, "note")
}

func TestAssign_NoteLengthBound(t *testing.T) {
	_, svc, org, alice, _, dev := assignFixture(t)
	_, err := svc.Assign(context.Background(), org.ID, dev.ID, alice.ID,
		device.AssignInput{Note: ptr(strings.Repeat("x", 300))})
	require.ErrorIs(t, err, device.ErrInvalidInput)
}

func TestAssign_NoChangeWritesNoAudit(t *testing.T) {
	st, svc, org, alice, _, dev := assignFixture(t)
	_, err := svc.Assign(context.Background(), org.ID, dev.ID, alice.ID,
		device.AssignInput{OwnerUserID: ptr(alice.ID)})
	require.NoError(t, err)

	_, err = svc.Assign(context.Background(), org.ID, dev.ID, alice.ID,
		device.AssignInput{OwnerUserID: ptr(alice.ID)})
	require.NoError(t, err)

	var count int64
	require.NoError(t, store.WithoutTenantScope(st.DB).Model(&model.AuditLog{}).
		Where("organization_id = ? AND action = ?", org.ID, "device.assign").Count(&count).Error)
	require.EqualValues(t, 1, count, "repeating the same owner is a no-op")
}

func TestAssign_UnknownDeviceIsNotFound(t *testing.T) {
	_, svc, org, alice, _, _ := assignFixture(t)
	_, err := svc.Assign(context.Background(), org.ID, 4242, alice.ID,
		device.AssignInput{OwnerUserID: ptr(alice.ID)})
	require.ErrorIs(t, err, device.ErrDeviceNotFound)
}

func TestAssign_RefusesWithoutRecorder(t *testing.T) {
	st, _, org, alice, _, dev := assignFixture(t)
	svc := device.NewService(st.DB, nil, nil)
	_, err := svc.Assign(context.Background(), org.ID, dev.ID, alice.ID,
		device.AssignInput{OwnerUserID: ptr(alice.ID)})
	require.Error(t, err, "an unaudited assignment must not commit")
}
