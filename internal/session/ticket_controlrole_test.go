package session_test

import (
	"context"
	"encoding/json"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/controlrole"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/session"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

var actorSeq atomic.Int64

// addActor creates a member with an optional control role and returns its user
// id. The control role service writes audit entries, so the harness recorder is
// reused.
func (h *harness) addActor(t *testing.T, perms controlrole.Permissions) (uint, *model.ControlRole, *controlrole.Service) {
	t.Helper()
	// The harness clock is fixed, so the email must come from a counter: CI's
	// test-db job shares one PostgreSQL database and users.email is globally
	// unique.
	user := model.User{Email: fmt.Sprintf("actor-%d@example.com", actorSeq.Add(1)), PasswordHash: "x", EmailVerified: true}
	require.NoError(t, h.db.Create(&user).Error)
	require.NoError(t, h.db.Create(&model.Membership{
		OrganizationID: h.org.ID,
		UserID:         user.ID,
		RoleID:         1,
	}).Error)
	svc := controlrole.NewService(h.db, h.recorder, func() time.Time { return h.now })
	require.NoError(t, controlrole.Migrate(h.db, func() time.Time { return h.now }))

	var role *model.ControlRole
	if perms != nil {
		created, err := svc.Create(context.Background(), h.org.ID, user.ID, "Ops", perms)
		require.NoError(t, err)
		require.NoError(t, svc.Assign(context.Background(), h.org.ID, user.ID, user.ID, &created.ID))
		role = created
	}
	return user.ID, role, svc
}

func TestIssue_SnapshotsControlPermissions(t *testing.T) {
	h := newHarness(t)
	actor, role, roleSvc := h.addActor(t, controlrole.Permissions{
		"file":      controlrole.StateEnable,
		"clipboard": controlrole.StateEnable,
		"usb":       controlrole.StateDisable,
	})
	svc := h.svc.WithControlRoles(roleSvc)

	ticket, _, err := svc.Issue(context.Background(), session.IssueInput{
		OrganizationID: h.org.ID,
		ActorUserID:    actor,
		DeviceID:       h.device.ID,
	})
	require.NoError(t, err)
	require.NotNil(t, ticket.ControlRoleID)
	require.EqualValues(t, role.ID, *ticket.ControlRoleID)
	// clipboard is bit 2, file is bit 3; a disabled usb must not set bit 13.
	require.Equal(t, uint64(1<<2|1<<3), ticket.ControlPermissions)

	var snapshot map[string]string
	require.NoError(t, json.Unmarshal([]byte(ticket.ControlRoleSnapshotJSON), &snapshot))
	require.Equal(t, "enable", snapshot["file"])
	require.Equal(t, "disable", snapshot["usb"])
	require.Equal(t, "use_client", snapshot["keyboard"])
}

func TestIssue_FallsBackToDefaultRole(t *testing.T) {
	h := newHarness(t)
	actor, _, roleSvc := h.addActor(t, nil)
	svc := h.svc.WithControlRoles(roleSvc)

	ticket, _, err := svc.Issue(context.Background(), session.IssueInput{
		OrganizationID: h.org.ID,
		ActorUserID:    actor,
		DeviceID:       h.device.ID,
	})
	require.NoError(t, err)
	require.Zero(t, ticket.ControlPermissions)

	var def model.ControlRole
	require.NoError(t, store.ScopedByOrg(h.db, h.org.ID).
		Where("kind = ?", model.KindControlRoleDefault).First(&def).Error)
	require.NotNil(t, ticket.ControlRoleID)
	require.Equal(t, def.ID, *ticket.ControlRoleID)
}

// TestIssue_DoesNotRetroactivelyChangeIssuedTicket pins D7: the ticket keeps
// the permissions it was issued under, even after the role is tightened.
func TestIssue_DoesNotRetroactivelyChangeIssuedTicket(t *testing.T) {
	h := newHarness(t)
	actor, role, roleSvc := h.addActor(t, controlrole.Permissions{"file": controlrole.StateEnable})
	svc := h.svc.WithControlRoles(roleSvc)

	first, _, err := svc.Issue(context.Background(), session.IssueInput{
		OrganizationID: h.org.ID, ActorUserID: actor, DeviceID: h.device.ID,
	})
	require.NoError(t, err)
	require.Equal(t, uint64(1<<3), first.ControlPermissions)

	tightened := controlrole.Permissions{"file": controlrole.StateDisable}
	_, err = roleSvc.Update(context.Background(), h.org.ID, actor, role.ID, nil, &tightened)
	require.NoError(t, err)

	second, _, err := svc.Issue(context.Background(), session.IssueInput{
		OrganizationID: h.org.ID, ActorUserID: actor, DeviceID: h.device.ID,
	})
	require.NoError(t, err)
	require.Zero(t, second.ControlPermissions)

	var reread model.Ticket
	require.NoError(t, store.ScopedByOrg(h.db, h.org.ID).First(&reread, first.ID).Error)
	require.Equal(t, uint64(1<<3), reread.ControlPermissions)
}

func TestRedeem_CopiesSnapshotToSession(t *testing.T) {
	h := newHarness(t)
	actor, _, roleSvc := h.addActor(t, controlrole.Permissions{"file": controlrole.StateEnable})
	svc := h.svc.WithControlRoles(roleSvc)

	ticket, token, err := svc.Issue(context.Background(), session.IssueInput{
		OrganizationID: h.org.ID, ActorUserID: actor, DeviceID: h.device.ID,
	})
	require.NoError(t, err)

	sess, err := svc.Redeem(context.Background(), h.org.ID, actor, ticket.ID, token)
	require.NoError(t, err)
	require.Equal(t, uint64(1<<3), sess.ControlPermissions)
}

// TestIssue_WithoutControlRolesStaysZero documents the "not wired" state: a
// service built without the role service must not invent permissions.
func TestIssue_WithoutControlRolesStaysZero(t *testing.T) {
	h := newHarness(t)
	actor, _, _ := h.addActor(t, controlrole.Permissions{"file": controlrole.StateEnable})

	ticket, _, err := h.svc.Issue(context.Background(), session.IssueInput{
		OrganizationID: h.org.ID, ActorUserID: actor, DeviceID: h.device.ID,
	})
	require.NoError(t, err)
	require.Zero(t, ticket.ControlPermissions)
	require.Nil(t, ticket.ControlRoleID)
}
