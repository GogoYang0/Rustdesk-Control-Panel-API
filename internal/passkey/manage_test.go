package passkey

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/passkey/testauth"
)

func TestList_OnlyOwnCredentials(t *testing.T) {
	svc, _, db := newRegistrationService(t, 10)
	owner := newTestUser(t, db, "passkey-list-owner")
	other := newTestUser(t, db, "passkey-list-other")
	registerPasskey(t, svc, owner, testauth.New(t, svc.cfg.RPID, svc.cfg.Origin), "Owner phone")
	registerPasskey(t, svc, other, testauth.New(t, svc.cfg.RPID, svc.cfg.Origin), "Other phone")

	rows, err := svc.List(context.Background(), owner.ID)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	require.Equal(t, "Owner phone", rows[0].Name)
}

func TestRename_ValidatesOwnershipAndName(t *testing.T) {
	svc, _, db := newRegistrationService(t, 10)
	owner := newTestUser(t, db, "passkey-rename-owner")
	other := newTestUser(t, db, "passkey-rename-other")
	created := registerPasskey(t, svc, owner, testauth.New(t, svc.cfg.RPID, svc.cfg.Origin), "Old")

	ctx := context.Background()
	_, err := svc.Rename(ctx, other.ID, created.ID, "Stolen")
	require.ErrorIs(t, err, ErrPasskeyNotFound)

	_, err = svc.Rename(ctx, owner.ID, created.ID, strings.Repeat("x", 65))
	require.ErrorIs(t, err, ErrInvalidName)

	_, err = svc.Rename(ctx, owner.ID, created.ID, "   ")
	require.ErrorIs(t, err, ErrInvalidName)

	renamed, err := svc.Rename(ctx, owner.ID, created.ID, "  Kitchen laptop  ")
	require.NoError(t, err)
	require.Equal(t, "Kitchen laptop", renamed.Name)
}

func TestDelete_LastCredentialOfPasswordlessAccount(t *testing.T) {
	svc, _, db := newRegistrationService(t, 10)
	u := newTestUser(t, db, "passkey-last")
	created := registerPasskey(t, svc, u, testauth.New(t, svc.cfg.RPID, svc.cfg.Origin), "Only")

	require.NoError(t, db.Model(&model.User{}).Where("id = ?", u.ID).Update("password_hash", "").Error)

	err := svc.Delete(context.Background(), u.ID, created.ID)
	require.ErrorIs(t, err, ErrLastCredential)

	var count int64
	require.NoError(t, db.Model(&model.UserPasskey{}).Count(&count).Error)
	require.EqualValues(t, 1, count)
}

func TestDelete_AllowsWhenPasswordExists(t *testing.T) {
	svc, _, db := newRegistrationService(t, 10)
	u := newTestUser(t, db, "passkey-delete")
	created := registerPasskey(t, svc, u, testauth.New(t, svc.cfg.RPID, svc.cfg.Origin), "Only")

	require.NoError(t, svc.Delete(context.Background(), u.ID, created.ID))

	var count int64
	require.NoError(t, db.Model(&model.UserPasskey{}).Count(&count).Error)
	require.Zero(t, count)
}

func TestDelete_OtherUsersCredentialIsNotFound(t *testing.T) {
	svc, _, db := newRegistrationService(t, 10)
	owner := newTestUser(t, db, "passkey-del-owner")
	other := newTestUser(t, db, "passkey-del-other")
	created := registerPasskey(t, svc, owner, testauth.New(t, svc.cfg.RPID, svc.cfg.Origin), "Phone")

	err := svc.Delete(context.Background(), other.ID, created.ID)
	require.ErrorIs(t, err, ErrPasskeyNotFound)
}
