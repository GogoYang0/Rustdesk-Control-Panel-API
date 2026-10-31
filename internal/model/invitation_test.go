package model_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
)

func TestInvitation_AcceptExpired_Fails(t *testing.T) {
	inv := model.Invitation{
		OrganizationID: 1,
		Email:          "dev@example.com",
		Role:           model.RoleMember,
		TokenHash:      "hash",
		ExpiresAt:      time.Now().Add(-time.Minute),
	}
	require.ErrorIs(t, inv.Acceptable(time.Now()), model.ErrInvitationExpired)
}

func TestInvitation_AcceptTwice_Fails(t *testing.T) {
	now := time.Now()
	accepted := now.Add(-time.Minute)
	inv := model.Invitation{
		OrganizationID: 1,
		Email:          "dev@example.com",
		Role:           model.RoleMember,
		TokenHash:      "hash",
		ExpiresAt:      now.Add(time.Hour),
		AcceptedAt:     &accepted,
	}
	require.ErrorIs(t, inv.Acceptable(now), model.ErrInvitationUsed)
}

func TestInvitation_AcceptRevoked_Fails(t *testing.T) {
	now := time.Now()
	revoked := now.Add(-time.Minute)
	inv := model.Invitation{
		OrganizationID: 1,
		Email:          "dev@example.com",
		Role:           model.RoleMember,
		TokenHash:      "hash",
		ExpiresAt:      now.Add(time.Hour),
		RevokedAt:      &revoked,
	}
	require.ErrorIs(t, inv.Acceptable(now), model.ErrInvitationRevoked)
}

func TestInvitation_AcceptValid(t *testing.T) {
	inv := model.Invitation{
		OrganizationID: 1,
		Email:          "dev@example.com",
		Role:           model.RoleMember,
		TokenHash:      "hash",
		ExpiresAt:      time.Now().Add(time.Hour),
	}
	require.NoError(t, inv.Acceptable(time.Now()))
}
