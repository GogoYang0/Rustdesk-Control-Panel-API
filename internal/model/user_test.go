package model_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/config"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

func TestUserModel_AutoMigrateAndCRUD(t *testing.T) {
	s, err := store.Open(config.DatabaseConfig{Driver: "sqlite", DSN: "file::memory:?cache=shared"})
	require.NoError(t, err)
	defer func() { _ = s.Close() }()

	require.NoError(t, s.DB.AutoMigrate(&model.User{}))

	u := model.User{Email: "admin@example.com", PasswordHash: "$argon2id$whatever"}
	require.NoError(t, s.DB.Create(&u).Error)

	var got model.User
	require.NoError(t, s.DB.Where("email = ?", "admin@example.com").First(&got).Error)
	require.Equal(t, u.ID, got.ID)
	require.NotEmpty(t, got.PasswordHash)
}
