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

// TestUser_BeforeSaveNormalizesEmail pins the mailbox normalization: every
// write path (invite accept, admin create, profile changes) funnels through
// BeforeSave, so case-variant shadow accounts can never be created again.
// Legacy mixed-case rows may still exist in old deployments — identity
// matching treats them as conflicts, but no new ones may appear.
func TestUser_BeforeSaveNormalizesEmail(t *testing.T) {
	u := model.User{Email: "  Mixed.Case@EXAMPLE.Com  ", PasswordHash: "h"}
	require.NoError(t, u.BeforeSave(nil))
	require.Equal(t, "mixed.case@example.com", u.Email, "BeforeSave must normalize the mailbox on every write")

	u2 := model.User{Email: "  spaced@example.com  ", PasswordHash: "h"}
	require.NoError(t, u2.BeforeSave(nil))
	require.Equal(t, "spaced@example.com", u2.Email, "surrounding whitespace must be trimmed too")
}
