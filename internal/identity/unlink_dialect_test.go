package identity

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/config"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// envDsn reads a test database DSN, defaulting to empty.
func envDsn(key string) string { return os.Getenv(key) }

// TestUnlink_LockingDialects pins the account-row-locked Unlink on the dialects
// production uses. The API harness is SQLite-only (running it against the real
// databases fails for unrelated reasons), so the clone semantics of the locked
// read chain would otherwise only ever be exercised on SQLite — where the
// locking clause is skipped entirely. A regression here is the reviewer's
// "second First inherits the first query's conditions" failure: on
// PostgreSQL/MySQL it turns every unlink into a 404.
func TestUnlink_LockingDialects(t *testing.T) {
	cases := []struct {
		name   string
		driver string
		dsnVar string
	}{
		{"postgres", "postgres", "TEST_POSTGRES_DSN"},
		{"mysql", "mysql", "TEST_MYSQL_DSN"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dsn := envDsn(tc.dsnVar)
			if dsn == "" {
				t.Skipf("%s not set", tc.dsnVar)
			}
			st, err := store.Open(config.DatabaseConfig{Driver: tc.driver, DSN: dsn})
			require.NoError(t, err)
			defer func() { _ = st.Close() }()
			// Unique table suffixes: the test-db job shares one database
			// across packages, and users.email has a unique index.
			suffix := time.Now().UnixNano()

			require.NoError(t, st.DB.AutoMigrate(&model.User{}, &model.UserIdentity{}, &model.UserPasskey{}))

			u := model.User{
				Email:         "identity-unlink-" + tc.name + "-" + strconv.FormatInt(suffix, 10) + "@example.com",
				EmailVerified: true,
				PasswordHash:  "$2a$10$dummyhashdummyhashdummyhashdummyhashdummyhashdummyhash",
			}
			require.NoError(t, st.DB.Create(&u).Error)

			// Every identity column is run-unique: user_identities is global
			// (no org scoping) and the test-db job shares one database across
			// runs — fixed subjects/issuers would collide on
			// idx_identity_provider_issuer_subject with the previous run.
			first := model.UserIdentity{UserID: u.ID, Provider: model.IdentityProviderLDAP, Issuer: "https://a-" + strconv.FormatInt(suffix, 10) + ".example.com", Subject: "s1-" + strconv.FormatInt(suffix, 10), Email: u.Email, LinkedAt: time.Now()}
			second := model.UserIdentity{UserID: u.ID, Provider: model.IdentityProviderLDAP, Issuer: "https://b-" + strconv.FormatInt(suffix, 10) + ".example.com", Subject: "s2-" + strconv.FormatInt(suffix, 10), Email: u.Email, LinkedAt: time.Now()}
			require.NoError(t, st.DB.Create(&first).Error)
			require.NoError(t, st.DB.Create(&second).Error)

			svc := &Service{DB: st.DB, Now: time.Now}
			ctx := context.Background()
			require.NoError(t, svc.Unlink(ctx, u.ID, first.ID), "first unlink must succeed")
			// The regression: the second lookup used to inherit the first
			// query's accumulated conditions on locking dialects.
			require.NoError(t, svc.Unlink(ctx, u.ID, second.ID), "second unlink must succeed under the same locked chain")

			var count int64
			require.NoError(t, st.DB.Model(&model.UserIdentity{}).Where("user_id = ?", u.ID).Count(&count).Error)
			require.EqualValues(t, 0, count)
		})
	}
}
