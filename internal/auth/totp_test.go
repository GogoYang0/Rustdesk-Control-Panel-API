package auth_test

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/auth"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/config"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

const totpPassword = "password123"

func newTOTPFixture(t *testing.T) (*store.Store, *auth.TOTPService, *time.Time, model.User) {
	t.Helper()
	dsn := fmt.Sprintf("file:totp_%d?mode=memory&cache=shared", time.Now().UnixNano())
	st, err := store.Open(config.DatabaseConfig{Driver: "sqlite", DSN: dsn})
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	require.NoError(t, st.DB.AutoMigrate(&model.User{}, &model.UserTOTP{}))

	hash, err := auth.HashPassword(totpPassword)
	require.NoError(t, err)
	user := model.User{Email: "otp@example.com", PasswordHash: hash, EmailVerified: true}
	require.NoError(t, st.DB.Create(&user).Error)

	now := time.Now().UTC().Truncate(30 * time.Second)
	svc := auth.NewTOTPService(st.DB, "test-secret", func() time.Time { return now })
	return st, svc, &now, user
}

// An empty auth secret must not silently become a public, deterministic key:
// every operation that needs the key fails closed instead.
func TestTOTP_EmptySecretFailsClosed(t *testing.T) {
	st, _, _, user := newTOTPFixture(t)
	svc := auth.NewTOTPService(st.DB, "", nil)
	_, _, err := svc.Setup(user.ID)
	require.ErrorIs(t, err, auth.ErrTOTPSecretMissing)
}

// totpCode computes the RFC 6238 code independently of the implementation.
func totpCode(secret string, at time.Time) string {
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		panic(err)
	}
	step := at.Unix() / 30
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(step))
	mac := hmac.New(sha1.New, raw)
	mac.Write(buf)
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", value%1000000)
}

func TestTOTP_SetupEnableVerifyAndReplay(t *testing.T) {
	st, svc, now, user := newTOTPFixture(t)

	secret, uri, err := svc.Setup(user.ID)
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(uri, "otpauth://totp/"))
	require.Contains(t, uri, secret)

	// The stored secret is encrypted, not the base32 plaintext.
	var row model.UserTOTP
	require.NoError(t, st.DB.First(&row, user.ID).Error)
	require.NotContains(t, row.SecretCiphertext, secret)
	require.Nil(t, row.EnabledAt)

	enabled, err := svc.Enabled(user.ID)
	require.NoError(t, err)
	require.False(t, enabled, "setup alone must not enable the factor")

	require.ErrorIs(t, svc.Enable(user.ID, "000000"), auth.ErrInvalidTOTP)
	code := totpCode(secret, *now)
	require.NoError(t, svc.Enable(user.ID, code))
	enabled, err = svc.Enabled(user.ID)
	require.NoError(t, err)
	require.True(t, enabled)

	// The enabling code is consumed by last_step: replay fails.
	require.ErrorIs(t, svc.VerifyLogin(user.ID, code), auth.ErrInvalidTOTP)

	// A code for the next step works.
	*now = now.Add(30 * time.Second)
	next := totpCode(secret, *now)
	require.NoError(t, svc.VerifyLogin(user.ID, next))

	// Disable needs the password and a fresh code.
	*now = now.Add(30 * time.Second)
	require.ErrorIs(t, svc.Disable(user.ID, "wrong-password", totpCode(secret, *now)), auth.ErrInvalidPassword)
	require.NoError(t, svc.Disable(user.ID, totpPassword, totpCode(secret, *now)))
	enabled, err = svc.Enabled(user.ID)
	require.NoError(t, err)
	require.False(t, enabled)
}

func TestTOTP_RecoveryCodeSingleUse(t *testing.T) {
	_, svc, now, user := newTOTPFixture(t)
	secret, _, err := svc.Setup(user.ID)
	require.NoError(t, err)
	require.NoError(t, svc.Enable(user.ID, totpCode(secret, *now)))

	*now = now.Add(30 * time.Second)
	codes, err := svc.RegenerateRecovery(user.ID, totpPassword, totpCode(secret, *now))
	require.NoError(t, err)
	require.Len(t, codes, auth.RecoveryCodeCount)

	first := codes[0]
	require.NoError(t, svc.VerifyLogin(user.ID, first))
	require.ErrorIs(t, svc.VerifyLogin(user.ID, first), auth.ErrInvalidTOTP, "a recovery code is single-use")
	require.NoError(t, svc.VerifyLogin(user.ID, codes[1]))

	// A recovery code can also disable the factor.
	require.NoError(t, svc.Disable(user.ID, totpPassword, codes[2]))
}

func TestTOTP_SetupTwiceConflictAndReset(t *testing.T) {
	_, svc, now, user := newTOTPFixture(t)
	secret, _, err := svc.Setup(user.ID)
	require.NoError(t, err)

	// Re-running setup before enabling replaces the pending secret.
	secret2, _, err := svc.Setup(user.ID)
	require.NoError(t, err)
	require.NotEqual(t, secret, secret2)
	require.NoError(t, svc.Enable(user.ID, totpCode(secret2, *now)))

	_, _, err = svc.Setup(user.ID)
	require.ErrorIs(t, err, auth.ErrTOTPAlreadyEnabled)

	require.NoError(t, svc.Reset(user.ID))
	enabled, err := svc.Enabled(user.ID)
	require.NoError(t, err)
	require.False(t, enabled)
	// Reset is idempotent.
	require.NoError(t, svc.Reset(user.ID))
}

func TestTOTP_VerifyWithoutSetupFailsClosed(t *testing.T) {
	_, svc, _, user := newTOTPFixture(t)
	require.ErrorIs(t, svc.VerifyLogin(user.ID, "123456"), auth.ErrTOTPNotSetup)
	require.ErrorIs(t, svc.Enable(user.ID, "123456"), auth.ErrTOTPNotSetup)
}
