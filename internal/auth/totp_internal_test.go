package auth

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/config"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// newInternalTOTPFixture mirrors the external fixture: the internal package
// needs it to drive the enrollment hook.
func newInternalTOTPFixture(t *testing.T) (*store.Store, *TOTPService, *time.Time, model.User) {
	t.Helper()
	dsn := fmt.Sprintf("file:totp_internal_%d?mode=memory&cache=shared", time.Now().UnixNano())
	st, err := store.Open(config.DatabaseConfig{Driver: "sqlite", DSN: dsn})
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	require.NoError(t, st.DB.AutoMigrate(&model.User{}, &model.UserTOTP{}))

	user := model.User{Email: "otp-internal@example.com", EmailVerified: true}
	require.NoError(t, st.DB.Create(&user).Error)

	now := time.Now().UTC().Truncate(30 * time.Second)
	svc := NewTOTPService(st.DB, "test-secret", func() time.Time { return now })
	return st, svc, &now, user
}

// internalTOTPCode computes the RFC 6238 code for the fixture clock.
func internalTOTPCode(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	require.NoError(t, err)
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(at.Unix()/30))
	mac := hmac.New(sha1.New, raw)
	mac.Write(buf)
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", value%1000000)
}

// Enable reads the pending secret, then a concurrent Setup replaces it before
// the activation update runs. The secret binding must reject the stale code and
// leave the account unenabled with the new pending secret intact.
func TestTOTP_EnableLosesToConcurrentSetup(t *testing.T) {
	_, svc, now, user := newInternalTOTPFixture(t)
	first, _, err := svc.Setup(user.ID)
	require.NoError(t, err)

	code := internalTOTPCode(t, first, *now)
	enableAfterReadHook = func() {
		enableAfterReadHook = nil
		_, _, serr := svc.Setup(user.ID)
		require.NoError(t, serr, "re-enrollment while pending is allowed")
	}
	t.Cleanup(func() { enableAfterReadHook = nil })

	err = svc.Enable(user.ID, code)
	require.ErrorIs(t, err, ErrInvalidTOTP, "the code belongs to the replaced secret")

	enabled, err := svc.Enabled(user.ID)
	require.NoError(t, err)
	require.False(t, enabled, "the replaced secret must not become active")
}
