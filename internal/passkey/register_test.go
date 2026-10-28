package passkey

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/auth"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/config"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/passkey/testauth"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

var registrationSeq atomic.Int64

func newRegistrationService(t *testing.T, perUser int) (*Service, *testClock, *gorm.DB) {
	t.Helper()

	st, err := store.Open(config.DatabaseConfig{
		Driver: "sqlite",
		DSN:    fmt.Sprintf("file:passkey_register_%d?mode=memory&cache=shared", registrationSeq.Add(1)),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	require.NoError(t, st.DB.AutoMigrate(&model.User{}, &model.UserPasskey{}, &model.WebAuthnCeremony{}))

	clock := &testClock{at: time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)}
	svc, err := NewService(st.DB, Config{
		RPID:               "panel.example.com",
		RPDisplayName:      "Panel",
		Origin:             "https://panel.example.com",
		CeremonyTTL:        5 * time.Minute,
		CredentialsPerUser: perUser,
	}, auth.NewIssuer("test-secret-test-secret-test-secret", 15*time.Minute, 168*time.Hour), clock.Now)
	require.NoError(t, err)
	return svc, clock, st.DB
}

func newTestUser(t *testing.T, db *gorm.DB, prefix string) model.User {
	t.Helper()

	n := registrationSeq.Add(1)
	u := model.User{
		Email:         fmt.Sprintf("%s-%d@example.com", prefix, n),
		PasswordHash:  "hash",
		EmailVerified: true,
	}
	require.NoError(t, db.Create(&u).Error)
	return u
}

// registerPasskey drives one full registration ceremony.
func registerPasskey(t *testing.T, svc *Service, u model.User, authn *testauth.Authenticator, name string) *model.UserPasskey {
	t.Helper()

	ctx := context.Background()
	token, options, err := svc.BeginRegistration(ctx, u)
	require.NoError(t, err)

	body := authn.Attestation(t, options.Response.Challenge.String(), base64.RawURLEncoding.EncodeToString(userHandle(u.ID)))
	created, err := svc.FinishRegistration(ctx, u, token, body, name)
	require.NoError(t, err)
	return created
}

func TestRegister_HappyPath(t *testing.T) {
	svc, _, db := newRegistrationService(t, 10)
	u := newTestUser(t, db, "passkey-register")
	authn := testauth.New(t, svc.cfg.RPID, svc.cfg.Origin)

	created := registerPasskey(t, svc, u, authn, "MacBook")

	require.NotZero(t, created.ID)
	require.Equal(t, u.ID, created.UserID)
	require.Equal(t, "MacBook", created.Name)
	require.Equal(t, base64.RawURLEncoding.EncodeToString(authn.CredentialID()), created.CredentialID)

	sum := sha256.Sum256(authn.CredentialID())
	require.Equal(t, hex.EncodeToString(sum[:]), created.CredentialIDHash)
	require.NotEmpty(t, created.PublicKey)
	require.Equal(t, "01020304-0506-0708-090a-0b0c0d0e0f10", created.AAGUID)
	require.JSONEq(t, `[]`, created.Transports)
	require.False(t, created.BackupEligible)
}

func TestRegister_RejectsDuplicateCredentialAcrossUsers(t *testing.T) {
	svc, _, db := newRegistrationService(t, 10)
	first := newTestUser(t, db, "passkey-dup-a")
	second := newTestUser(t, db, "passkey-dup-b")

	authn := testauth.New(t, svc.cfg.RPID, svc.cfg.Origin)
	registerPasskey(t, svc, first, authn, "Phone")

	ctx := context.Background()
	token, options, err := svc.BeginRegistration(ctx, second)
	require.NoError(t, err)
	body := authn.Attestation(t, options.Response.Challenge.String(), base64.RawURLEncoding.EncodeToString(userHandle(second.ID)))
	_, err = svc.FinishRegistration(ctx, second, token, body, "Stolen")
	require.ErrorIs(t, err, ErrCredentialExists)

	var count int64
	require.NoError(t, db.Model(&model.UserPasskey{}).Count(&count).Error)
	require.EqualValues(t, 1, count)
}

func TestRegister_RejectsCredentialCap(t *testing.T) {
	svc, _, db := newRegistrationService(t, 1)
	u := newTestUser(t, db, "passkey-cap")

	registerPasskey(t, svc, u, testauth.New(t, svc.cfg.RPID, svc.cfg.Origin), "First")

	_, _, err := svc.BeginRegistration(context.Background(), u)
	require.ErrorIs(t, err, ErrTooManyPasskeys)
}

func TestRegister_LibraryRejectsWrongOrigin(t *testing.T) {
	svc, _, db := newRegistrationService(t, 10)
	u := newTestUser(t, db, "passkey-origin")
	evil := testauth.New(t, svc.cfg.RPID, "https://evil.example.org")

	ctx := context.Background()
	token, options, err := svc.BeginRegistration(ctx, u)
	require.NoError(t, err)
	body := evil.Attestation(t, options.Response.Challenge.String(), base64.RawURLEncoding.EncodeToString(userHandle(u.ID)))

	_, err = svc.FinishRegistration(ctx, u, token, body, "Evil")
	require.ErrorIs(t, err, ErrAssertionFailed)

	var count int64
	require.NoError(t, db.Model(&model.UserPasskey{}).Count(&count).Error)
	require.Zero(t, count)
}

func TestRegister_ValidatesName(t *testing.T) {
	svc, _, db := newRegistrationService(t, 10)
	u := newTestUser(t, db, "passkey-name")

	ctx := context.Background()
	token, options, err := svc.BeginRegistration(ctx, u)
	require.NoError(t, err)
	authn := testauth.New(t, svc.cfg.RPID, svc.cfg.Origin)
	body := authn.Attestation(t, options.Response.Challenge.String(), base64.RawURLEncoding.EncodeToString(userHandle(u.ID)))

	_, err = svc.FinishRegistration(ctx, u, token, body, strings.Repeat("x", 65))
	require.ErrorIs(t, err, ErrInvalidName)
}

func TestRegister_DefaultNameWhenEmpty(t *testing.T) {
	svc, _, db := newRegistrationService(t, 10)
	u := newTestUser(t, db, "passkey-default-name")

	created := registerPasskey(t, svc, u, testauth.New(t, svc.cfg.RPID, svc.cfg.Origin), "")
	require.Equal(t, "Passkey", created.Name)
}

func TestRegister_RejectsReplayedCeremony(t *testing.T) {
	svc, _, db := newRegistrationService(t, 10)
	u := newTestUser(t, db, "passkey-replay")
	authn := testauth.New(t, svc.cfg.RPID, svc.cfg.Origin)

	ctx := context.Background()
	token, options, err := svc.BeginRegistration(ctx, u)
	require.NoError(t, err)
	body := authn.Attestation(t, options.Response.Challenge.String(), base64.RawURLEncoding.EncodeToString(userHandle(u.ID)))

	_, err = svc.FinishRegistration(ctx, u, token, body, "First")
	require.NoError(t, err)
	_, err = svc.FinishRegistration(ctx, u, token, body, "Second")
	require.ErrorIs(t, err, ErrCeremonyUsed)
}

func TestRegister_CeremonyBelongsToItsUser(t *testing.T) {
	svc, _, db := newRegistrationService(t, 10)
	owner := newTestUser(t, db, "passkey-owner")
	other := newTestUser(t, db, "passkey-other")
	authn := testauth.New(t, svc.cfg.RPID, svc.cfg.Origin)

	ctx := context.Background()
	token, options, err := svc.BeginRegistration(ctx, owner)
	require.NoError(t, err)
	body := authn.Attestation(t, options.Response.Challenge.String(), base64.RawURLEncoding.EncodeToString(userHandle(other.ID)))

	_, err = svc.FinishRegistration(ctx, other, token, body, "Hijack")
	require.ErrorIs(t, err, ErrCeremonyNotFound)
}
