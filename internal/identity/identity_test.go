package identity

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/config"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

const (
	providerOIDC = model.IdentityProviderOIDC
	providerLDAP = model.IdentityProviderLDAP
	issuerA      = "https://idp.example.com"
	issuerB      = "https://idp2.example.com"
)

var seq atomic.Uint64

func newService(t *testing.T) (*Service, func(at time.Time)) {
	t.Helper()

	st, err := store.Open(config.DatabaseConfig{
		Driver: "sqlite",
		DSN:    fmt.Sprintf("file:identity_%d?mode=memory&cache=shared", seq.Add(1)),
	})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	sqlDB, err := st.DB.DB()
	if err != nil {
		t.Fatalf("sql db: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)

	if err := st.DB.AutoMigrate(&model.User{}, &model.UserPasskey{}, &model.UserIdentity{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	return &Service{DB: st.DB, Now: func() time.Time { return now }}, func(at time.Time) { now = at }
}

func seedUser(t *testing.T, s *Service, email string, verified bool) model.User {
	t.Helper()

	u := model.User{Email: email, PasswordHash: "argon2id-placeholder", EmailVerified: verified}
	if err := s.DB.Create(&u).Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return u
}

func TestResolve_BindsVerifiedMailboxToExistingAccount(t *testing.T) {
	s, _ := newService(t)
	u := seedUser(t, s, "ldap-bind@example.com", true)

	user, err := s.Resolve(context.Background(), Claims{
		Provider: providerLDAP, Issuer: issuerA, Subject: "alice",
		Email: "LDAP-Bind@example.com", EmailVerified: true,
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if user.ID != u.ID {
		t.Fatalf("bound to user %d, want %d", user.ID, u.ID)
	}

	var row model.UserIdentity
	if err := s.DB.Where("provider = ? AND subject = ?", providerLDAP, "alice").First(&row).Error; err != nil {
		t.Fatalf("identity row: %v", err)
	}
	if row.Email != "ldap-bind@example.com" {
		t.Fatalf("identity email = %q (normalized to lower case)", row.Email)
	}
	if row.LastLoginAt == nil {
		t.Fatal("last_login_at not recorded")
	}
}

func TestResolve_ExistingBindingWinsOverMailbox(t *testing.T) {
	s, _ := newService(t)
	u := seedUser(t, s, "ldap-return@example.com", true)

	if _, err := s.Resolve(context.Background(), Claims{
		Provider: providerLDAP, Issuer: issuerA, Subject: "bob",
		Email: u.Email, EmailVerified: true,
	}); err != nil {
		t.Fatalf("first bind: %v", err)
	}

	// The directory now reports a recycled mailbox; the binding must win.
	user, err := s.Resolve(context.Background(), Claims{
		Provider: providerLDAP, Issuer: issuerA, Subject: "bob",
		Email: "ldap-someone-else@example.com", EmailVerified: true,
	})
	if err != nil {
		t.Fatalf("second login: %v", err)
	}
	if user.ID != u.ID {
		t.Fatalf("binding moved to user %d", user.ID)
	}
}

func TestResolve_Refusals(t *testing.T) {
	cases := []struct {
		name    string
		claims  Claims
		seed    bool
		wantErr error
	}{
		{
			name:    "no panel account",
			claims:  Claims{Provider: providerLDAP, Issuer: issuerA, Subject: "ghost", Email: "ldap-ghost@example.com", EmailVerified: true},
			wantErr: ErrNoAccount,
		},
		{
			name:    "unverified external claim",
			claims:  Claims{Provider: providerLDAP, Issuer: issuerA, Subject: "unv", Email: "ldap-unv@example.com", EmailVerified: false},
			seed:    true,
			wantErr: ErrEmailUnverified,
		},
		{
			name:    "unverified panel mailbox",
			claims:  Claims{Provider: providerLDAP, Issuer: issuerA, Subject: "panelunv", Email: "ldap-panelunv@example.com", EmailVerified: true},
			seed:    true,
			wantErr: ErrEmailUnverified,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := newService(t)
			if tc.seed {
				seedUser(t, s, tc.claims.Email, false)
			}
			if _, err := s.Resolve(context.Background(), tc.claims); !errors.Is(err, tc.wantErr) {
				t.Fatalf("Resolve = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

// TestResolve_SubjectConflictMarksRow covers the recycled-mailbox takeover
// path: subject stays bound to A while the mailbox now belongs to B.
func TestResolve_SubjectConflictMarksRow(t *testing.T) {
	s, _ := newService(t)
	alice := seedUser(t, s, "ldap-conflict-a@example.com", true)
	bob := seedUser(t, s, "ldap-conflict-b@example.com", true)

	if _, err := s.Resolve(context.Background(), Claims{
		Provider: providerLDAP, Issuer: issuerA, Subject: "shared",
		Email: alice.Email, EmailVerified: true,
	}); err != nil {
		t.Fatalf("first bind: %v", err)
	}

	if _, err := s.Resolve(context.Background(), Claims{
		Provider: providerLDAP, Issuer: issuerA, Subject: "shared",
		Email: bob.Email, EmailVerified: true,
	}); !errors.Is(err, ErrIdentityConflict) {
		t.Fatalf("Resolve = %v, want ErrIdentityConflict", err)
	}

	var row model.UserIdentity
	if err := s.DB.Where("subject = ?", "shared").First(&row).Error; err != nil {
		t.Fatalf("identity: %v", err)
	}
	if row.UserID != alice.ID {
		t.Fatalf("binding moved to %d; a conflict must not rebind", row.UserID)
	}
	if row.ConflictAt == nil {
		t.Fatal("conflict_at not set; the operator cannot tell which binding is broken")
	}
}

// TestResolve_SameSubjectUnderNewIssuerBindsFresh pins the issuer-in-the-key
// rule: the same subject string under a different issuer is a different person.
func TestResolve_SameSubjectUnderNewIssuerBindsFresh(t *testing.T) {
	s, _ := newService(t)
	alice := seedUser(t, s, "ldap-issuer-a@example.com", true)
	bob := seedUser(t, s, "ldap-issuer-b@example.com", true)

	if _, err := s.Resolve(context.Background(), Claims{
		Provider: providerOIDC, Issuer: issuerA, Subject: "same",
		Email: alice.Email, EmailVerified: true,
	}); err != nil {
		t.Fatalf("first bind: %v", err)
	}
	if _, err := s.Resolve(context.Background(), Claims{
		Provider: providerOIDC, Issuer: issuerB, Subject: "same",
		Email: bob.Email, EmailVerified: true,
	}); err != nil {
		t.Fatalf("second bind: %v", err)
	}

	var rows []model.UserIdentity
	if err := s.DB.Order("id").Find(&rows).Error; err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 2 || rows[0].UserID != alice.ID || rows[1].UserID != bob.ID {
		t.Fatalf("issuer change bound the wrong accounts: %+v", rows)
	}
}

// TestResolve_ConcurrentFirstBind pins the unique-key fallback: two concurrent
// first logins for one mailbox both succeed and leave exactly one row.
func TestResolve_ConcurrentFirstBind(t *testing.T) {
	s, _ := newService(t)
	u := seedUser(t, s, "ldap-race@example.com", true)

	var wg sync.WaitGroup
	var errs [2]error
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = s.Resolve(context.Background(), Claims{
				Provider: providerLDAP, Issuer: issuerA, Subject: "racer",
				Email: u.Email, EmailVerified: true,
			})
		}(i)
	}
	wg.Wait()

	if errs[0] != nil || errs[1] != nil {
		t.Fatalf("both first logins must succeed, got %v / %v", errs[0], errs[1])
	}
	var count int64
	if err := s.DB.Model(&model.UserIdentity{}).Where("user_id = ?", u.ID).Count(&count).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Fatalf("identity rows = %d, want exactly 1", count)
	}
}

func TestUnlink_OwnershipAndLockout(t *testing.T) {
	s, _ := newService(t)
	alice := seedUser(t, s, "ldap-unlink-a@example.com", true)
	bob := seedUser(t, s, "ldap-unlink-b@example.com", true)

	row := model.UserIdentity{UserID: bob.ID, Provider: providerLDAP, Issuer: issuerA, Subject: "bobs", Email: "ldap-bobs@example.com", LinkedAt: time.Now()}
	if err := s.DB.Create(&row).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Another user's identity is a 404, not a lockout refusal.
	if err := s.Unlink(context.Background(), alice.ID, row.ID); !errors.Is(err, ErrIdentityNotFound) {
		t.Fatalf("Unlink(other) = %v, want ErrIdentityNotFound", err)
	}
}

func TestUnlink_LastCredentialRefused(t *testing.T) {
	s, _ := newService(t)
	alice := seedUser(t, s, "ldap-last@example.com", true)
	row := model.UserIdentity{UserID: alice.ID, Provider: providerLDAP, Issuer: issuerA, Subject: "last", Email: "ldap-last@example.com", LinkedAt: time.Now()}
	if err := s.DB.Create(&row).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := s.DB.Model(&model.User{}).Where("id = ?", alice.ID).Update("password_hash", "").Error; err != nil {
		t.Fatalf("clear password: %v", err)
	}

	if err := s.Unlink(context.Background(), alice.ID, row.ID); !errors.Is(err, ErrLastCredential) {
		t.Fatalf("Unlink = %v, want ErrLastCredential", err)
	}
	var count int64
	if err := s.DB.Model(&model.UserIdentity{}).Where("id = ?", row.ID).Count(&count).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Fatal("the refused unlink must not delete the row")
	}
}

// TestUnlink_SecondBindingAllowed pins the flip side: the same passwordless
// account can unlink when a second binding remains (different issuer — one
// account holds at most one binding per provider+issuer).
func TestUnlink_SecondBindingAllowed(t *testing.T) {
	s, _ := newService(t)
	alice := seedUser(t, s, "ldap-second@example.com", true)
	first := model.UserIdentity{UserID: alice.ID, Provider: providerLDAP, Issuer: issuerA, Subject: "first", Email: "ldap-first@example.com", LinkedAt: time.Now()}
	second := model.UserIdentity{UserID: alice.ID, Provider: providerLDAP, Issuer: issuerB, Subject: "second", Email: "ldap-second@example.com", LinkedAt: time.Now()}
	if err := s.DB.Create(&first).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := s.DB.Create(&second).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := s.DB.Model(&model.User{}).Where("id = ?", alice.ID).Update("password_hash", "").Error; err != nil {
		t.Fatalf("clear password: %v", err)
	}

	if err := s.Unlink(context.Background(), alice.ID, first.ID); err != nil {
		t.Fatalf("Unlink = %v, want success (one binding remains)", err)
	}
	var count int64
	if err := s.DB.Model(&model.UserIdentity{}).Where("user_id = ?", alice.ID).Count(&count).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Fatalf("remaining bindings = %d, want 1", count)
	}
}

func TestStaleCount(t *testing.T) {
	s, _ := newService(t)
	alice := seedUser(t, s, "ldap-stale@example.com", true)
	bob := seedUser(t, s, "ldap-stale-b@example.com", true)
	carol := seedUser(t, s, "ldap-stale-c@example.com", true)

	// (user, provider, issuer) unique: one binding per account and issuer, so
	// the stale rows live on different accounts.
	for _, row := range []model.UserIdentity{
		{UserID: alice.ID, Provider: providerLDAP, Issuer: "ldap-old.example.com", Subject: "old", Email: "ldap-old@example.com", LinkedAt: time.Now()},
		{UserID: bob.ID, Provider: providerLDAP, Issuer: "ldap-old.example.com", Subject: "old2", Email: "ldap-old2@example.com", LinkedAt: time.Now()},
		{UserID: carol.ID, Provider: providerOIDC, Issuer: "https://old.example.com", Subject: "oidc-old", Email: "ldap-oidc@example.com", LinkedAt: time.Now()},
	} {
		if err := s.DB.Create(&row).Error; err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	got, err := s.StaleCount(context.Background(), providerLDAP, "ldap-new.example.com")
	if err != nil {
		t.Fatalf("StaleCount: %v", err)
	}
	if got != 2 {
		t.Fatalf("stale ldap rows = %d, want 2", got)
	}

	// Provider-scoped: the OIDC row must not leak into the LDAP count.
	got, err = s.StaleCount(context.Background(), providerOIDC, "https://new.example.com")
	if err != nil {
		t.Fatalf("StaleCount: %v", err)
	}
	if got != 1 {
		t.Fatalf("stale oidc rows = %d, want 1", got)
	}
}

// TestResolve_LegacyCaseVariantMailboxFailsClosed pins the reviewer's CWE-178
// finding: databases with a case-sensitive collation can hold two accounts
// whose emails differ only by case (legacy rows created before write-path
// normalization, e.g. via an invite). A first external login for that mailbox
// must refuse to guess between them — conflict, never First-row binding.
func TestResolve_LegacyCaseVariantMailboxFailsClosed(t *testing.T) {
	s, _ := newService(t)
	ctx := context.Background()

	// Two accounts whose mailbox differs only by case. The rows are planted
	// with a raw UPDATE so they exist even with write-path normalization in
	// place: they model the pre-normalization data a deployment can carry.
	alice := seedUser(t, s, "recycled@example.com", true)
	bob := seedUser(t, s, "filler@example.com", true)
	require.NoError(t, s.DB.Exec("UPDATE users SET email = 'Recycled@example.com' WHERE id = ?", bob.ID).Error)
	_ = alice

	claims := Claims{
		Provider:      providerOIDC,
		Issuer:        "https://legacy.example.com",
		Subject:       "subject-case-variant",
		Email:         "recycled@example.com",
		EmailVerified: true,
	}
	_, err := s.Resolve(ctx, claims)
	require.ErrorIs(t, err, ErrIdentityConflict,
		"an ambiguous legacy mailbox must fail closed, not bind to whichever row comes first")
}

// TestLoginExisting_LegacyCaseVariantOtherAccountFailsConflict pins the
// returning-login side: a bound user whose mailbox now collides with a
// case-variant legacy row of a different account must be conflicted too.
func TestLoginExisting_LegacyCaseVariantOtherAccountFailsConflict(t *testing.T) {
	s, _ := newService(t)
	ctx := context.Background()

	alice := seedUser(t, s, "alice@example.com", true)
	legacy := seedUser(t, s, "filler2@example.com", true)
	require.NoError(t, s.DB.Exec("UPDATE users SET email = 'Alice@example.com' WHERE id = ?", legacy.ID).Error)

	require.NoError(t, s.DB.Create(&model.UserIdentity{
		UserID:   alice.ID,
		Provider: providerOIDC,
		Issuer:   "https://legacy.example.com",
		Subject:  "subject-returning",
		Email:    "alice@example.com",
		LinkedAt: time.Now(),
	}).Error)

	// The IdP now reports the mailbox with different case: the legacy
	// case-variant row of another account matches it.
	claims := Claims{
		Provider:      providerOIDC,
		Issuer:        "https://legacy.example.com",
		Subject:       "subject-returning",
		Email:         "Alice@example.com",
		EmailVerified: true,
	}
	_, err := s.Resolve(ctx, claims)
	require.ErrorIs(t, err, ErrIdentityConflict,
		"a mailbox collision with another account must conflict even when only case differs")
}
